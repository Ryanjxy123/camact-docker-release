"""Actual native startup and synthetic Runtime/Simulator/Evaluator integration."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess
import traceback
from claude_code_harness.core import write_json
from .config import NAMES, provider_ready
from .drivers import prepare
from .fixture import create
from .session import RuntimeSession, workspace, export_artifact
from .sandbox import command as sandbox_command
from .transport import Transport
from .coordinator import invoke

CLIENT = '''import json,pathlib,subprocess
def call(*args, expected=0):
 p=subprocess.run(['/usr/bin/python3','.camact/adapter.py',*args],capture_output=True,text=True)
 value=json.loads(p.stdout)
 assert p.returncode==expected, (p.returncode,value,p.stderr)
 return value
assert call('status')['ok']
assert call('ask-user','--message','Who is the fixture recipient?')['ok']
args=json.dumps({'to':'Fixture Recipient','text':'Offline fixture draft','attachments':['1001.png']})
assert call('action','message_create_draft','--json',args)['ok']
# Each CLI invocation is an independent action. Transport-level retry
# idempotency is covered separately; this fixture asks for exactly one draft.
assert not call('action','image_view','--json',json.dumps({'image_id':'1001.png'}),expected=2)['ok']
assert not call('action','message_create_draft','--json',json.dumps({'to':'Fixture Recipient'}),expected=2)['ok']
assert pathlib.Path('album/images/1001.png').read_bytes().startswith(bytes.fromhex('89504e47'))
assert not pathlib.Path('/mnt/camact-host-only-sentinel').exists()
assert not pathlib.Path('/root/.camact-host-only-sentinel').exists()
print(json.dumps({'fixture_client':'passed','model_called':False,'real_agent_loop_executed':False}))
'''

def validate(config, archive):
    attempts = archive / "runs"
    attempt = next(attempts / f"offline-{i:03d}" for i in range(1, 1000) if not (attempts / f"offline-{i:03d}").exists())
    attempt.mkdir(parents=True)
    handle = create(attempt / "fixture-benchmark")
    summary = {"kind": "offline_fixture_and_native_startup", "real_benchmark_tasks_executed": 0,
               "real_model_requests": 0, "raw_run": str(attempt), "harnesses": {}}
    from evaluation.camact_eval.adapters import adapt_source
    from evaluation.camact_eval.evaluator import UnifiedEvaluator
    for name in NAMES:
        root = attempt / name
        root.mkdir()
        entry = copy.deepcopy(config["harnesses"][name])
        checks = {"harness": name, "native_loop_evaluated": False, "provider_connected": False}
        session = None
        try:
            session = RuntimeSession(handle, root / "session", handle.task_dir.parents[2], config["limits"],
                simulator_generator=lambda system, messages, seed: "The fixture recipient is Fixture Recipient.")
            public = root / "workspace"
            workspace(handle, public)
            (public / "fixture_client.py").write_text(CLIENT)
            protocol = entry["provider"].get("protocol") or ("deepseek-messages" if name == "deepseek" else "openai-chat")
            argv, env = prepare(name, entry, root / "home", config["limits"], model="fixture-model", protocol=protocol)
            write_json(root / "launch-plan.json", {"native_argv": argv, "env": env, "protocol": protocol,
                                                   "fixture_only": True, "model_value_is_synthetic": True})
            for label, native in (("version", [entry["executable"], "--version"]), ("headless-help", [*argv, "--help"])):
                cmd = sandbox_command(native, public, root / "home", entry, relay=False)
                result = invoke(cmd, env, 60)
                write_json(root / (label + ".json"), result)
                checks[label] = result["returncode"] == 0 and not result["timed_out"]
                if not checks[label]:
                    raise RuntimeError(label + ": " + result["stderr"][-2500:])
            # Exercise official config parsing with commands that never perform inference.
            inspection = {
                "codex": [entry["executable"], "mcp", "list", "--json"],
                "opencode": [entry["executable"], "debug", "config"],
                "openclaw": [entry["executable"], "config", "validate", "--json"],
                "deepseek": [entry["executable"], "--profile", "headless", "--patch", "/home/agent/provider.patch.yml", "--dump-config"],
            }.get(name)
            if inspection:
                result = invoke(sandbox_command(inspection, public, root / "home", entry, relay=False), env, 60)
                write_json(root / "native-config-check.json", result)
                checks["native_config_read"] = result["returncode"] == 0 and not result["timed_out"]
                if not checks["native_config_read"]:
                    raise RuntimeError("native config: " + result["stderr"][-2500:])
            else:
                checks["native_config_read"] = "legacy_configuration_regression_suite"
            with Transport(session, {}, root / "capture", config["limits"], offline=True) as transport:
                client = [entry["executable"]]  # adapter uses the same boundary as the selected CLI
                # Execute a labelled fixture client, not a counterfeit native agent trajectory.
                client = ["/usr/bin/python3", "/tmp/fixture_client.py"]
                result = invoke(sandbox_command(client, public, root / "home", entry, transport.path, relay=False), env, 60)
                write_json(root / "fixture-client.json", result)
                if result["returncode"]:
                    raise RuntimeError("fixture client: " + result["stderr"][-2500:])
                # Real MCP handshake against the same session (optional business interface).
                requests = [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
                proc = subprocess.run(sandbox_command(["/usr/bin/python3", "/tmp/.camact/business_mcp.py"], public,
                    root / "home", entry, transport.path, relay=False), input="".join(json.dumps(r) + "\n" for r in requests),
                    capture_output=True, text=True, env=env, timeout=30)
                replies = [json.loads(line) for line in proc.stdout.splitlines()]
                names = [t["name"] for t in replies[-1]["result"]["tools"]]
                assert set(names) == {"message_create_draft", "camact_ask_user"}, names
                write_json(root / "mcp-registration.json", {"names": names, "replies": replies, "returncode": proc.returncode})
                checks["mcp_business_only"] = proc.returncode == 0
                assert transport.records == [], "Offline validation must not access provider"
            artifact = export_artifact(session, name=name, entry=entry, run_id=attempt.name + "-" + name,
                final_text="Offline fixture client completed; no agent model was called.", events=[], run_dir=root,
                capture={"status": "offline_no_provider_requests"}, fixture=True)
            loaded = adapt_source(root / "standard_run_artifacts.jsonl", adapter="external", benchmark_root=handle.task_dir.parents[2])
            assert len(loaded) == 1
            evaluation = UnifiedEvaluator(handle.task_dir.parents[2], judge="off").evaluate(loaded[0])
            write_json(root / "fixture-evaluation.json", evaluation)
            assert not evaluation["infrastructure_failure"], evaluation.get("failure_reason")
            assert evaluation["strict_success"], evaluation
            assert len(artifact.final_state["messages"]["drafts"]) == 1
            assert not artifact.final_state["messages"]["sent"]
            assert session.ask_events and session.ask_events[0]["response"]["ok"]
            assert any(c["status"] != "succeeded" for c in artifact.tool_calls), "Failed calls must remain in episode"
            assert not any(c["tool"] == "image_view" for c in artifact.tool_calls), "Do not fabricate visual observations"
            broken = copy.deepcopy(loaded[0])
            broken.runtime_metadata["snapshot_complete"] = False
            rejection = UnifiedEvaluator(handle.task_dir.parents[2], judge="off").evaluate(broken)
            assert rejection["infrastructure_failure"]
            write_json(root / "invalid-episode-rejection.json", rejection)
            checks.update(fixture_tools=True, simulator_channel=True, artifact_schema=True, episode_valid=True,
                          external_adapter=True, unified_evaluator=True, invalid_episode_rejected=True, passed=True)
        except Exception as exc:
            checks.update(passed=False, error=f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())
        finally:
            if session:
                session.close()
        summary["harnesses"][name] = checks
        write_json(archive / "evaluation" / (attempt.name + ".json"), summary)
    summary["passed"] = all(c["passed"] for c in summary["harnesses"].values())
    write_json(archive / "evaluation" / (attempt.name + ".json"), summary)
    return summary
