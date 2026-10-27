"""Actual canonical Agent loop + local HTTP models + formal evaluator, synthetic data only."""
from __future__ import annotations

import contextlib
import copy
import gzip
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from release import runner

GRADER = '''from benchmark.evaluator.grading import GradingResult, _result, request_fingerprint
TASK_ID = 'fixture_user_OFFLINE'
class TaskGrader:
    def grade(self, *, task, submission, state, judge):
        drafts = state['messages']['drafts']
        passed = len(drafts) == 1 and drafts[0]['attachments'] == ['1001.png'] and not state['messages']['sent']
        checks = [_result(task['scoring_components'][0], passed,
            ['final_service_state/messages'], 'Synthetic business draft state')]
        component = task['scoring_components'][1]
        request = dict(task_prompt={'content_context': []},
            evidence={'final_response': submission.get('final_response','')}, trajectory={},
            criterion_rubric=[{'criterion_id': component['id'], 'rubric': component['rubric']}], image_paths=[])
        batch = judge.evaluate(**request)
        decision = batch.results[component['id']]
        checks.append(_result(component, decision['pass'], decision['evidence_refs'], decision['reason']))
        return GradingResult(criteria=checks, judge_calls=[dict(criterion_id=component['id'],
            owner=component['owner'], request_sha256=request_fingerprint(request), status='succeeded',
            result=decision, audit=batch.audit)])
'''


class EvaluationPipeline(unittest.TestCase):
    def execute_cli(self, directory, handle, keys, base, output):
        """Use a separate copied installation so global data paths stay isolated."""
        installation = directory / "installation"
        for relative in ("benchmark/benchmark_runner", "benchmark/services", "benchmark/evaluator",
                         "harness/baseline harness", "harness/claude code/claude_code_harness",
                         "harness/camact_multi_harness_v1/camact_multi", "harness/camact_compatibility_v2",
                         "harness/camact_token_usage_v1", "evaluation", "camact_eval"):
            shutil.copytree(runner.PROJECT / relative, installation / relative,
                            ignore=shutil.ignore_patterns("__pycache__"))
        dataset = handle.task_dir.parents[2]
        for name in ("tasks", "users"):
            (installation / "benchmark" / name).symlink_to(dataset / name, target_is_directory=True)
        (installation / "benchmark/benchmark_manifest.json").write_text(json.dumps({"release_id": "synthetic-local-only"}))
        roles = {role: {"provider": "synthetic-local", "model": role + "-fixture", "base_url": base,
                        "api_key_env": role.upper() + "_FIXTURE_KEY", "protocol": "openai-chat",
                        "timeout_seconds": 15, "max_output_tokens": 256, "retry_attempts": 1}
                 for role in ("agent", "judge", "simulator")}
        configuration = {"roles": roles, "limits": {"max_agent_turns": 10, "max_simulator_rounds": 3,
                                                    "task_timeout_seconds": 60},
                         "evaluation": {"python": os.sys.executable}, "token_tracking": {"enabled": True}}
        config_path = directory / "cli-config.json"
        config_path.write_text(json.dumps(configuration))
        environment = os.environ | keys | {"PYTHONPATH": os.pathsep.join(str(installation / p) for p in runner.IMPORT_ROOTS),
                                           "CAMACT_RESULTS_ROOT": str(directory), "PYTHONDONTWRITEBYTECODE": "1"}
        # Cache the deployment shim before Baseline inserts evaluation/ into
        # sys.path, exercising the package import ordering seen by embedders.
        command = [os.sys.executable, "-B", "-c",
                   "import camact_eval; import runpy; runpy.run_module('camact_harness', run_name='__main__')",
                   "run", "--config", str(config_path), "--user-id", "fixture_user", "--tasks", "task_fixture",
                   "--run-dir", str(output), "--save-artifacts", "--token-tracking"]
        completed = subprocess.run(command, cwd=installation, env=environment, capture_output=True, text=True, timeout=90)
        (directory / "cli-stdout.log").write_text(completed.stdout)
        (directory / "cli-stderr.log").write_text(completed.stderr)
        self.assertEqual(completed.returncode, 0, completed.stdout[-2000:] + completed.stderr[-3000:])
        document = json.loads((output / "result.json").read_text())
        grade = document["evaluations"][0]
        self.assertEqual(grade["score"], 1)
        self.assertTrue(grade["strict_success"])
        self.assertEqual(len(grade["atomic_criteria"]), 2)
        self.assertFalse(grade["infrastructure_failure"])

    def execute_fixture(self, kind, *, outer_cli=False):
        from camact_multi.fixture import create
        from benchmark.benchmark_runner.run_model import _run_agent
        from benchmark.services.runtime_environment import RuntimeEnvironment
        from benchmark_runner import mllm_adapter as provider
        from baseline_harness.visual_wire import capture_json_http
        from harness.camact_token_usage_v1.integration import baseline_scope, reconcile_baseline
        from harness.camact_token_usage_v1.report import safe_report as agent_report
        from harness.camact_compatibility_v2.artifacts import RunArtifacts, evaluate_artifacts
        from evaluation.camact_eval.adapters import BaselineAdapter
        import yaml

        archive = Path(os.environ.get("CAMACT_TEST_OUTPUT", str(runner.PROJECT / ".validation/source-integration")))
        archive.mkdir(parents=True, exist_ok=True)
        # Preserve actual task evidence for review; every invocation gets its
        # own directory and never reads or writes a canonical Benchmark task.
        directory = Path(tempfile.mkdtemp(prefix=("baseline-cli-" if outer_cli else "baseline-") + kind + "-", dir=archive))
        handle = create(directory / "synthetic-benchmark")
        task_path = handle.task_dir / "task.yaml"
        task = yaml.safe_load(task_path.read_text())
        task["task_type"] = kind
        task["user_agent"]["enabled"] = kind == "multi_turn"
        if kind == "users_history":
            task["context"] = {"kind": "agent_history", "source": "messages", "thread_id": "fixture-history",
                "messages": [{"role": "user", "content": "Saved private fixture: prepare the Fixture Recipient draft."},
                             {"role": "assistant", "content": "I will use the saved recipient."}]}
        semantic = copy.deepcopy(task["scoring_components"][0])
        semantic.update(id="fixture:semantic", owner="fixture:semantic", description="Synthetic semantic final response",
            check={"type": "semantic_judge", "checker": "fixture_semantic", "params": {}},
            rubric="Criterion: final response describes the draft. Evidence: final_response. PASS: clear draft confirmation. FAIL: absent confirmation. Output: boolean.")
        task["scoring_components"].append(semantic)
        task_path.write_text(yaml.safe_dump(task, sort_keys=False))
        (handle.task_dir / "grader.py").write_text(GRADER)
        state = {"agent": [], "simulator": [], "judge": [], "auth_valid": True}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                if self.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                request = json.loads(raw)
                role = request["model"].removesuffix("-fixture")
                state["auth_valid"] &= self.headers.get("Authorization") == "Bearer " + role + "-local-fixture"
                state[role].append(request)
                number = len(state[role])
                if role == "judge":
                    content = json.dumps({"criterion_results": [{"criterion_id": "fixture:semantic", "pass": True,
                        "evidence_refs": ["final_response"], "reason": "Synthetic local Judge accepted the confirmation."}]})
                    message = {"role": "assistant", "content": content}
                elif role == "simulator":
                    message = {"role": "assistant", "content": "The recipient is Fixture Recipient." if number == 1 else "###STOP###"}
                elif kind == "multi_turn" and number == 1:
                    message = {"role": "assistant", "content": "Who is the fixture recipient?"}
                else:
                    commands = [("image_view", {"image_id": "1001.png"}),
                        ("message_create_draft", {"to": "Fixture Recipient", "text": "Offline fixture draft", "attachments": ["1001.png"]}),
                        ("finish", {"final_response": "The fixture draft is ready.", "evidence": ["1001.png"]})]
                    if kind == "users_history":
                        commands = [("threads_list", {}), ("thread_get", {"thread_id": "fixture-history"})] + commands
                    index = number - 2 if kind == "multi_turn" else number - 1
                    name, arguments = commands[index]
                    message = {"role": "assistant", "content": None, "tool_calls": [{"id": "fixture-call-" + str(number),
                        "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}]}
                payload = json.dumps({"id": role + "-" + str(number), "object": "chat.completion", "model": request["model"],
                    "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}/v1"
        options = SimpleNamespace(user_id="fixture_user", task="task_fixture", provider="relay", model="agent-fixture",
            api_base=base, api_key_env="AGENT_FIXTURE_KEY", timeout=15, max_output_tokens=256, provider_retry_attempts=1,
            aep_mode="baseline", aep_log=None, max_agent_turns=10, max_simulator_rounds=3,
            simulator_model="simulator-fixture", simulator_api_base=base, simulator_api_key_env="SIMULATOR_FIXTURE_KEY",
            simulator_timeout=15, simulator_max_output_tokens=64, simulator_retry_attempts=1,
            token_tracking=True, no_runtime_caps=False)
        keys = {"AGENT_FIXTURE_KEY": "agent-local-fixture", "SIMULATOR_FIXTURE_KEY": "simulator-local-fixture",
            "JUDGE_FIXTURE_KEY": "judge-local-fixture", "CAMACT_JUDGE_API_KEY_ENV": "DISABLED_FIXTURE_JUDGE_KEY"}
        judge = {"provider": "synthetic-local", "model": "judge-fixture", "base_url": base, "api_key_env": "JUDGE_FIXTURE_KEY",
            "protocol": "openai-chat", "timeout_seconds": 15, "max_output_tokens": 256, "retry_attempts": 1}
        output = directory / "run"
        try:
            if outer_cli:
                self.execute_cli(directory, handle, keys, base, output)
            else:
                with patch.dict(os.environ, keys), RunArtifacts(output, save_artifacts=True, secrets=list(keys.values())) as storage:
                    os.environ["CAMACT_TOKEN_RUN_ID"] = str(output)
                    session = storage.work_dir / "execution/fixture_user/task_fixture"
                    original_request = provider._json_request

                    def observe(url, body, headers, configuration, **kwargs):
                        role = "simulator" if kwargs.get("component") == "simulator_model" else "agent"
                        filename = "simulator_provider_wire.jsonl" if role == "simulator" else "visual_wire.jsonl"
                        with capture_json_http(session / filename, url, configuration.api_key, component=role + "_model"):
                            return original_request(url, body, headers, configuration, **kwargs)

                    with baseline_scope(options, session) as collector:
                        with RuntimeEnvironment(handle.task_dir, session, max_agent_turns=10, max_simulator_rounds=3) as environment:
                            stdout = io.StringIO()
                            with patch.object(provider, "_json_request", observe), contextlib.redirect_stdout(stdout):
                                code = _run_agent(options, handle.task_dir, session, environment)
                            collector.task_status = environment.state["session"]["status"]
                            reconcile_baseline(collector, session)
                    (session / "baseline-output.json").write_text(stdout.getvalue())
                    self.assertEqual(code, 0)
                    artifact = BaselineAdapter(handle.task_dir.parents[2]).adapt(session,
                        user_id="fixture_user", task="task_fixture", task_id=handle.task_id)[0]
                    artifact.method = "canonical-baseline"
                    artifact.run.update(run_id=str(output), harness="baseline", offline_fixture=True)
                    artifact.model.update(model="agent-fixture")
                    source = storage.work_dir / "standard_run_artifacts.jsonl"
                    source.write_text(json.dumps(artifact.document_for_path(source)) + "\n")
                    agent_report([storage.work_dir], output / "token_usage")
                    document = evaluate_artifacts(source, handle.task_dir.parents[2], judge_role=judge,
                        judge_mode="env", output=storage.work_dir / "evaluation/result.json", evaluation_python=os.sys.executable)
                    self.assertTrue(document["evaluation_environment"]["formal"])
                    grade = document["evaluations"][0]
                    self.assertEqual(grade["score"], 1)
                    self.assertTrue(grade["strict_success"])
                    self.assertEqual(len(grade["atomic_criteria"]), 2)
                    self.assertFalse(grade["infrastructure_failure"])
                    storage.finish(document, config={"synthetic_fixture": True, "kind": kind})
            compact = json.loads((output / "token_usage/accounting_v3/summary.json").read_text())
            agent = compact["views"]["selected_run"]["canonical-baseline"]
            self.assertEqual(agent["http_attempt_count"], len(state["agent"]))
            self.assertEqual(agent["exact_tokens"]["total_tokens"], len(state["agent"]) * 13)
            self.assertTrue(agent["capture_complete"])
            role_totals = compact["all_roles_all_attempts"]
            expected_requests = sum(len(state[role]) for role in ("agent", "simulator", "judge"))
            self.assertEqual(role_totals["http_attempt_count"], expected_requests)
            self.assertEqual(role_totals["exact_tokens"]["total_tokens"], expected_requests * 13)
            self.assertTrue(role_totals["capture_complete"])
            self.assertTrue(state["auth_valid"])
            self.assertEqual(len(state["simulator"]), 2 if kind == "multi_turn" else 0)
            self.assertEqual(len(state["judge"]), 1)
            if kind == "users_history":
                self.assertNotIn("Saved private fixture", json.dumps(state["agent"][0]))
                self.assertIn("Saved private fixture", json.dumps(state["agent"][2]))
            report = {"kind": kind, "passed": True, "outer_cli_executed": outer_cli,
                "agent_mock_http_requests": len(state["agent"]),
                "simulator_mock_http_requests": len(state["simulator"]), "judge_mock_http_requests": len(state["judge"]),
                "score": 1, "strict": True, "atomic_checks": 2, "agent_tokens": agent["exact_tokens"],
                "real_external_model_requests": 0, "canonical_benchmark_tasks": 0,
                "all_role_http_attempts": expected_requests, "all_role_exact_tokens": expected_requests * 13,
                "source": "actual unchanged canonical _run_agent, RuntimeEnvironment, BaselineAdapter and formal evaluator subprocess"}
            (directory / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            os.environ.pop("CAMACT_TOKEN_RUN_ID", None)
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_outer_cli_with_cached_evaluator_package(self):
        self.execute_fixture("single_turn", outer_cli=True)

    def test_single_turn(self):
        self.execute_fixture("single_turn")

    def test_multi_turn(self):
        self.execute_fixture("multi_turn")

    def test_saved_history(self):
        self.execute_fixture("users_history")


if __name__ == "__main__":
    unittest.main(verbosity=2)
