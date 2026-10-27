"""Reuse the Claude integration's live runtime and public workspace builder."""
from __future__ import annotations
import copy
from pathlib import Path
from claude_code_harness.core import ClaudeSettings, TaskHandle, write_json
from claude_code_harness.native_adapter import NativeAdapterRuntime, build_native_workspace


def export_setup_failure(handle, *, name, entry, run_dir, error, timing=None):
    """An initialization crash has no valid Episode and must stay unscorable."""
    from evaluation.camact_eval.schema import StandardRunArtifact
    from harness.camact_compatibility_v2.roles import public_role
    artifact = StandardRunArtifact(user_id=handle.user_id, task_id=handle.task_id,
        task=f"{handle.user_id}/{handle.task_name}", run={"run_id": run_dir.name, "harness": name,
        "tool_profile": "native"}, method=f"{name}_native", model=public_role(entry.get("provider", {})),
        final_response="", evidence=[], tool_calls=[], actions=[], final_state={}, simulator={},
        errors={"infrastructure": [{"message": error}]}, trajectory_class="infrastructure_failure",
        timing=timing or {}, diagnostics={"runtime_initialization_failure": True})
    artifact.write(run_dir / "artifact.json")
    import json
    source = run_dir / "standard_run_artifacts.jsonl"
    source.write_text(json.dumps(artifact.document_for_path(source), ensure_ascii=False) + "\n", encoding="utf-8")
    return {"artifact": str(run_dir / "artifact.json"), "trajectory_class": "infrastructure_failure",
            "note": "Runtime initialization failed; a formal null result is required"}

class RuntimeSession(NativeAdapterRuntime):
    def __init__(self, handle, session_dir, benchmark_root, limits, simulator_generator=None):
        # Agent credentials never select the simulator. Configure its generator separately.
        settings = ClaudeSettings(model="", base_url="", api_key="", tool_profile="native",
                                  max_agent_turns=limits.get("max_agent_turns", 50),
                                  max_simulator_rounds=limits.get("max_simulator_rounds", 10))
        super().__init__(handle, session_dir, settings, benchmark_root)
        self.environment.simulator_generator = simulator_generator

    def _execute_command(self, payload):
        if payload.get("op") == "business_tools":
            return {"ok": True, "tools": [
                {"name": name, "description": self.environment.tools[name]["description"],
                 "inputSchema": self.environment.tools[name]["input_schema"]}
                for name in self.allowed_actions]}
        # Native mode deliberately denies the inherited domain channel.
        if payload.get("op") in {"domain", "domain_tools"}:
            return {"ok": False, "error": "album/domain tools disabled in native profile"}
        return super()._execute_command(payload)

def workspace(handle: TaskHandle, root: Path):
    public = build_native_workspace(handle, root, {"transport": "unix", "timeout": 180}, "native")
    text = (root / "TASK.md").read_text()
    text = text.replace("Use Claude Code's native Read, Glob, Grep, and Bash tools.",
                        "Use your harness's native file, shell, search and image tools.")
    text = text.replace("use Read on the original image files", "use your native image capability on the original image files")
    text = text.replace("Claude Code trajectory", "official harness trajectory")
    (root / "TASK.md").write_text(text)
    contract = __import__("json").loads((root / "context/adapter_cli.json").read_text())
    contract["interface"] = "Native shell -> task-local CamAct gateway -> existing RuntimeEnvironment"
    write_json(root / "context/adapter_cli.json", contract)
    manifest = public["workspace_manifest"]
    manifest.update(schema_version="camact.native_workspace.v1", native_tools="official defaults",
                    result_source="official trajectory + live RuntimeEnvironment; no action replay")
    write_json(root / "workspace_manifest.json", manifest)
    # Optional business-only MCP transport. Not loaded by the native shell profile.
    from . import PROJECT
    import shutil
    shutil.copy2(Path(__file__).with_name("business_mcp.py"), root / ".camact/business_mcp.py")
    shutil.copy2(Path(__file__).with_name("launcher.py"), root / ".camact/multi_launcher.py")
    return public

def export_artifact(session, *, name, entry, run_id, final_text, events, run_dir,
                    trajectory_class="finished", error=None, timing=None, capture=None, fixture=False):
    from evaluation.camact_eval.schema import StandardRunArtifact
    from benchmark.services.episode import episode_error
    from harness.camact_compatibility_v2.terminal import classify_native
    trajectory_class, error = classify_native(session, requested=trajectory_class, error=error,
                                             capture=capture, events=events, native_harness=name)
    try:
        episode = session.finish(final_text, [], trajectory_class)
        state = session.close()
    except Exception as exc:
        # Preserve the actual incomplete snapshot for diagnostics. It will fail
        # Episode validation, never masquerade as a scorable Agent failure.
        trajectory_class, error = "infrastructure_failure", f"terminal snapshot: {type(exc).__name__}: {exc}"
        state = copy.deepcopy(session.environment.state)
        path = session.environment.session_dir / "episode.json"
        import json
        episode = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    invalid = episode_error(episode, state, task_id=session.handle.task_id)
    if invalid:
        trajectory_class, error = "infrastructure_failure", f"{error}; {invalid}" if error else invalid
    calls = session.tool_calls()
    artifact = StandardRunArtifact(
        user_id=session.handle.user_id, task_id=session.handle.task_id,
        task=f"{session.handle.user_id}/{session.handle.task_name}",
        run={"run_id": run_id, "harness": name, "harness_version": entry.get("version"),
             "executable": entry["executable"], "tool_profile": "native", "offline_fixture": fixture},
        method=f"{name}_native", model={k: v for k, v in entry.get("provider", {}).items() if k != "api_key"},
        final_response=final_text, evidence=[], tool_calls=calls,
        actions=[c for c in calls if c["tool"] in session.mutating_tools],
        final_state=state, simulator={"conversation_trace": episode.get("conversation", [])},
        errors={"agent" if trajectory_class == "agent_failure" else "infrastructure": [{"message": error}]} if error else {},
        model_calls=[{"source": "provider_http_attempt", **copy.deepcopy(r)} for r in (capture or {}).get("requests", [])],
        token_usage={"status": "provider_usage_in_model_calls", "normalization": "reserved"},
        timing=timing or {}, trajectory_class=trajectory_class,
        diagnostics={"native_events": events, "episode_validation_error": invalid,
                     "capture": capture or {}, "native_visual_evidence": {"status": "reserved_unverified", "observations": []},
                     "visual_policy": "No image_view credit inferred from filenames, text reads or fixture events",
                     "adapter": session.diagnostics(), "offline_fixture": fixture},
        **{k: copy.deepcopy(episode.get(k, {} if k in {"final_service_state", "service_audit", "runtime_metadata"} else [])) for k in ("execution_trace", "action_audit", "conversation",
                                                 "final_service_state", "service_audit", "runtime_metadata")})
    from evaluation.camact_eval.visual_capture import collect_visual_evidence
    artifact.visual_evidence = collect_visual_evidence(run_dir, episode, run_dir / "workspace/album/images")
    artifact.diagnostics["native_visual_evidence"] = {"status": artifact.visual_evidence["status"],
                                                     "schema_version": artifact.visual_evidence["schema_version"]}
    artifact.validate()
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact.write(run_dir / "artifact.json")
    import json
    source = run_dir / "standard_run_artifacts.jsonl"
    source.write_text(json.dumps(artifact.document_for_path(source), ensure_ascii=False) + "\n", encoding="utf-8")
    return artifact

