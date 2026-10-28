#!/usr/bin/env python3
"""Run the real production-plan probe with synthetic, bind-backed storage only."""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("production_plan_diagnostics", ROOT / "scripts/diagnose-gvisor.py")
diag = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(diag)

PROFILE = "camact-gvisor-diagnostic-v1"
VERSION = "0.1.0-rc.1"
INNER_OUTPUT = "/var/lib/camact/scratch/production-plan-probe-report"
INNER_SCHEMA = "camact.gvisor.production-plan.v1"
POLICY_REFERENCE_TARGET = "/opt/camact/deploy/seccomp-gvisor.json"
CANARY = "camact-production-plan-synthetic-secret-only\n"
CAPTURE_BYTES = 2 * 1024 * 1024
ARTIFACT_BYTES = 4 * 1024 * 1024
IMAGE_MANIFEST_SCHEMA = "camact.gvisor.diagnostic-image.v1"
NATIVE_CASES = tuple((name, mode) for name in ("claude", "codex", "opencode", "deepseek", "openclaw")
                     for mode in ("single_turn", "multi_turn", "users_history"))
NATIVE_INDEX_SCHEMA = "camact.gvisor.native-artifacts.v1"
NATIVE_CASE_BYTES = 32 * 1024 * 1024
NATIVE_CASE_FILES = 256
NATIVE_EXECUTABLES = {"claude": "claude", "codex": "codex", "opencode": "opencode", "deepseek": "dsh", "openclaw": "openclaw"}
NATIVE_ASSERTIONS = {
    "native_tool_assertions": {"readonly_resources_and_no_secrets", "rejected_invalid_business_actions", "history_context"},
    "token_accounting_assertions": {"agent_request_count", "agent_capture_complete", "agent_usage_complete",
        "agent_tokens_exact", "all_roles_request_count", "all_roles_tokens_exact", "all_roles_capture_complete", "formal_evaluation_linked"},
    "sandbox_lifecycle_assertions": {"production_gvisor_executed", "all_states_removed", "trusted_credentials_absent"},
}


def native_artifact_allowed(name):
    path = PurePosixPath(name)
    parts = path.parts
    if not parts or path.is_absolute() or ".." in parts or path.as_posix() != name or "\\" in name:
        return False
    if name in {"validation.json", "run/result.json", "run/runs/execution/launch.json", "run/token_usage/accounting_v3/summary.json",
                "run/runs/standard_run_artifacts.jsonl"}:
        return True
    if parts[0] != "run":
        return False
    return ((len(parts) >= 4 and parts[-3] == "sandbox-launches" and parts[-1] in {"plan.json", "lifecycle.json"})
            or parts[-1] in {"turn.json", "native_conversation.json"}
            or (parts[-1] == "requests.jsonl" and "token_usage" in parts))


# This host-supplied wrapper executes the unchanged in-image acceptance script.
# Only bounded, reviewed evidence paths enter its inventory, never the album,
# synthetic task tree, model configuration or fixture request/response payloads.
NATIVE_WRAPPER = r'''
import hashlib,json,os,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[3])
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
outer=(os.getuid()==10001 and os.getgid()==10001
    and int(status['CapEff'].strip(),16)==0 and int(status['CapBnd'].strip(),16)==0
    and status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2'
    and pathlib.Path('/proc/self/attr/current').read_text().strip()=='camact-gvisor-diagnostic-v1 (enforce)')
index={'schema':'camact.gvisor.native-artifacts.v1','outer_policy':outer,'files':[],'errors':[],
       'native_executable_resolutions':[]}
rc=125
try:
    if not outer: raise RuntimeError('outer_policy')
    rc=subprocess.run([sys.executable,'-B','/opt/camact/scripts/native-loop-smoke.py',
        '--harness',sys.argv[1],'--mode',sys.argv[2],'--output',str(root)]).returncode
finally:
    root.mkdir(parents=True,exist_ok=True)
    def allowed(path):
        p=path.parts
        name=path.as_posix()
        return (name in {'validation.json','run/result.json','run/runs/execution/launch.json','run/token_usage/accounting_v3/summary.json',
                        'run/runs/standard_run_artifacts.jsonl'}
            or (p[0]=='run' and ((len(p)>=4 and p[-3]=='sandbox-launches' and p[-1] in {'plan.json','lifecycle.json'})
                or p[-1] in {'turn.json','native_conversation.json'}
                or (p[-1]=='requests.jsonl' and 'token_usage' in p))))
    total=0
    for path in sorted(root.rglob('*')):
        relative=path.relative_to(root)
        if not allowed(relative): continue
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
            index['errors'].append('artifact_type'); continue
        size=path.stat().st_size
        if size>4194304 or total+size>33554432 or len(index['files'])>=256:
            index['errors'].append('artifact_limit'); continue
        total+=size
        index['files'].append({'path':relative.as_posix(),'bytes':size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        if path.name=='turn.json':
            try:
                original=json.loads(path.read_text())['argv'][0]
                source=pathlib.PurePosixPath(original)
                executable={'claude':'claude','codex':'codex','opencode':'opencode','deepseek':'dsh','openclaw':'openclaw'}[sys.argv[1]]
                package='/opt/camact/.tools/'+sys.argv[1]
                if not source.is_absolute() or '..' in source.parts or original!=package+'/node_modules/.bin/'+executable:
                    raise ValueError('unapproved executable')
                resolved=pathlib.Path(original).resolve(strict=True).as_posix()
                if not resolved.startswith(package+'/') or '..' in pathlib.PurePosixPath(resolved).parts:
                    raise ValueError('unapproved resolved executable')
                index['native_executable_resolutions'].append({'artifact':relative.as_posix(),
                    'original':original,'resolved':resolved})
            except (OSError,ValueError,KeyError,IndexError,TypeError):
                index['errors'].append('native_executable_resolution')
    index['script_returncode']=rc
    (root/'native-artifact-index.json').write_text(json.dumps(index)+'\n')
sys.exit(rc)
'''
# These files configure the host-side diagnostic only. The in-image probe,
# every runtime/core module, Dockerfile, Compose, scanner and lock stay critical.
REUSE_SAFE_FILES = frozenset({
    ".github/workflows/diagnose-gvisor.yml",
    "scripts/diagnostic/camact-gvisor-diagnostic-v1.profile",
    "scripts/diagnostic/production-plan-controller.py",
    "tests/test_production_plan_controller.py",
})
INNER_REQUIRED = {
    "outer_policy", "secret_fixture", "runtime_version", "plan_layout", "guest_exit",
    "guest_evidence", "lifecycle", "credential_evidence", "fixture_cleanup",
    "album_readonly", "context_readonly", "policy_readonly", "memory_alias_readonly",
    "workspace_writable", "home_writable", "secrets_unreadable", "other_user_unreadable",
    "external_network_unreachable", "transport_allowed", "transport_sibling_denied", "credentials_absent",
}
RUNTIME_REQUIRED = {"claude", "codex", "opencode", "deepseek", "openclaw", "credential_boundary"}


class Stop(Exception):
    """A prerequisite failed; its sanitized check has already been recorded."""


def command(argv, timeout=20):
    return diag.command(argv, timeout=timeout)


def critical_source_digest(revision):
    """Hash the committed tree, excluding only four reviewed host-side files.

    Quoted Git paths make newlines and arbitrary filename bytes unambiguous
    despite the shared command helper's text interface. No blob is executed.
    """
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("A full source commit SHA is required")
    kind = command(["git", "-C", ROOT, "cat-file", "-t", revision], timeout=30)
    if kind["returncode"] or kind.get("timed_out") or kind["stdout"].strip() != "commit":
        raise ValueError("Source commit is not available locally")
    tree = command(["git", "-C", ROOT, "-c", "core.quotepath=true", "ls-tree", "-r", "--full-tree", revision], timeout=30)
    if tree["returncode"] or tree.get("timed_out"):
        raise ValueError("Source tree is not available locally")
    records = []
    seen = set()
    for line in tree["stdout"].splitlines():
        metadata, separator, path = line.partition("\t")
        if (not separator or not path or path in seen
                or not re.fullmatch(r"[0-7]{6} (?:blob|commit) (?:[0-9a-f]{40}|[0-9a-f]{64})", metadata)):
            raise ValueError("Malformed source tree inventory")
        seen.add(path)
        if path not in REUSE_SAFE_FILES:
            records.append(line)
    if not records:
        raise ValueError("Critical source tree inventory is empty")
    payload = "camact-critical-source-v1\0" + "\0".join(records) + "\0"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def image_provenance(identity, current_revision, manifest=None):
    """Validate provenance before the independent, mandatory image rescan."""
    if not isinstance(identity, dict):
        raise ValueError("Image identity is malformed")
    image_id, source_revision = identity.get("id"), identity.get("revision")
    if (not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", source_revision)
            or identity.get("version") != VERSION):
        raise ValueError("Image identity is not an approved diagnostic release")
    if manifest is None:
        if source_revision != current_revision:
            raise ValueError("A fresh image must identify the current commit")
    else:
        if not isinstance(manifest, dict) or manifest.get("schema") != IMAGE_MANIFEST_SCHEMA:
            raise ValueError("Reused image manifest schema is invalid")
        if (manifest.get("image_id") != image_id or manifest.get("source_revision") != source_revision
                or manifest.get("version") != VERSION
                or not isinstance(manifest.get("critical_source_digest"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", manifest["critical_source_digest"])
                or not isinstance(manifest.get("image_archive_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", manifest["image_archive_sha256"])):
            raise ValueError("Reused image manifest identity or checksum is invalid")
    current_digest = critical_source_digest(current_revision)
    source_digest = current_digest if source_revision == current_revision else critical_source_digest(source_revision)
    if source_digest != current_digest or (manifest is not None and manifest["critical_source_digest"] != source_digest):
        raise ValueError("Critical image source changed; a fresh build is required")
    result = {"reused": manifest is not None, "current_revision": current_revision,
              "source_revision": source_revision, "critical_source_digest": source_digest,
              "current_critical_source_digest": current_digest, "image_id": image_id, "version": VERSION}
    if manifest is not None:
        # The workflow verifies the tar checksum before docker load. Here the
        # loaded content ID is checked and the entire image is scanned again.
        result["image_archive_sha256"] = manifest["image_archive_sha256"]
        result["archive_checksum_scope"] = "workflow_before_load"
    return result


def status(item):
    return item.get("status", item.get("result")) if isinstance(item, dict) else None


def normalized_capabilities(values):
    """Docker may prefix capability names with CAP_; reject malformed sets."""
    if values is None:
        return frozenset()
    if not isinstance(values, (list, tuple)):
        return None
    names = []
    for value in values:
        if not isinstance(value, str):
            return None
        name = value[4:] if value.startswith("CAP_") else value
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name.startswith("CAP_") or name in names:
            return None
        names.append(name)
    return frozenset(names)


def lifecycle_ok(value):
    return (isinstance(value, dict) and value.get("returncode") == 0
            and value.get("cleanup_returncode") == 0 and value.get("state_removed") is True)


def validate_inner(report, artifacts, check_runtimes=True):
    """Do not turn a successful Docker exit or an arbitrary PASS row into success."""
    errors = []
    if not isinstance(report, dict) or report.get("schema") != INNER_SCHEMA:
        return ["inner_schema"]
    tests = report.get("tests")
    if not isinstance(tests, list) or not tests:
        errors.append("inner_tests_missing")
        tests = []
    names = [item.get("test") for item in tests if isinstance(item, dict)]
    required = INNER_REQUIRED | ({"check_runtimes"} if check_runtimes else set())
    if not required.issubset(names) or len(names) != len(set(names)):
        errors.append("inner_required_checks_missing_or_duplicate")
    if any(status(item) != "PASS" for item in tests):
        errors.append("inner_check_not_pass")
    if report.get("outcome") != "PASS":
        errors.append("inner_outcome_not_pass")
    lifecycles = report.get("lifecycles")
    expected_count = 7 if check_runtimes else 1
    if (not isinstance(lifecycles, list) or len(lifecycles) != expected_count
            or not all(lifecycle_ok(item) for item in lifecycles)):
        errors.append("inner_lifecycle_missing_or_failed")
    if check_runtimes:
        runtimes = report.get("runtime_checks")
        if not isinstance(runtimes, dict) or set(runtimes) != RUNTIME_REQUIRED:
            errors.append("runtime_checks_missing")
        else:
            for name in RUNTIME_REQUIRED - {"credential_boundary"}:
                item = runtimes[name]
                if (not isinstance(item, dict) or item.get("returncode") != 0
                        or not lifecycle_ok(item.get("lifecycle"))):
                    errors.append("runtime_check_failed:" + name)
            credential = runtimes["credential_boundary"]
            if (not isinstance(credential, dict) or credential.get("synthetic_only") is not True
                    or credential.get("trusted_credentials_absent") is not True
                    or credential.get("plan_and_lifecycle_canary_values_absent") is not True
                    or not lifecycle_ok(credential.get("lifecycle"))):
                errors.append("runtime_credential_boundary_failed")
    files = set(artifacts)
    if "report.json" not in files or "summary.md" not in files:
        errors.append("inner_report_or_summary_missing")
    if not any("plan" in Path(name).name and name.endswith(".json") and name != "report.json" for name in files):
        errors.append("plan_artifact_missing")
    if not any("lifecycle" in Path(name).name and name.endswith(".json") for name in files):
        errors.append("lifecycle_artifact_missing")
    return errors


def trusted_environment_name(name):
    return (name.startswith(("AGENT_API_KEY", "JUDGE_API_KEY", "SIMULATOR_API_KEY"))
            or name in {"CAMACT_ZCLOUD_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_HUB_TOKEN"})


def launcher_plan_reference(argv, case_output):
    if (not isinstance(argv, list) or len(argv) != 4 or not all(isinstance(value, str) for value in argv)
            or not re.fullmatch(r"/usr/(?:local/)?bin/python(?:3(?:\.13)?)?", argv[0]) or argv[1] != "-B"
            or argv[2] != "/opt/camact/harness/camact_multi_harness_v1/camact_multi/gvisor.py"):
        return None
    path = PurePosixPath(argv[3])
    if (not path.is_absolute() or ".." in path.parts or path.as_posix() != argv[3]
            or not argv[3].startswith(case_output + "/") or not argv[3].endswith("/plan.json")):
        return None
    return argv[3][len(case_output) + 1:-len("/plan.json")]


def native_guest_argv(argv, resolution, mapping, harness):
    if (not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv)
            or not isinstance(resolution, dict) or resolution.get("original") != argv[0]
            or not isinstance(mapping, list) or not mapping):
        return None
    resolved = resolution.get("resolved")
    package = "/opt/camact/.tools/" + harness
    if (argv[0] != package + "/node_modules/.bin/" + NATIVE_EXECUTABLES[harness]
            or not isinstance(resolved, str) or not resolved.startswith(package + "/")
            or ".." in PurePosixPath(resolved).parts or PurePosixPath(resolved).as_posix() != resolved):
        return None
    roots = []
    for item in mapping:
        if (not isinstance(item, dict) or not isinstance(item.get("host"), str) or not isinstance(item.get("guest"), str)
                or not re.fullmatch(r"/opt/camact/\.tools/(?:claude|codex|opencode|deepseek|openclaw|node)", item["host"])
                or not re.fullmatch(r"/opt/camact/runtime/[01]", item["guest"])):
            return None
        roots.append((item["host"], item["guest"]))
    if (len(set(host for host, _ in roots)) != len(roots) or len(set(guest for _, guest in roots)) != len(roots)
            or not any(resolved.startswith(host + "/") and argv[0].startswith(host + "/") for host, _ in roots)):
        return None
    def mapped(value):
        for host, guest in sorted(roots, key=lambda item: len(item[0]), reverse=True):
            if value == host or value.startswith(host + "/"):
                return guest + value[len(host):]
        return value
    return ["/usr/bin/python3", "/tmp/.camact/multi_launcher.py", mapped(resolved), *[mapped(value) for value in argv[1:]]]


def openclaw_preflight_code():
    source = ROOT / "harness/camact_multi_harness_v1/camact_multi/openclaw_runtime.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "sandbox_preflight")
    value = next(node.value for node in function.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "code" for target in node.targets))
    code = ast.literal_eval(value)
    if not isinstance(code, str):
        raise ValueError("OpenClaw preflight code is not a literal")
    return code


def classify_native_plans(evidence, harness, case_output):
    """Separate one source-proven coordinator preview from real invocations."""
    plans = {name.rsplit("/", 1)[0]: value for name, value in evidence.items()
             if name.endswith("/plan.json") and "/sandbox-launches/" in name}
    lifecycles = {name.rsplit("/", 1)[0]: value for name, value in evidence.items()
                  if name.endswith("/lifecycle.json") and "/sandbox-launches/" in name}
    classification = {"executed": [], "planned_unexecuted": []}
    errors = []
    if not plans or set(lifecycles) - set(plans):
        errors.append("plan_lifecycle_pairs")
    paired = set(plans) & set(lifecycles)
    orphan = set(plans) - set(lifecycles)
    def executed(name, kind, invocation):
        classification["executed"].append({"plan": name + "/plan.json", "lifecycle": name + "/lifecycle.json",
                                           "kind": kind, "invocation": invocation})
    if harness == "claude":
        references = []
        for source, document in evidence.items():
            if source.endswith("/native_conversation.json") and isinstance(document, dict):
                for number, invocation in enumerate(document.get("invocations", [])):
                    reference = launcher_plan_reference(invocation.get("command") if isinstance(invocation, dict) else None, case_output)
                    if reference not in paired:
                        errors.append("claude_invocation_plan:" + source)
                    else:
                        references.append(reference)
                        executed(reference, "claude_invocation", source + "#invocations[" + str(number) + "]")
        if orphan or not references or len(references) != len(set(references)) or set(references) != paired:
            errors.append("plan_lifecycle_pairs")
        return classification, errors
    launch_name = "run/runs/execution/launch.json"
    launch = evidence.get(launch_name)
    preview = launcher_plan_reference(launch.get("argv") if isinstance(launch, dict) else None, case_output)
    if preview not in plans or orphan != {preview}:
        errors.append("coordinator_preview_reference")
        errors.append("plan_lifecycle_pairs")
    else:
        classification["planned_unexecuted"].append({"plan": preview + "/plan.json",
            "kind": "coordinator_launch_preview", "reference": launch_name + "#argv", "lifecycle_present": False})
    turns = {name: value for name, value in evidence.items() if name.endswith("/turn.json")}
    index = evidence.get("native-artifact-index.json", {})
    raw_resolutions = index.get("native_executable_resolutions") if isinstance(index, dict) else None
    resolutions = {}
    if isinstance(raw_resolutions, list):
        for item in raw_resolutions:
            if not isinstance(item, dict) or item.get("artifact") not in turns or item.get("artifact") in resolutions:
                errors.append("native_executable_resolution")
            else:
                resolutions[item["artifact"]] = item
    if not turns or set(resolutions) != set(turns):
        errors.append("native_executable_resolution")
    preview_plan = plans.get(preview)
    mapping = preview_plan.get("runtime_mapping") if isinstance(preview_plan, dict) else None
    for number, (source, turn) in enumerate(sorted(turns.items())):
        argv = turn.get("argv") if isinstance(turn, dict) else None
        expected = native_guest_argv(argv, resolutions.get(source), mapping, harness)
        if (expected is None or not isinstance(launch, dict) or not argv or launch.get("executable") != argv[0]
                or (number == 0 and preview_plan.get("argv") != expected)):
            errors.append("native_turn_plan_argv:" + source)
            continue
        matches = sorted(name for name in paired if isinstance(plans[name], dict)
                         and plans[name].get("runtime_mapping") == mapping and plans[name].get("argv") == expected)
        if not matches:
            errors.append("native_turn_plan_missing:" + source)
            continue
        selected = matches[0]  # Identical repeated argv still consumes one distinct execution per turn.
        paired.remove(selected)
        executed(selected, "native_turn", source)
    if harness == "openclaw" and len(paired) == 1:
        selected = next(iter(paired))
        plan = plans[selected]
        argv = plan.get("argv") if isinstance(plan, dict) else None
        expected_code = diag.redact(openclaw_preflight_code(), limit=None)
        if (isinstance(argv, list) and len(argv) == 3
                and argv[0] in {"/usr/bin/python3", "/usr/local/bin/python3", "/usr/local/bin/python3.13"}
                and argv[1] == "-c" and diag.redact(argv[2], limit=None) == expected_code
                and not any(mount.get("destination") == "/transport" for mount in plan.get("mounts", []))):
            paired.remove(selected)
            executed(selected, "openclaw_permission_preflight", "camact_multi.openclaw_runtime.sandbox_preflight")
        else:
            errors.append("openclaw_preflight_plan")
    elif harness == "openclaw":
        errors.append("openclaw_preflight_plan")
    if paired:
        errors.append("executed_plan_without_invocation")
    return classification, errors


def validate_native(evidence, harness, mode, case_output):
    """Keep the existing smoke assertions and verify their retained evidence."""
    errors = []
    row = evidence.get("validation.json")
    if not isinstance(row, dict):
        return ["validation_missing"]
    if (row.get("harness") != harness or row.get("mode") != mode or row.get("fixture_only") is not True
            or type(row.get("real_model_calls")) is not int or row["real_model_calls"] != 0
            or type(row.get("canonical_tasks_run")) is not int or row["canonical_tasks_run"] != 0
            or any(row.get(key) is not True for key in ("passed", "listener_closed", "script_completed", "prompt_injected"))
            or row.get("visual_status") != "visual_verified"
            or type(row.get("agent_requests")) is not int or row["agent_requests"] <= 0
            or type(row.get("simulator_requests")) is not int
            or row.get("simulator_requests") != (3 if mode == "multi_turn" else 0)):
        errors.append("validation_contract")
    for field, required in NATIVE_ASSERTIONS.items():
        assertions = row.get(field)
        if not isinstance(assertions, dict) or set(assertions) != required or any(value is not True for value in assertions.values()):
            errors.append(field)
    result = evidence.get("run/result.json", {})
    evaluations = result.get("evaluations") if isinstance(result, dict) else None
    if (not isinstance(result, dict) or result.get("schema_version") != "camact.standard_evaluation_result.v1"
            or not isinstance(evaluations, list) or len(evaluations) != 1 or not isinstance(evaluations[0], dict)
            or evaluations[0].get("strict_success") is not True or evaluations[0].get("infrastructure_failure") is not False
            or evaluations[0].get("agent_failure") is not False or evaluations[0].get("user_id") != "fixture_user"
            or evaluations[0].get("task_id") != "fixture_user_OFFLINE"
            or any(result.get("summary", {}).get(key) != value for key, value in (
                ("total_tasks", 1), ("evaluated_tasks", 1), ("strict_success_count", 1),
                ("agent_failure_count", 0), ("infrastructure_failure_count", 0)))
            or row.get("evaluation") != evaluations[0]):
        errors.append("formal_evaluation")
    artifacts = evidence.get("run/runs/standard_run_artifacts.jsonl")
    if (not isinstance(artifacts, list) or len(artifacts) != 1 or not isinstance(artifacts[0], dict)
            or artifacts[0].get("schema_version") != "camact.standard_run_artifact.v1"
            or artifacts[0].get("trajectory_class") != "finished"
            or artifacts[0].get("visual_evidence", {}).get("status") != "visual_verified"):
        errors.append("visual_artifact")
    ledgers = row.get("token_request_ledgers")
    if (not isinstance(ledgers, list) or not ledgers or len(ledgers) != len(set(ledgers))
            or any(not isinstance(name, str) or not native_artifact_allowed(name) or not name.endswith("requests.jsonl")
                   or not isinstance(evidence.get(name), list) or not evidence[name] for name in ledgers)):
        errors.append("token_ledgers")
    elif not any(item.get("run_id") == case_output + "/run" and item.get("harness_id") == harness
                 for name in ledgers for item in evidence[name] if isinstance(item, dict)):
        errors.append("token_ledger_case_identity")
    try:
        summary = evidence["run/token_usage/accounting_v3/summary.json"]
        agent = summary["views"]["all_attempts"][harness]
        roles = summary["all_roles_all_attempts"]
        calls, simulator = row["agent_requests"], row["simulator_requests"]
        accounting = (summary["schema_version"] == "camact.token_accounting.v3"
            and agent["http_attempt_count"] == calls and agent["capture_complete"] is True
            and agent["usage_coverage"] == 1.0 and agent["unknown_or_unreliable_usage_requests"] == 0
            and all(agent["exact_tokens"][key] == multiple * calls for key, multiple in (
                ("input_tokens", 10), ("output_tokens", 5), ("total_tokens", 15)))
            and roles["http_attempt_count"] == calls + simulator and roles["capture_complete"] is True
            and roles["exact_tokens"]["total_tokens"] == 15 * (calls + simulator)
            and summary["formal_results"][harness]["scored_tasks"] == 1
            and summary["formal_results"][harness]["strict_success_count"] == 1)
    except (KeyError, TypeError, ValueError):
        accounting = False
    if not accounting:
        errors.append("accounting_evidence")
    plans = {name.rsplit("/", 1)[0]: value for name, value in evidence.items()
             if name.endswith("/plan.json") and "/sandbox-launches/" in name}
    lifecycles = {name.rsplit("/", 1)[0]: value for name, value in evidence.items()
                  if name.endswith("/lifecycle.json") and "/sandbox-launches/" in name}
    _, plan_errors = classify_native_plans(evidence, harness, case_output)
    errors.extend(plan_errors)
    state_parent = str(PurePosixPath(case_output).parent / "gvisor-state")
    for name, plan in plans.items():
        if (not isinstance(plan, dict) or plan.get("schema") != "camact.gvisor.launch.v1"
                or plan.get("state_parent") != state_parent or not plan.get("mounts")
                or plan.get("metadata") != case_output + "/" + name
                or any(trusted_environment_name(key) for key in plan.get("environment", {}))):
            errors.append("launch_plan:" + name)
            continue
        workspace = [mount for mount in plan["mounts"] if isinstance(mount, dict) and mount.get("type") == "bind"
                     and mount.get("destination") in {"/tmp", "/tmp/album", "/tmp/context", "/tmp/.camact"}]
        if (not any(mount.get("destination") == "/tmp" for mount in workspace)
                or any(not isinstance(mount.get("source"), str) or not mount["source"].startswith(case_output + "/")
                       or ".." in PurePosixPath(mount["source"]).parts for mount in workspace)):
            errors.append("workspace_case_identity:" + name)
    for name, item in lifecycles.items():
        if (not isinstance(item, dict) or item.get("backend") != "gvisor" or item.get("platform") != "systrap"
                or item.get("network") != "none" or item.get("host_proc_bound") is not False
                or type(item.get("returncode")) is not int or type(item.get("parent_disconnected")) is not bool
                or item.get("cleanup_returncode") != 0 or item.get("state_removed") is not True
                or not str(item.get("state", "")).startswith(state_parent + "/run-")
                or not isinstance(item.get("guest_environment_keys"), list)
                or any(not isinstance(key, str) or trusted_environment_name(key) for key in item.get("guest_environment_keys", []))):
            errors.append("sandbox_lifecycle:" + name)
    turns = [value for name, value in evidence.items() if name.endswith("/turn.json")]
    conversations = [value for name, value in evidence.items() if name.endswith("/native_conversation.json")]
    native_records = (any(isinstance(item, dict) and isinstance(item.get("invocations"), list) and item["invocations"]
                          for item in conversations) if harness == "claude" else
                      bool(turns) and all(isinstance(item, dict) and type(item.get("returncode")) is int
                          and type(item.get("timed_out")) is bool and isinstance(item.get("decision"), dict)
                          for item in turns) and any(item["decision"].get("action") == "finish" for item in turns))
    if not native_records:
        errors.append("native_turn_evidence")
    return errors


def tmpfs_map(service):
    result = {}
    for value in service.get("tmpfs", []):
        if not isinstance(value, str) or ":" not in value:
            raise ValueError("Unexpected Compose tmpfs format")
        target, options = value.split(":", 1)
        if target in result:
            raise ValueError("Duplicate Compose tmpfs target")
        result[target] = options
    if set(result) != {"/run/camact", "/run/camact/openclaw", "/tmp"}:
        raise ValueError("Unexpected Compose tmpfs targets")
    for options in result.values():
        if not {"rw", "nosuid", "nodev", "uid=10001", "gid=10001"}.issubset(options.split(",")):
            raise ValueError("Compose tmpfs hardening drift")
    return result


def mount_matches(actual, expected, allowed_tmpfs=()):
    if not isinstance(actual, list):
        return False
    observed = {}
    for mount in actual:
        if not isinstance(mount, dict):
            return False
        target = mount.get("Destination")
        if mount.get("Type") == "tmpfs":
            if target not in allowed_tmpfs or mount.get("RW") is not True or mount.get("Source"):
                return False
            continue
        if mount.get("Type") != "bind":
            return False
        if target in observed:
            return False
        observed[target] = (str(Path(mount.get("Source", "")).resolve()), mount.get("RW"))
    return observed == {target: (str(source.resolve()), writable) for target, (source, writable) in expected.items()}


def requested_mounts_match(actual, expected):
    if not isinstance(actual, list) or len(actual) != len(expected):
        return False
    observed = {}
    for mount in actual:
        if not isinstance(mount, dict) or mount.get("Type") != "bind" or mount.get("Target") in observed:
            return False
        observed[mount.get("Target")] = (str(Path(mount.get("Source", "")).resolve()), not mount.get("ReadOnly", False))
    return observed == {target: (str(source.resolve()), writable) for target, (source, writable) in expected.items()}


class Controller:
    def __init__(self, output, check_runtimes=True, native_matrix=False):
        self.output = Path(output).absolute()
        self.check_runtimes = check_runtimes
        self.native_matrix = native_matrix
        self.native_started = False
        self.native_prefix = "/var/lib/camact/scratch/docker-gates-" + uuid.uuid4().hex
        self.report = {"schema": "camact.gvisor.production-plan-controller.v1", "scope": "diagnostic_candidate_only",
                       "expected_apparmor": PROFILE, "tests": [], "logs": [], "check_runtimes": check_runtimes,
                       "synthetic_credentials_only": True, "model_requests": False}
        self.report["native_matrix_requested"] = native_matrix
        if native_matrix:
            self.report["native_matrix"] = []
        self.image_id = None
        self.scanned = False
        self.fixture = self.output / "private-fixture-data"
        self.runner = "camact-production-plan-" + uuid.uuid4().hex[:12]
        self.runner_created = False
        self.fixture_owned = False
        self.since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.image_manifest = None

    def check(self, name, passed, detail="", *, stop=True):
        self.report["tests"].append(diag.row("controller", name, "PASS" if passed else "FAIL", detail=detail))
        if not passed and stop:
            raise Stop(name)

    def capture(self, name, result):
        for stream in ("stdout", "stderr"):
            sanitized = diag.redact(result.get(stream, ""), limit=None).encode("utf-8")
            truncated = len(sanitized) > CAPTURE_BYTES
            value = sanitized[:CAPTURE_BYTES].decode("utf-8", errors="ignore")
            files = []
            for index, start in enumerate(range(0, len(value), 16000)):
                path = self.output / "logs" / f"{name}-{stream}-{index:04d}.txt"
                path.parent.mkdir(exist_ok=True)
                path.write_text(value[start:start + 16000], encoding="utf-8")
                files.append(str(path.relative_to(self.output)))
            self.report["logs"].append({"stage": name, "stream": stream, "files": files,
                                       "bytes": len(value.encode("utf-8")), "truncated": truncated})
            if truncated:
                self.check(name + "." + stream + "_complete", False, "Sanitized capture exceeded 2 MiB", stop=False)

    def execute(self, name, argv, timeout=30, *, stop=True):
        result = command(argv, timeout=timeout)
        self.capture(name, result)
        self.report["tests"].append(diag.command_row("controller", name, result))
        if result["returncode"] != 0 and stop:
            raise Stop(name)
        return result

    def compose(self):
        override = self.output / "credential-reset.yml"
        override.write_text("services:\n  runner:\n    env_file: !reset []\n    environment: !reset {}\n"
                            "    secrets: !reset []\n    volumes: !reset []\n"
                            "  storage-init:\n    volumes: !reset []\nsecrets: !reset {}\n", encoding="utf-8")
        result = self.execute("compose_read", ["docker", "compose", "--profile", "tools", "--env-file", "/dev/null", "-f", ROOT / "compose.yaml",
                              "-f", override, "config", "--format", "json", "--no-env-resolution", "--no-consistency"])
        source = json.loads(result["stdout"])
        runner, storage = source["services"]["runner"], source["services"]["storage-init"]
        runner_ok = (runner.get("user") == "10001:10001" and runner.get("cap_drop") == ["ALL"]
                     and not runner.get("cap_add") and runner.get("read_only") is True
                     and runner.get("security_opt") == ["no-new-privileges:true", "seccomp=./deploy/seccomp-gvisor.json"]
                     and runner.get("pids_limit") == 4096 and runner.get("platform") == "linux/amd64"
                     and not any(runner.get(key) for key in ("privileged", "env_file", "environment", "secrets", "volumes")))
        storage_ok = (storage.get("user") == "0:0" and storage.get("cap_drop") == ["ALL"]
                      and normalized_capabilities(storage.get("cap_add")) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
                      and storage.get("read_only") is True and storage.get("network_mode") == "none"
                      and storage.get("entrypoint") == ["python", "-B", "/opt/camact/scripts/init-storage.py"]
                      and not any(storage.get(key) for key in ("privileged", "env_file", "environment", "secrets", "volumes", "security_opt")))
        self.check("compose_policy", runner_ok and storage_ok, "Credential fields reset before Compose resolution")
        tmpfs_map(runner)
        return runner, storage

    def inspect(self, name, stage, *, role, mounts, service=None, caps=(), started=False):
        fields = {"image": ".Image", "user": ".Config.User", "cap_drop": ".HostConfig.CapDrop", "cap_add": ".HostConfig.CapAdd",
                  "read_only": ".HostConfig.ReadonlyRootfs", "privileged": ".HostConfig.Privileged", "pids_limit": ".HostConfig.PidsLimit",
                  "apparmor": ".AppArmorProfile", "security_opt": ".HostConfig.SecurityOpt", "network": ".HostConfig.NetworkMode",
                  "tmpfs": ".HostConfig.Tmpfs", "mounts": ".Mounts", "requested_mounts": ".HostConfig.Mounts", "state": ".State"}
        template = "{" + ",".join('"' + key + '":{{json ' + field + "}}" for key, field in fields.items()) + "}"
        result = self.execute(stage + "_inspect", ["docker", "inspect", "--format", template, name])
        actual = json.loads(result["stdout"])
        security = actual.get("security_opt") or []
        valid = (actual.get("image") == self.image_id and actual.get("cap_drop") == ["ALL"]
                 and normalized_capabilities(actual.get("cap_add")) == normalized_capabilities(caps) and actual.get("read_only") is True
                 and not actual.get("privileged") and actual.get("network") == "none"
                 and (mount_matches(actual.get("mounts"), mounts, tmpfs_map(service) if role == "runner" else ())
                      if started else requested_mounts_match(actual.get("requested_mounts"), mounts))
                 and not any("unconfined" in value for value in security))
        if role == "runner":
            seccomp = [value.partition("=")[2] for value in security if value.startswith("seccomp=")]
            try:
                matches_seccomp = len(seccomp) == 1 and json.loads(seccomp[0]) == json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text())
            except (ValueError, TypeError):
                matches_seccomp = False
            requested = [value.partition("=")[2] for value in security if value.startswith("apparmor=")]
            valid = (valid and actual.get("user") == "10001:10001" and actual.get("pids_limit") == service["pids_limit"]
                     and actual.get("tmpfs") == tmpfs_map(service) and matches_seccomp
                     and any(value in ("no-new-privileges", "no-new-privileges:true") for value in security)
                     and requested == [PROFILE] and actual.get("apparmor") in ((PROFILE,) if started else ("", PROFILE)))
        else:
            valid = (valid and actual.get("user") == "0:0" and not actual.get("tmpfs")
                     and not security and actual.get("apparmor") in (("docker-default",) if started else ("", "docker-default")))
        self.check(stage + "_policy", valid, "Only synthetic bind mounts and the expected immutable image are allowed")
        return actual

    def helper(self, name, mounts, caps, arguments, stage):
        self.check(stage + "_scan_prerequisite", self.scanned and bool(self.image_id))
        argv = ["docker", "create", "--name", name, "--user", "0:0", "--cap-drop=ALL", "--read-only", "--network=none"]
        for cap in caps:
            argv += ["--cap-add", cap]
        for target, (source, writable) in mounts.items():
            argv += ["--mount", f"type=bind,src={source},dst={target}" + ("" if writable else ",readonly")]
        argv += ["--entrypoint", "python", self.image_id, *arguments]
        created = False
        try:
            created = True  # A timed-out create may still have created its named container.
            self.execute(stage + "_create", argv)
            self.inspect(name, stage, role="helper", mounts=mounts, caps=caps)
            self.execute(stage + "_start", ["docker", "start", "--attach", name], timeout=120)
            actual = self.inspect(name, stage + "_started", role="helper", mounts=mounts, caps=caps, started=True)
            state = actual.get("state") or {}
            self.check(stage + "_exit", state.get("Status") == "exited" and state.get("ExitCode") == 0
                       and not state.get("OOMKilled") and not state.get("Error"))
        finally:
            if created:
                self.execute(stage + "_container_cleanup", ["docker", "rm", "--force", name], stop=False)

    def safe_fixture(self):
        return (not self.fixture.is_symlink() and self.fixture.resolve().parent == self.output.resolve()
                and self.fixture.name == "private-fixture-data")

    def cleanup_fixture(self):
        if not self.fixture_owned:
            self.check("fixture_cleanup", True, "No fixture was created by this invocation")
            return
        if not self.fixture.exists():
            self.check("fixture_cleanup", True)
            return
        if not self.safe_fixture():
            self.check("fixture_cleanup", False, "Unsafe fixture path; retained", stop=False)
            return
        try:
            shutil.rmtree(self.fixture)
        except OSError:
            # Root is confined to this one verified fixture mount. Never use host sudo.
            code = ("from pathlib import Path; import shutil\n"
                    "root=Path('/fixture')\n"
                    "assert not root.is_symlink() and root.resolve()==root\n"
                    "for child in root.iterdir():\n"
                    " if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)\n"
                    " else: child.unlink()\n")
            try:
                self.helper(self.runner + "-cleanup", {"/fixture": (self.fixture, True)},
                            ("DAC_OVERRIDE", "FOWNER"), ["-B", "-c", code], "fixture_owner_cleanup")
                self.fixture.rmdir()
            except (Stop, OSError, ValueError, KeyError):
                self.check("fixture_cleanup", False, "Dedicated fixture retained for runner teardown", stop=False)
                self.report["fixture_retained"] = "private-fixture-data"
                return
        self.check("fixture_cleanup", not self.fixture.exists(), stop=False)

    def artifacts(self):
        target = self.output / "probe-artifacts"
        target.mkdir()
        self.execute("artifact_copy", ["docker", "cp", self.runner + ":" + INNER_OUTPUT + "/.", target])
        files = []
        valid = True
        for path in target.rglob("*"):
            if path.is_symlink() or not path.resolve().is_relative_to(target.resolve()):
                valid = False
                if path.is_symlink():
                    path.unlink()
                continue
            if path.is_dir():
                continue
            if path.suffix not in {".json", ".md", ".txt", ".log"} or path.stat().st_size > ARTIFACT_BYTES:
                valid = False
                path.unlink()
                continue
            value = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix == ".json":
                try:
                    value = json.dumps(diag.clean(json.loads(value)), ensure_ascii=False, indent=2) + "\n"
                except ValueError:
                    valid = False
                    value = diag.redact(value, limit=None)
            else:
                value = diag.redact(value, limit=None)
            path.write_text(value, encoding="utf-8")
            files.append(path.relative_to(target).as_posix())
        self.check("artifact_format", valid, "Only bounded, sanitized text artifacts are accepted")
        inner_path = target / "report.json"
        inner = json.loads(inner_path.read_text()) if inner_path.is_file() else {}
        errors = validate_inner(inner, files, self.check_runtimes)
        reference = self.report.get("diagnostic_policy_reference_mount", {})
        if inner.get("runtime", {}).get("seccomp_file_sha256") != reference.get("sha256"):
            errors.append("diagnostic_policy_reference_fingerprint")
        self.report["inner_validation_errors"] = errors
        self.report["inner_outcome"] = inner.get("outcome")
        self.report["inner_lifecycle_count"] = len(inner.get("lifecycles", []))
        self.report["probe_artifacts"] = files
        self.check("inner_report", not errors, ", ".join(errors))

    def policy_reference(self):
        source = ROOT / "deploy/seccomp-gvisor.json"
        self.check("diagnostic_policy_reference_file", source.is_file() and not source.is_symlink()
                   and source.resolve() == source.absolute(), "The public policy reference must be the exact regular repository file")
        self.report["diagnostic_policy_reference_mount"] = {
            "source": "deploy/seccomp-gvisor.json", "destination": POLICY_REFERENCE_TARGET,
            "type": "bind", "source_type": "file", "read_only": True,
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "purpose": "diagnostic_reference_only", "guest_exposed": False}
        return source

    def runner_command(self, name, service, mounts, arguments, *, openclaw=False):
        self.check(name + ".scan_prerequisite", self.scanned and bool(self.image_id))
        argv = ["docker", "create", "--name", name, "--platform", service["platform"], "--user", service["user"],
                "--cap-drop=ALL", "--read-only", "--pids-limit", str(service["pids_limit"]), "--network=none",
                "--security-opt=no-new-privileges:true", "--security-opt=seccomp=" + str(ROOT / "deploy/seccomp-gvisor.json"),
                "--security-opt=apparmor=" + PROFILE]
        for target, options in tmpfs_map(service).items():
            argv += ["--tmpfs", target + ":" + options]
        for target, (source, writable) in mounts.items():
            argv += ["--mount", f"type=bind,src={source},dst={target}" + ("" if writable else ",readonly")]
        if openclaw:
            argv += ["--env", "CAMACT_OPENCLAW_TMPDIR=/run/camact/openclaw"]
        return argv + ["--entrypoint", "python", self.image_id, "-B", *arguments]

    def native_artifacts(self, container, case_output, target, stage):
        target.mkdir(parents=True)
        index_path = target / "native-artifact-index.json"
        self.execute(stage + ".artifact_index_copy", ["docker", "cp", container + ":" + case_output + "/native-artifact-index.json", index_path])
        if index_path.is_symlink():
            index_path.unlink()
            self.check(stage + ".artifact_index_file", False, "Rejected symbolic link index removed")
        self.check(stage + ".artifact_index_file", index_path.is_file() and not index_path.is_symlink()
                   and index_path.stat().st_size <= 256 * 1024)
        index = json.loads(index_path.read_text(encoding="utf-8"))
        entries = index.get("files") if isinstance(index, dict) else None
        valid = (isinstance(index, dict) and index.get("schema") == NATIVE_INDEX_SCHEMA
                 and index.get("outer_policy") is True and index.get("script_returncode") == 0
                 and index.get("errors") == [] and isinstance(entries, list) and 0 < len(entries) <= NATIVE_CASE_FILES)
        seen, total = set(), 0
        for item in entries or []:
            if not isinstance(item, dict):
                valid = False
                continue
            name = item.get("path")
            if (not isinstance(name, str) or not native_artifact_allowed(name) or name in seen
                    or type(item.get("bytes")) is not int or not 0 <= item["bytes"] <= ARTIFACT_BYTES
                    or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                valid = False
                continue
            seen.add(name)
            total += item["bytes"]
        valid = valid and total <= NATIVE_CASE_BYTES
        # Even an incomplete script inventory retains its valid, bounded evidence.
        self.check(stage + ".artifact_index", valid, "Bounded whitelist and actual outer policy", stop=False)
        index_path.write_text(json.dumps(diag.clean(index), indent=2) + "\n", encoding="utf-8")
        structural = (isinstance(entries, list) and len(seen) == len(entries) and 0 < len(entries) <= NATIVE_CASE_FILES
                      and total <= NATIVE_CASE_BYTES)
        if not structural:
            return {}, ["artifact_inventory_invalid"]
        evidence, errors = {"native-artifact-index.json": index}, []
        for number, item in enumerate(entries):
            name = item["path"]
            path = target.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            copied = self.execute(stage + f".artifact_{number:03d}", ["docker", "cp", container + ":" + case_output + "/" + name, path], stop=False)
            if copied["returncode"] or not path.is_file() or path.is_symlink():
                if path.is_symlink():
                    path.unlink()
                errors.append("artifact_copy:" + name)
                continue
            if path.stat().st_size != item["bytes"] or path.stat().st_size > ARTIFACT_BYTES:
                path.unlink()
                errors.append("artifact_size:" + name)
                continue
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                path.unlink()
                errors.append("artifact_digest:" + name)
                continue
            text = raw.decode("utf-8", errors="replace")
            try:
                if path.suffix == ".jsonl":
                    value = [json.loads(line) for line in text.splitlines() if line.strip()]
                    if not value or not all(isinstance(row, dict) for row in value):
                        raise ValueError("JSONL records missing")
                    sanitized = "".join(json.dumps(diag.clean(row), ensure_ascii=False) + "\n" for row in value)
                else:
                    value = json.loads(text)
                    sanitized = json.dumps(diag.clean(value), ensure_ascii=False, indent=2) + "\n"
                evidence[name] = value
            except (ValueError, TypeError):
                errors.append("artifact_json:" + name)
                sanitized = diag.redact(text, limit=None)
            if len(sanitized.encode("utf-8")) > ARTIFACT_BYTES:
                errors.append("sanitized_artifact_limit:" + name)
                evidence.pop(name, None)
                path.unlink()
                continue
            path.write_text(sanitized, encoding="utf-8")
        return evidence, errors

    def run_native_matrix(self, service, mounts):
        self.native_started = True
        for harness, mode in NATIVE_CASES:
            key = harness + "-" + mode
            stage = "native." + key
            container = self.runner + "-" + key.replace("_", "-")
            case_output = self.native_prefix + "/" + key
            row = {"harness": harness, "mode": mode, "outcome": "FAIL", "artifacts": [], "lifecycles": {}}
            first_check = len(self.report["tests"])
            created = False
            try:
                argv = self.runner_command(container, service, mounts, ["-c", NATIVE_WRAPPER, harness, mode, case_output],
                                           openclaw=harness == "openclaw")
                created = True
                self.execute(stage + ".create", argv)
                self.inspect(container, stage, role="runner", mounts=mounts, service=service)
                self.execute(stage + ".start", ["docker", "start", "--attach", container], timeout=300, stop=False)
                actual = self.inspect(container, stage + ".started", role="runner", mounts=mounts, service=service, started=True)
                state = actual.get("state") or {}
                self.check(stage + ".exit", state.get("Status") == "exited" and state.get("ExitCode") == 0
                           and not state.get("OOMKilled") and not state.get("Error"), stop=False)
                target = self.output / "native-artifacts" / key
                evidence, errors = self.native_artifacts(container, case_output, target, stage)
                row["artifacts"] = sorted(evidence)
                row["lifecycles"] = {name: value for name, value in evidence.items() if name.endswith("/lifecycle.json")}
                row["plan_classification"], _ = classify_native_plans(evidence, harness, case_output)
                errors += validate_native(evidence, harness, mode, case_output)
                row["validation_errors"] = errors
                self.check(stage + ".evidence", not errors, ", ".join(errors), stop=False)
            except Stop as exc:
                row["failure_stage"] = str(exc)
            except Exception as exc:
                self.check(stage + ".exception", False, type(exc).__name__, stop=False)
            finally:
                if created:
                    self.execute(stage + ".cleanup", ["docker", "rm", "--force", container], stop=False)
                row["outcome"] = "PASS" if all(status(item) == "PASS" for item in self.report["tests"][first_check:]) else "FAIL"
                self.report["native_matrix"].append(row)
        self.check("native_matrix", len(self.report["native_matrix"]) == len(NATIVE_CASES)
                   and all(item["outcome"] == "PASS" for item in self.report["native_matrix"]), stop=False)

    def skip_native_matrix(self):
        self.report["native_matrix"] = [{"harness": name, "mode": mode, "outcome": "SKIP",
            "dependency": "production_plan_and_all_runtime_boundaries"} for name, mode in NATIVE_CASES]
        for name, mode in NATIVE_CASES:
            self.report["tests"].append(diag.row("controller", "native." + name + "-" + mode, "SKIP",
                detail="Production-plan and all five runtime/credential checks must pass first"))
        self.check("native_matrix", False, "Production prerequisites did not all pass", stop=False)

    def run(self, image, reused_image_manifest=None):
        self.output.mkdir(parents=True, exist_ok=False)
        self.report["image_reuse_requested"] = reused_image_manifest is not None
        try:
            revision = self.execute("git_revision", ["git", "-C", ROOT, "rev-parse", "HEAD"])["stdout"].strip()
            self.check("git_revision_shape", bool(re.fullmatch(r"[0-9a-f]{40}", revision)))
            template = '{"id":{{json .Id}},"version":{{json (index .Config.Labels "org.opencontainers.image.version")}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"os":{{json .Os}},"architecture":{{json .Architecture}}}'
            value = json.loads(self.execute("image_inspect", ["docker", "image", "inspect", "--format", template, image])["stdout"])
            self.image_id = value.get("id")
            self.check("image_identity", bool(re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id or ""))
                       and value.get("version") == VERSION
                       and value.get("os") == "linux" and value.get("architecture") == "amd64")
            self.report["image_identity"] = value
            manifest = None
            if reused_image_manifest is not None:
                path = Path(reused_image_manifest)
                self.check("reuse_manifest_file", path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536)
                manifest = json.loads(path.read_text(encoding="utf-8"))
                self.check("reuse_manifest_format", isinstance(manifest, dict), "An explicit reuse manifest must be a JSON object")
            try:
                provenance = image_provenance(value, revision, manifest)
            except (ValueError, KeyError, TypeError) as exc:
                self.check("image_provenance", False, str(exc))
            self.report["image_provenance"] = provenance
            self.check("image_provenance", True, "Committed critical sources match the immutable image source")
            self.execute("critical_worktree_clean", ["git", "-C", ROOT, "diff", "--quiet", revision, "--", ".",
                         *(":(top,literal,exclude)" + path for path in sorted(REUSE_SAFE_FILES))])
            scan = self.execute("image_scan_command", [sys.executable, "-B", ROOT / "scripts/scan-image.py", "--image", self.image_id], timeout=900)
            inventory = json.loads(scan["stdout"])
            self.check("image_scan", inventory.get("result") == "PASS" and inventory.get("issue_count") == 0
                       and inventory.get("issues") == [] and inventory.get("candidate_values_printed") is False)
            self.scanned = True
            self.report["image_scan"] = diag.clean(inventory)
            self.image_manifest = {"schema": IMAGE_MANIFEST_SCHEMA, "image_id": self.image_id,
                                   "source_revision": provenance["source_revision"], "version": VERSION,
                                   "critical_source_digest": provenance["critical_source_digest"]}
            policy_reference = self.policy_reference()
            service, storage = self.compose()
            self.check("new_fixture", not self.fixture.exists() and self.safe_fixture())
            self.fixture.mkdir(mode=0o700)
            self.fixture_owned = True
            data, secrets = self.fixture / "data", self.fixture / "secrets"
            data.mkdir(mode=0o700)
            secrets.mkdir(mode=0o700)
            (secrets / "agent_api_key").write_text(CANARY, encoding="utf-8")
            self.helper(self.runner + "-storage", {"/var/lib/camact": (data, True), "/secrets": (secrets, True)},
                        tuple(storage["cap_add"]), ["-B", "/opt/camact/scripts/init-storage.py"], "storage")
            self.check("fixture_bind_path", self.safe_fixture() and not data.is_symlink() and not secrets.is_symlink())
            mounts = {"/var/lib/camact": (data, True), "/run/secrets/production-plan-fixture": (secrets / "agent_api_key", False),
                      POLICY_REFERENCE_TARGET: (policy_reference, False)}
            arguments = ["/opt/camact/scripts/diagnostic/production-plan-probe.py", "--output", INNER_OUTPUT]
            if self.check_runtimes:
                arguments += ["--check-runtimes"]
            argv = self.runner_command(self.runner, service, mounts, arguments)
            self.runner_created = True
            self.execute("runner_create", argv)
            self.inspect(self.runner, "runner", role="runner", mounts=mounts, service=service)
            self.execute("runner_start", ["docker", "start", "--attach", self.runner], timeout=1300, stop=False)
            actual = self.inspect(self.runner, "runner_started", role="runner", mounts=mounts, service=service, started=True)
            state = actual.get("state") or {}
            self.check("runner_exit", state.get("Status") == "exited" and state.get("ExitCode") == 0
                       and not state.get("OOMKilled") and not state.get("Error"), stop=False)
            self.artifacts()
            if self.native_matrix and self.check_runtimes and all(status(item) == "PASS" for item in self.report["tests"]):
                self.run_native_matrix(service, mounts)
        except Stop:
            pass
        except Exception as exc:
            self.check("controller_exception", False, type(exc).__name__, stop=False)
        finally:
            if self.native_matrix and not self.native_started:
                self.skip_native_matrix()
            if self.runner_created:
                self.execute("runner_cleanup", ["docker", "rm", "--force", self.runner], stop=False)
            self.cleanup_fixture()
            try:
                audit_access, audit_events = diag.audit_records(self.since)
                self.report["audit_access"] = audit_access
                self.report["audit_events"] = audit_events
            except Exception as exc:
                self.report["audit_access"] = [diag.row("audit", "collector", "SKIP", detail=type(exc).__name__)]
                self.report["audit_events"] = []
            if self.scanned and self.image_manifest is not None:
                (self.output / "image-manifest.json").write_text(json.dumps(self.image_manifest, indent=2) + "\n", encoding="utf-8")
                self.report["scanned_image_manifest"] = "image-manifest.json"
            tests = self.report["tests"]
            self.report["outcome"] = "PASS" if tests and all(status(item) == "PASS" for item in tests) and any(
                item["test"] == "inner_report" and item["status"] == "PASS" for item in tests) else "FAIL"
            (self.output / "report.json").write_text(json.dumps(diag.clean(self.report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            lines = ["# Production-plan diagnostic: " + self.report["outcome"], "",
                     "Synthetic fixture only. This does not approve publication or modify production policy.", "",
                     "| Check | Status |", "| --- | --- |"]
            lines += [f"| {item['test']} | {item['status']} |" for item in tests]
            (self.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="camact:gvisor-diagnostic")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-check-runtimes", action="store_true")
    parser.add_argument("--reused-image-manifest", type=Path)
    parser.add_argument("--native-matrix", action="store_true", help="Run all 15 original synthetic native CLI acceptance cases")
    args = parser.parse_args(argv)
    os.umask(0o077)
    report = Controller(args.output, check_runtimes=not args.skip_check_runtimes, native_matrix=args.native_matrix).run(
        args.image, reused_image_manifest=args.reused_image_manifest)
    print(json.dumps({"schema": report["schema"], "outcome": report["outcome"], "model_requests": False}))
    return 0 if report["outcome"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
