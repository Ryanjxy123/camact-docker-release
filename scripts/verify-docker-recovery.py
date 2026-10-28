#!/usr/bin/env python3
"""Real Docker interruption/resume acceptance using only synthetic Codex tasks."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import http.server
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from release import benchmark, runner


def load_script(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hf = load_script("recovery_cache_helpers", "scripts/verify-full-cache.py")
SCHEMA = "camact.docker-recovery-validation.v1"
FIXTURE_REPO = "fixture/recovery"
FIXTURE_REVISION = "0" * 40
DATA = Path("/var/lib/camact")
PORT = 38645
TASKS = ("task_fixture_a", "task_fixture_b", "task_fixture_c")
CASES = ("stop", "kill")
PHASES = ("run", "observe", "resume", "repeat")
READY = "/run/camact/recovery-policy.json"
RELEASE = "/run/camact/recovery-policy.release"


def engine():
    return runner.scheduler()


def hashed_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def checkpoint(case, suffix):
    hf.require(case in CASES and suffix in {"ledger", "interrupt", *PHASES}, "invalid_checkpoint")
    return DATA / "checkpoints" / ("recovery-" + case + "-" + suffix + ".json")


def run_root(case):
    hf.require(case in CASES, "invalid_case")
    return DATA / "results" / ("recovery-" + case)


def create_snapshot(cache_root):
    """Use the existing synthetic fixture and production offline cache contract."""
    import yaml
    from camact_multi.fixture import create
    with benchmark._lock(cache_root, FIXTURE_REPO, FIXTURE_REVISION) as (directory, _):
        snapshot = directory / "snapshot"
        hf.require(not snapshot.exists(), "fixture_snapshot_already_exists")
        handle = create(snapshot)
        original = handle.task_dir
        first = original.with_name(TASKS[0])
        original.rename(first)
        for name in TASKS[1:]:
            shutil.copytree(first, first.with_name(name))
        for number, name in enumerate(TASKS):
            task = first.with_name(name)
            identity = "fixture_user_RECOVERY_" + str(number)
            document = yaml.safe_load((task / "task.yaml").read_text())
            document.update(task_id=identity, task_type="single_turn")
            document["user_agent"]["enabled"] = False
            (task / "task.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
            public = json.loads((task / "task_spec.json").read_text())
            public["task_id"] = identity
            engine().write(task / "task_spec.json", public)
            grader = task / "grader.py"
            grader.write_text(grader.read_text().replace("fixture_user_OFFLINE", identity), encoding="utf-8")
        engine().write(snapshot / "benchmark_manifest.json", {"release_id": "synthetic-recovery-only"})
        files = {}
        for path in sorted(snapshot.rglob("*")):
            hf.require(not path.is_symlink(), "fixture_symlink")
            if path.is_file():
                content = path.read_bytes()
                files[path.relative_to(snapshot).as_posix()] = {"size": len(content), "algorithm": "git-sha1",
                    "digest": hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()}
        benchmark._atomic(directory / "manifest.json", {"schema": benchmark.SCHEMA,
            "repo_id": FIXTURE_REPO, "revision": FIXTURE_REVISION, "files": files})
    return benchmark.ensure(cache_root, FIXTURE_REPO, FIXTURE_REVISION, offline=True)


def fixture_actions():
    """The same Codex tools and deterministic actions as native-loop-smoke.py."""
    from camact_multi.offline import CLIENT
    def shell(command):
        return "exec_command", {"cmd": command, "workdir": "/tmp", "login": False, "max_output_tokens": 3000}
    resource = """import json,pathlib
policy=json.loads(pathlib.Path('/tmp/.camact/prompt_policy.json').read_text())
source=pathlib.Path(policy['memory_root'])
assert (source/'images/1001.png').read_bytes()==pathlib.Path('/tmp/album/images/1001.png').read_bytes()
assert pathlib.Path('/tmp/context/adapter_cli.json').is_file()
try:(source/'images/1001.png').write_bytes(b'forbidden');raise AssertionError('album writable')
except OSError:pass
assert not pathlib.Path('/run/secrets').exists()
assert not pathlib.Path('/var/run/docker.sock').exists()
print('CAMACT_RESOURCE_OK')
"""
    draft = {"to": "Fixture Recipient", "text": "Offline fixture draft", "attachments": ["1001.png"]}
    negative = ("import json,pathlib,subprocess\n" + CLIENT[CLIENT.index("def call("):CLIENT.index("assert call('status')")]
        + CLIENT[CLIENT.index("# Each CLI invocation"):]).replace("'real_agent_loop_executed':False", "'native_tool_assertions_executed':True")
    return [shell("/usr/bin/python3 -c " + shlex.quote(resource)), ("view_image", {"path": "/tmp/album/images/1001.png"}),
        shell("/usr/bin/python3 .camact/adapter.py action message_create_draft --json " + shlex.quote(json.dumps(draft))),
        shell("/usr/bin/python3 -c " + shlex.quote(negative))]


class ProtocolFixture:
    """Loopback Responses fixture; persist counters, never raw request bodies."""
    def __init__(self, case):
        self.case = case
        self.path = checkpoint(case, "ledger")
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.smoke = load_script("recovery_native_smoke", "scripts/native-loop-smoke.py")
        self.actions = fixture_actions()
        self.ledger = engine().read(self.path) if self.path.exists() else {
            "counts": dict.fromkeys(TASKS, 0), "stages": dict.fromkeys(TASKS, 0), "unexpected": 0,
            "prompt_rules": dict.fromkeys(TASKS, True), "tool_assertions": dict.fromkeys(TASKS, False),
            "resource_ok": dict.fromkeys(TASKS, False), "negative_ok": dict.fromkeys(TASKS, False)}
        fixture = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    hf.require(0 < length <= 8 * 1024**2 and self.path.rstrip("/").endswith("/responses"), "fixture_request_shape")
                    body = self.rfile.read(length)
                    if self.headers.get("Content-Encoding") == "gzip":
                        body = gzip.decompress(body)
                    request = json.loads(body)
                    result = fixture.respond(request)
                    if result is None:  # Task B's first real request remains in flight until Docker interruption.
                        fixture.closed.wait(1200)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(result)))
                    self.end_headers()
                    self.wfile.write(result)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception:
                    with fixture.lock:
                        fixture.ledger["unexpected"] += 1
                        engine().write(fixture.path, fixture.ledger)
                    self.send_error(400, "Synthetic fixture contract failed")
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def respond(self, request):
        with self.lock:
            manifest = engine().read(run_root(self.case) / "run_manifest.json")
            active = [slot for slot in manifest["tasks"] if slot["status"] == "running"]
            hf.require(len(active) == 1 and active[0]["task"] in TASKS, "fixture_active_task_invalid")
            name = active[0]["task"]
            self.ledger["counts"][name] += 1
            self.ledger["prompt_rules"][name] &= "<camact_public_task_rules>" in json.dumps(request)
            returned = "\n".join(self.smoke.successful_tool_texts(request))
            self.ledger["resource_ok"][name] |= "CAMACT_RESOURCE_OK" in returned
            self.ledger["negative_ok"][name] |= '"fixture_client": "passed"' in returned
            self.ledger["tool_assertions"][name] = self.ledger["resource_ok"][name] and self.ledger["negative_ok"][name]
            tools = [item.get("name", item.get("function", {}).get("name")) for item in request.get("tools", [])]
            tool = None
            if name != TASKS[1] and tools and self.ledger["stages"][name] < len(self.actions):
                tool = self.actions[self.ledger["stages"][name]]
                hf.require(tool[0] in tools, "original_native_tool_missing")
                self.ledger["stages"][name] += 1
            engine().write(self.path, self.ledger)
            if name == TASKS[1]:
                return None
            response = self.smoke.responses(tool)
            suffix = "_" + str(self.ledger["counts"][name])
            for token in ("msg_fixture", "resp_fixture", "call_fixture", "fc_fixture"):
                response = response.replace(token.encode(), (token + suffix).encode())
            return response

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.closed.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def tree_digest(directory):
    if not directory.is_dir():
        return None
    result = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            result.update(path.relative_to(directory).as_posix().encode() + b"\0symlink\0" + os.readlink(path).encode())
        elif path.is_file():
            result.update(path.relative_to(directory).as_posix().encode() + b"\0")
            result.update(bytes.fromhex(hf.digest(path)))
    return result.hexdigest()


def runtime_evidence(output):
    from camact_multi.gvisor import trusted_secret_name
    plans = list(output.glob("runs/execution/sandbox-launches/*/plan.json"))
    lifecycles = [path.with_name("lifecycle.json") for path in plans if path.with_name("lifecycle.json").is_file()]
    values = [engine().read(path) for path in lifecycles]
    clean = bool(values) and all(item.get("backend") == "gvisor" and item.get("platform") == "systrap"
        and item.get("network") == "none" and item.get("host_proc_bound") is False
        and item.get("cleanup_returncode") == 0 and item.get("state_removed") is True
        and item.get("returncode") == 0 and item.get("parent_disconnected") is False for item in values)
    credentials_absent = bool(values) and all(isinstance(value.get("guest_environment_keys"), list)
        and not any(trusted_secret_name(key) for key in value["guest_environment_keys"]) for value in values)
    index = output / "runs/standard_run_artifacts.jsonl"
    artifacts = [json.loads(line) for line in index.read_text().splitlines() if line.strip()] if index.is_file() else []
    visual = len(artifacts) == 1 and artifacts[0].get("visual_evidence", {}).get("status") == "visual_verified"
    # Reuse the Run9-validated classifier: only launch.json's source-proven
    # coordinator preview may lack a lifecycle in a completed Codex task.
    evidence, resolutions = {}, []
    parent = output.parent
    for path in [*plans, *lifecycles, *output.glob("runs/execution/native_turns/*/turn.json")]:
        name = path.relative_to(parent).as_posix()
        value = engine().read(path)
        evidence[name] = value
        if path.name == "turn.json":
            original = value.get("argv", [None])[0]
            if isinstance(original, str) and original.startswith("/opt/camact/.tools/codex/"):
                resolutions.append({"artifact": name, "original": original,
                    "resolved": str(Path(original).resolve(strict=True))})
    launch = output / "runs/execution/launch.json"
    if launch.is_file():
        evidence[launch.relative_to(parent).as_posix()] = engine().read(launch)
    evidence["native-artifact-index.json"] = {"native_executable_resolutions": resolutions}
    classifier = load_script("recovery_plan_classifier", "scripts/diagnostic/production-plan-controller.py")
    _, plan_errors = classifier.classify_native_plans(evidence, "codex", str(parent))
    return {"plans": len(plans), "recorded_lifecycles": len(values), "missing_lifecycles": len(plans) - len(values),
            "recorded_executions_clean": clean, "guest_credentials_absent": credentials_absent,
            "visual_verified": visual, "execution_plan_pairs_verified": not plan_errors}


def snapshot(case):
    archive = run_root(case)
    manifest = engine().read(archive / "run_manifest.json")
    runner.verify_source(archive)
    ledger = engine().read(checkpoint(case, "ledger"))
    frozen = {key: manifest[key] for key in ("config_sha256", "source_version_sha256", "model_config_id", "image", "harness_versions")}
    frozen.update(config_file_sha256=hf.digest(archive / "formal_config.json"),
        source_file_sha256=hf.digest(archive / "source-version.json"), benchmark_sha256=hashed_json(manifest["benchmark"]))
    tasks = {}
    for slot in manifest["tasks"]:
        name = slot["task"]
        hf.require(name in TASKS and slot["harness"] == "codex", "unexpected_recovery_slot")
        attempts = slot["attempts"]
        record = attempts[-1] if attempts else None
        directory = Path(record["directory"]) if record else None
        output = Path(record["output"]) if record else None
        worker = engine().read(directory / "worker.json").get("identity") if directory and (directory / "worker.json").is_file() else None
        child = engine().read(directory / "child.json").get("identity") if directory and (directory / "child.json").is_file() else None
        verdict = engine().inspect_result(output, slot) if output else {"scored": False, "result": None}
        usage = engine().selected_usage(output, "codex") if output else None
        tasks[name] = {"status": slot["status"], "attempts": len(attempts), "scored": verdict["scored"],
            "strict": verdict.get("strict"), "reward": verdict.get("reward"), "result_sha256": verdict.get("result_sha256"),
            "artifact_tree_sha256": tree_digest(output) if output else None,
            "requests": ledger["counts"][name], "script_stage": ledger["stages"][name],
            "prompt_rules": ledger["prompt_rules"][name], "tool_assertions": ledger["tool_assertions"][name],
            "usage_requests": usage.get("http_attempt_count") if usage else None,
            "usage_complete": usage.get("capture_complete") if usage else None,
            "worker_identity": worker, "child_identity": child,
            "worker_live": engine().live(worker), "child_live": engine().live(child),
            "worker_locked": engine().locked(directory / "worker.lock") if directory else False,
            "terminal_present": bool(directory and (directory / "terminal.json").is_file()),
            "runtime": runtime_evidence(output) if output else {"plans": 0, "recorded_lifecycles": 0,
                "missing_lifecycles": 0, "recorded_executions_clean": False,
                "guest_credentials_absent": False, "visual_verified": False, "execution_plan_pairs_verified": False}}
    hf.require(set(tasks) == set(TASKS), "recovery_slot_set_mismatch")
    states = DATA / "scratch/gvisor"
    return {"frozen": frozen, "tasks": tasks, "scheduler_status": manifest["status"],
        "scheduler_locked": engine().locked(archive / "scheduler.lock"), "unexpected_requests": ledger["unexpected"],
        "state_directories": sorted(hashlib.sha256(path.name.encode()).hexdigest() for path in states.glob("run-*") if path.is_dir())}


def ready_for_interrupt(value):
    a, b, c = (value["tasks"][name] for name in TASKS)
    return (a["status"] == "scored" and a["scored"] is True and a["strict"] is True and a["reward"] == 1
        and a["attempts"] == 1 and a["usage_complete"] is True and a["requests"] == a["usage_requests"] > 0
        and a["runtime"]["recorded_executions_clean"] is True and not a["worker_locked"]
        and a["runtime"]["guest_credentials_absent"] is True and a["runtime"]["visual_verified"] is True
        and a["runtime"]["execution_plan_pairs_verified"] is True
        and b["status"] == "running" and b["attempts"] == 1 and b["requests"] >= 1 and b["script_stage"] == 0
        and b["worker_locked"] is True and b["worker_live"] is True and b["child_live"] is True
        and b["runtime"]["plans"] > 0 and not b["terminal_present"]
        and c["status"] == "pending" and c["attempts"] == 0 and c["requests"] == 0
        and value["scheduler_locked"] is True and value["unexpected_requests"] == 0)


def validate_final(before, after, *, repeat=None):
    hf.require(after["frozen"] == before["frozen"], "frozen_configuration_or_source_changed")
    hf.require(after["scheduler_status"] == "finished_with_infrastructure_errors" and after["scheduler_locked"] is False
        and after["unexpected_requests"] == 0, "unexpected_scheduler_outcome")
    a, b, c = (after["tasks"][name] for name in TASKS)
    hf.require(all(task["attempts"] == 1 and not task["worker_locked"] and not task["worker_live"]
        and not task["child_live"] for task in (a, b, c)), "duplicate_attempt_or_live_process")
    for name in (TASKS[0], TASKS[2]):
        value = after["tasks"][name]
        hf.require(value["status"] == "scored" and value["scored"] is True and value["strict"] is True
            and value["reward"] == 1 and value["usage_complete"] is True and value["usage_requests"] == value["requests"] > 0
            and value["script_stage"] == 4 and value["prompt_rules"] is True and value["tool_assertions"] is True
            and value["runtime"]["recorded_executions_clean"] is True and value["runtime"]["guest_credentials_absent"] is True
            and value["runtime"]["visual_verified"] is True and value["runtime"]["execution_plan_pairs_verified"] is True
            and hf.HEX.fullmatch(value["result_sha256"] or "")
            and hf.HEX.fullmatch(value["artifact_tree_sha256"] or ""), "completed_fixture_evidence_incomplete")
    for key in ("result_sha256", "artifact_tree_sha256", "requests", "usage_requests"):
        hf.require(a[key] == before["tasks"][TASKS[0]][key], "completed_task_reexecuted_or_changed")
    hf.require(b["status"] == "infrastructure_error" and b["scored"] is False
        and b["requests"] == before["tasks"][TASKS[1]]["requests"] and b["script_stage"] == 0,
        "interrupted_attempt_replayed_or_scored")
    if repeat is not None:
        hf.require(repeat["frozen"] == after["frozen"] and repeat["tasks"] == after["tasks"]
            and repeat["unexpected_requests"] == after["unexpected_requests"] and not repeat["scheduler_locked"]
            and repeat["scheduler_status"] == after["scheduler_status"], "second_resume_was_not_idempotent")


def configure_fixture():
    for key in tuple(os.environ):
        if key.startswith(("AGENT_", "JUDGE_", "SIMULATOR_")):
            os.environ.pop(key)
    for role in ("AGENT", "JUDGE", "SIMULATOR"):
        os.environ.update({role + "_MODEL": "fixture-model", role + "_BASE_URL": "http://127.0.0.1:" + str(PORT),
                          role + "_API_KEY": "local-fixture-only"})
    os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"


def inside(args):
    os.umask(0o077)
    output = checkpoint(args.case, args.phase)
    result = {"schema": SCHEMA, "case": args.case, "phase": args.phase, "result": "FAIL",
              "external_model_requests": 0, "canonical_tasks_run": 0}
    monitor_stop = threading.Event()
    def monitor():
        while not monitor_stop.wait(.2):
            try:
                observed = snapshot(args.case)
                if ready_for_interrupt(observed):
                    engine().write(checkpoint(args.case, "interrupt"), observed)
                    return
            except (OSError, ValueError, KeyError, TypeError, hf.ValidationError):
                continue
    try:
        security = hf.inside_checks()
        hf.require(os.environ.get("CAMACT_SOURCE_REVISION") == args.expected_source_revision
            and os.environ.get("CAMACT_IMAGE_VERSION") == args.version
            and os.environ.get("CAMACT_IMAGE_DIGEST") == args.image_id, "inside_image_identity_mismatch")
        hf.write(READY, {"schema": SCHEMA, "security": security, "result": "PASS"})
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            release = Path(RELEASE)
            if release.is_file() and not release.is_symlink() and release.read_text() == "verified\n":
                break
            time.sleep(.05)
        else:
            raise hf.ValidationError("host_policy_release_missing")
        # Real networking is disabled by Docker. Guard trusted Python socket
        # callers too; native Guest network=none remains the production path.
        def loopback_only(event, values):
            if event == "socket.connect" and isinstance(values[1], tuple):
                hf.require(ipaddress.ip_address(values[1][0]).is_loopback, "non_loopback_connection_blocked")
        sys.addaudithook(loopback_only)
        if args.phase == "observe":
            observed = snapshot(args.case)
            hf.require(not observed["scheduler_locked"] and all(not value["worker_locked"] and not value["worker_live"]
                and not value["child_live"] for value in observed["tasks"].values()), "old_execution_not_terminated")
            result.update(observation=observed, result="PASS", command_exit_code=None)
        else:
            if args.phase == "run":
                directory, _ = benchmark._location(DATA / "benchmark", FIXTURE_REPO, FIXTURE_REVISION)
                if not (directory / "complete.json").is_file():
                    create_snapshot(DATA / "benchmark")
            configure_fixture()
            arguments = ["run" if args.phase == "run" else "resume", "--run-id", "recovery-" + args.case,
                "--users", "fixture_user", "--harness", "codex", "--parallel", "1", "--infrastructure-attempts", "1",
                "--repo-id", FIXTURE_REPO, "--revision", FIXTURE_REVISION, "--offline"]
            with ProtocolFixture(args.case):
                thread = threading.Thread(target=monitor, daemon=True)
                if args.phase == "run":
                    thread.start()
                code = runner.main(arguments)
                monitor_stop.set()
                if thread.is_alive():
                    thread.join(2)
            observed = snapshot(args.case)
            if args.phase in {"resume", "repeat"}:
                deadline = time.monotonic() + 15
                while any(value["worker_locked"] or value["worker_live"] or value["child_live"]
                          for value in observed["tasks"].values()) and time.monotonic() < deadline:
                    time.sleep(.1)
                    observed = snapshot(args.case)
            result.update(command_exit_code=code, observation=observed)
            result["result"] = "PASS" if args.phase in {"resume", "repeat"} and code == 3 else "FAIL"
    except Exception as exc:
        result["failure"] = hf.failure_reason(exc)
    finally:
        monitor_stop.set()
        engine().write(output, result)
    return 0 if result["result"] == "PASS" and args.phase == "observe" else result.get("command_exit_code", 125)


class RecoveryController(hf.Controller):
    def __init__(self, args):
        super().__init__(args)
        if not hasattr(self, "container_labels"):
            self.container_labels = {"camact.validation-run": os.environ.get("GITHUB_RUN_ID", "local")
                + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", str(os.getpid()))}
        self.container_labels["camact.validation-kind"] = "recovery"
        self.report["schema"] = SCHEMA
        self.report["cases"] = []

    def create(self, name, *, stage=None):
        if stage is None:
            return super().create(name)
        case, phase = stage.split(":")
        self.check("scan_before_" + case + "_" + phase, self.scanned and self.manifest is not None)
        command = ["docker", "create", "--name", name, "--platform=linux/amd64", "--user=10001:10001", "--cap-drop=ALL",
            "--read-only", "--network=none", "--pids-limit=4096", "--security-opt=no-new-privileges:true",
            "--security-opt=seccomp=" + str(ROOT / "deploy/seccomp-gvisor.json"), "--security-opt=apparmor=" + hf.PROFILE,
            "--mount", "type=bind,src=" + str(self.data) + ",dst=/var/lib/camact", "--env", "CAMACT_IMAGE_DIGEST=" + self.manifest["image_id"]]
        for target, value in self.tmpfs.items():
            command += ["--tmpfs", target + ":" + value]
        for key, value in self.container_labels.items():
            command += ["--label", key + "=" + value]
        command += ["--entrypoint", "python", self.manifest["image_id"], "-B", "/opt/camact/scripts/verify-docker-recovery.py",
            "inside", "--case", case, "--phase", phase, "--expected-source-revision", self.args.expected_source_revision,
            "--version", self.args.version, "--image-id", self.manifest["image_id"]]
        self.containers.add(name)
        self.call(command, timeout=120)
        self.inspect(name, stage=stage)

    def copy_json(self, name, remote, local):
        self.call(["docker", "cp", name + ":" + str(remote), local])
        return hf.read_object(local, maximum=1024 * 1024)

    def start(self, case, phase):
        stage = case + ":" + phase
        name = "camact-recovery-" + case + "-" + phase + "-" + str(os.getpid())
        self.create(name, stage=stage)
        self.call(["docker", "start", name])
        local = self.private / (case + "-" + phase + "-policy.json")
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.call(["docker", "cp", name + ":" + READY, local], check=False).returncode == 0:
                break
            time.sleep(.1)
        observed = hf.read_object(local)
        self.check(stage + "_inside_policy", set(observed) == {"schema", "security", "result"}
            and observed["schema"] == SCHEMA and observed["result"] == "PASS"
            and set(observed["security"]) == hf.INNER_CHECKS and all(value is True for value in observed["security"].values()))
        self.inspect(name, stage=stage, started=True)
        released = self.private / (case + "-" + phase + "-release")
        released.write_text("verified\n", encoding="utf-8")
        released.chmod(0o644)
        self.call(["docker", "cp", released, name + ":" + RELEASE])
        return name

    def phase(self, case, phase):
        name = self.start(case, phase)
        try:
            waited = self.call(["docker", "wait", name], timeout=600)
            expected = "0" if phase == "observe" else "3"
            self.check(case + "_" + phase + "_expected_exit", waited.stdout.strip() == expected)
            value = self.copy_json(name, checkpoint(case, phase), self.private / (case + "-" + phase + ".json"))
            self.check(case + "_" + phase + "_summary", value.get("schema") == SCHEMA and value.get("result") == "PASS"
                and value.get("case") == case and value.get("phase") == phase
                and value.get("external_model_requests") == 0 and value.get("canonical_tasks_run") == 0)
            return value["observation"]
        finally:
            if name in self.containers:
                self.cleanup(name)

    def interrupt(self, case):
        name = self.start(case, "run")
        try:
            local = self.private / (case + "-interrupt.json")
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                copied = self.call(["docker", "cp", name + ":" + str(checkpoint(case, "interrupt")), local], check=False)
                if copied.returncode == 0:
                    break
                time.sleep(.5)
            before = hf.read_object(local, maximum=1024 * 1024)
            if self.report["cases"] and self.report["cases"][-1]["case"] == case:
                self.report["cases"][-1]["before"] = before
            self.check(case + "_interrupt_barrier", ready_for_interrupt(before))
            top = self.call(["docker", "top", name, "-eo", "pid"]).stdout.splitlines()[1:]
            identities = [engine().proc_identity(int(value.strip())) for value in top if value.strip().isdigit()]
            self.check(case + "_host_process_identities", len(identities) >= 3 and all(identities))
            if case == "stop":
                self.call(["docker", "stop", "--time", "60", name], timeout=90)
            else:
                self.call(["docker", "kill", "--signal", "KILL", name])
            waited = self.call(["docker", "wait", name], timeout=90)
            self.check(case + "_docker_exit", waited.stdout.strip() == ("137" if case == "kill" else "3"))
            deadline = time.monotonic() + 15
            while any(engine().live(identity) for identity in identities) and time.monotonic() < deadline:
                time.sleep(.1)
            self.check(case + "_old_host_processes_gone", not any(engine().live(identity) for identity in identities))
            return before, {"host_processes": identities, "old_host_processes_gone": True, "docker_exit_code": int(waited.stdout.strip())}
        finally:
            if name in self.containers:
                self.cleanup(name)

    def case(self, case):
        record = {"case": case, "result": "FAIL", "disk_state_deleted_for_acceptance": False}
        self.report["cases"].append(record)
        before, interruption = self.interrupt(case)
        record.update(before=before, interruption=interruption)
        observed = self.phase(case, "observe")
        record.update(after_interruption=observed,
            interrupted_lifecycle_missing=observed["tasks"][TASKS[1]]["runtime"]["missing_lifecycles"],
            retained_state_directories=len(observed["state_directories"]))
        self.check(case + "_frozen_after_recreation", observed["frozen"] == before["frozen"])
        self.check(case + "_no_dispatch_during_observation", all(observed["tasks"][name]["attempts"] == before["tasks"][name]["attempts"]
            and observed["tasks"][name]["requests"] == before["tasks"][name]["requests"] for name in TASKS))
        after = self.phase(case, "resume")
        record["after_resume"] = after
        validate_final(before, after)
        repeat = self.phase(case, "repeat")
        record["after_second_resume"] = repeat
        validate_final(before, after, repeat=repeat)
        record["result"] = "PASS"

    def run(self):
        os.umask(0o077)
        self.output.mkdir(parents=True, exist_ok=True)
        self.private.mkdir(exist_ok=False)
        try:
            memory = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))
            resources = {"cpus": os.cpu_count() or 0, "memory_bytes": memory, "disk_free_bytes": shutil.disk_usage(self.output).free}
            self.report["host_resources"] = resources
            self.check("host_platform_and_disk", platform.system() == "Linux" and platform.machine() == "x86_64"
                and resources["cpus"] >= 2 and memory >= 4 * 1024**3 and resources["disk_free_bytes"] >= 16 * 1024**3)
            self.image()
            self.compose()
            self.storage()
            for case in CASES:
                self.case(case)
            self.check("both_real_interruption_modes", len(self.report["cases"]) == 2
                and all(case["result"] == "PASS" for case in self.report["cases"]))
            self.report["result"] = "PASS"
        except Exception as exc:
            self.report["failure"] = hf.failure_reason(exc)
        finally:
            for name in tuple(self.containers):
                try:
                    self.cleanup(name)
                except Exception:
                    self.report.update(result="FAIL", failure="container_cleanup_failed")
            hf.write(self.output / "report.json", self.report)
            hf.write(self.output / "summary.json", {"schema": SCHEMA, "result": self.report["result"], "image": self.report.get("image"),
                "cases_passed": [case["case"] for case in self.report["cases"] if case["result"] == "PASS"], "expected_resume_exit": 3,
                "expected_scheduler_status": "finished_with_infrastructure_errors", "external_model_requests": 0,
                "canonical_tasks_run": 0, "private_data_uploaded": False, "failure": self.report.get("failure")})
            hf.write(self.output / "manifest.json", {"schema": "camact.recovery-artifacts.v1", "files": ["README.md", "manifest.json", "report.json", "summary.json", "cleanup.json"],
                "private_directory_excluded": True, "source_revision": self.args.expected_source_revision, "version": self.args.version})
            (self.output / "README.md").write_text("# Synthetic Docker recovery acceptance\n\nResult: " + self.report["result"]
                + "\n\nReal original scheduler/worker/reconcile, Codex, gVisor and evaluator; local deterministic Responses fixture only. "
                "A is retained, interrupted B is infrastructure_error and never replayed, C continues. Expected resume exit is 3. "
                "Missing interrupted lifecycle evidence and remaining disk state are recorded, never erased to claim clean execution. "
                "The workflow adds cleanup.json as independent final teardown evidence; unexpected residual containers keep the job failed. "
                "Only the five indexed aggregate files are public; private synthetic cache/album/request data is excluded.\n", encoding="utf-8")
        print(json.dumps({"schema": SCHEMA, "result": self.report["result"], "cases": len(self.report["cases"]), "failure": self.report.get("failure")}))
        return 0 if self.report["result"] == "PASS" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "inside"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--image-run-id")
    parser.add_argument("--expected-source-revision")
    parser.add_argument("--version", default="0.1.0-rc.1")
    parser.add_argument("--image-id")
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--phase", choices=PHASES)
    args = parser.parse_args(argv)
    if args.action == "inside":
        return inside(args)
    if not all((args.output, args.repository, args.image_run_id, args.expected_source_revision)):
        parser.error("explicit output/repository/image run/source identity is required")
    return RecoveryController(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
