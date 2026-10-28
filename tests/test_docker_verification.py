"""Exercise strict gates, isolation and failure collection with a Docker stub."""
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest

from test_image_security import SYNTHETIC_KEY, image_archive, tar_payload

ROOT = Path(__file__).resolve().parents[1]
IMAGE_ID = "sha256:" + "1" * 64
CALLER_CANARY = "caller-private-configuration-canary"
HF_CANARY = "hf_" + "0" * 40


class DockerVerificationDiagnostics(unittest.TestCase):
    def run_gate(self, *, dirty=False, failures=None, skip_build="1", expected_version=None):
        with tempfile.TemporaryDirectory(prefix="camact-gate-regression-") as temporary:
            project = Path(temporary)
            (project / "scripts").mkdir()
            for name in ("verify-docker.sh", "scan-image.py", "scan-release.py", "diagnose-gvisor.py", "gvisor-preflight.py", "verify-benchmark-cache.py", "verify-runner-policy.py", "run-compose-offline-tests.py"):
                shutil.copy2(ROOT / "scripts" / name, project / "scripts" / name)
            (project / "release").mkdir()
            for name in ("__init__.py", "diagnostics.py"):
                shutil.copy2(ROOT / "release" / name, project / "release" / name)
            shutil.copytree(ROOT / "locks", project / "locks")
            shutil.copy2(ROOT / "Dockerfile", project / "Dockerfile")
            (project / "deploy").mkdir()
            shutil.copy2(ROOT / "deploy/seccomp-gvisor.json", project / "deploy/seccomp-gvisor.json")
            (project / "camactctl").write_text("#!/bin/sh\nexit 0\n")
            (project / "camactctl").chmod(0o700)
            # Final runner images intentionally omit git. Serve only the two
            # Git protocols used by the real scanner/build-label code, with a
            # fixed tracked inventory that excludes private fixture state.
            tracked = [str(path.relative_to(project)) for path in project.rglob("*") if path.is_file()]
            (project / "tracked-files.json").write_text(json.dumps(sorted(tracked)))
            fixture = project / "fixture.tar"
            fixture.write_bytes(image_archive(layers=[tar_payload([
                ("opt/camact/fixture.txt", SYNTHETIC_KEY.encode() if dirty else b"safe")])]))
            (project / "caller-models.env").write_text("AGENT_API_KEY=" + CALLER_CANARY + "\n")
            (project / "failures.json").write_text(json.dumps(failures or {}))
            bin_dir = project / "bin"
            bin_dir.mkdir()
            # Restrict PATH to the actual runtime prerequisites and protocol
            # stubs; a host git installation cannot mask a new dependency.
            for name in ("bash", "dirname", "date", "mkdir", "cat"):
                executable = shutil.which(name)
                self.assertIsNotNone(executable, name)
                (bin_dir / name).symlink_to(executable)
            python = bin_dir / "python3"
            python.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' "$@"\n')
            python.chmod(0o700)
            git = bin_dir / "git"
            git.write_text("#!" + sys.executable + "\n" + '''import json, pathlib, sys
root = pathlib.Path(__file__).resolve().parents[1]
args = sys.argv[1:]
with (root / "git-calls.jsonl").open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
if args == ["ls-files", "-z"]:
    files = json.loads((root / "tracked-files.json").read_text())
    sys.stdout.buffer.write(b"\\0".join(value.encode() for value in files) + b"\\0")
elif args == ["rev-parse", "HEAD"]:
    print("2" * 40)
else:
    raise SystemExit(97)
''')
            git.chmod(0o700)
            docker = bin_dir / "docker"
            docker.write_text("#!" + sys.executable + "\n" + '''import json, os, pathlib, re, sys
args = sys.argv[1:]
root = pathlib.Path(__file__).resolve().parents[1]
with (root / "docker-calls.jsonl").open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
failures = json.loads((root / "failures.json").read_text())
state_file = root / "containers.json"
containers = json.loads(state_file.read_text()) if state_file.exists() else {}
def save_state():
    state_file.write_text(json.dumps(containers))
def outcome(stage):
    if stage in failures:
        print("Permission denied; private raw diagnostics: " + os.environ["CALLER_CANARY"])
        sys.exit(failures[stage])
def offline_report(stage):
    failed = stage in failures
    print("CAMACT_DIAGNOSTIC_JSON=" + json.dumps({"schema": "camact.offline-diagnostics.v1",
        "success": not failed, "testsRun": 1, "failures": int(failed), "errors": 0, "skipped": 0,
        "uid": 10001, "gid": 10001, "paths": {}, "failure_details": [{
            "test": "test_fixture.Offline.test_compose", "exception_type": "AssertionError",
            "assertion_kind": "assertEqual", "traceback": [{"file": "tests/test_fixture.py", "line": 10,
            "function": "test_compose"}]}] if failed else []}))
if args[:2] == ["image", "inspect"]:
    if "--format" in args:
        print("sha256:" + "1" * 64)
    else:
        print(json.dumps([{"Id": "sha256:" + "1" * 64,
            "Config": {"Labels": {"org.opencontainers.image.version": "fixture-version",
                "org.opencontainers.image.revision": "fixture-revision"},
                "Env": ["CAMACT_IMAGE_VERSION=fixture-version", "CAMACT_SOURCE_REVISION=fixture-revision"]}}]))
elif args[:1] == ["save"]:
    sys.stdout.buffer.write((root / "fixture.tar").read_bytes())
elif args[:1] == ["run"]:
    assert "--network=none" in args
    assert "sha256:" + "1" * 64 in args
    stage = "network-disabled-offline-tests" if "scripts/run-offline-tests.py" in args else "network-disabled-runtime-checks"
    if stage == "network-disabled-offline-tests":
        offline_report(stage)
    outcome(stage)
elif args[:1] == ["inspect"]:
    value = containers[args[-1]]
    config = value["config"]
    mounts = [{"Type":"bind","Source":config["services"]["runner"]["volumes"][0]["source"],"Target":"/var/lib/camact","ReadOnly":False}]
    mounts += [{"Type":"bind","Source":item["file"],"Target":"/run/secrets/"+name,"ReadOnly":True} for name,item in config["secrets"].items()]
    actual = {"Image":"sha256:"+"1"*64,"Config":{"User":"10001:10001"},"AppArmorProfile":"camact-gvisor-v1",
        "State":{"Running":value.get("running",False)},"HostConfig":{"CapDrop":["ALL"],"CapAdd":[],
        "ReadonlyRootfs":True,"Privileged":False,"PidsLimit":4096,"NetworkMode":"none",
        "SecurityOpt":["no-new-privileges:true","apparmor=camact-gvisor-v1","seccomp="+(root/"deploy/seccomp-gvisor.json").read_text()],
        "Tmpfs":{p:"rw,nosuid,nodev,size="+size+",uid=10001,gid=10001,mode="+mode for p,size,mode in
            [("/run/camact","256m","0700"),("/run/camact/openclaw","256m","0700"),("/tmp","512m","1777")]},"Mounts":mounts},
        "Mounts":[{"Type":"bind","Source":m["Source"],"Destination":m["Target"],"RW":not m["ReadOnly"]} for m in mounts]}
    if "runner-policy-created" in failures:
        actual["HostConfig"]["ReadonlyRootfs"]=False
    print(json.dumps(actual))
elif args[:1] == ["start"]:
    containers[args[-1]]["running"]=True
    save_state()
elif args[:1] == ["cp"]:
    if args[1].endswith(":/run/camact/runner-policy.json"):
        checks = {name:True for name in ["identity","capabilities","no_new_privileges","seccomp","apparmor","root_readonly","pids_limit","data_bind","tmpfs_flags"]}
        pathlib.Path(args[2]).write_text(json.dumps({"schema":"camact.runner-policy.inside.v1","result":"PASS","checks":checks}))
    elif args[-1].endswith(":/run/camact/runner-policy.release"):
        containers[args[-1].split(":")[0]]["released"]=True
        save_state()
    else:
        raise SystemExit(96)
elif args[:1] == ["wait"]:
    value=containers[args[-1]]
    assert value.get("released") is True
    print(failures.get(value["stage"],0))
elif args[:1] == ["logs"]:
    value=containers[args[-1]]
    stage=value["stage"]
    if stage in failures:
        print("Permission denied; private raw diagnostics: "+os.environ["CALLER_CANARY"])
    if stage == "offline-tests-in-compose":
        offline_report(stage)
    elif stage == "runner-sandbox-preflight":
        print("CAMACT_DIAGNOSTIC_JSON="+json.dumps({"schema":"camact.sandbox-diagnostics.v1","diagnostic_only":True,
            "context":"container","runsc":{"result":"FAIL","stage":"runsc_run"}}))
    elif stage.startswith("synthetic-benchmark-cache-"):
        print(json.dumps({"file_count":1,"manifest_sha256":"fixture-manifest"}))
elif args[:1] == ["rm"]:
    containers.pop(args[-1],None)
    save_state()
elif args[:1] == ["compose"]:
    assert not any(name in os.environ for name in ["COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME", "COMPOSE_ENV_FILES"])
    assert args[args.index("--env-file") + 1] == "/dev/null"
    if "--project-name" in args:
        assert re.fullmatch(r"[a-z0-9][a-z0-9_-]*", args[args.index("--project-name") + 1])
    compose_path = pathlib.Path(args[args.index("-f") + 1])
    if "config" in args and "--format" in args:
        assert args[args.index("--profile") + 1] == "tools"
        outcome("compose-source")
        if os.environ["CAMACT_VERIFY_SKIP_BUILD"] == "0":
            assert len(os.environ["CAMACT_SOURCE_REVISION"]) == 40
        print(json.dumps({"name": "camact", "services": {
            "runner": {"image": "fixture-image", "user": "10001:10001", "read_only": True,
                "secrets":["agent_api_key","judge_api_key","simulator_api_key"],
                "build": {"context": str(root)},
                "env_file": [{"path": str(root / "caller-models.env")}],
                "environment": {"AGENT_API_KEY": os.environ["CALLER_CANARY"]},
                "volumes": [{"type": "bind", "source": str(root / "caller-data"), "target": "/var/lib/camact"}]},
            "storage-init": {"image": "fixture-image", "volumes": [
                {"type": "bind", "source": str(root / "caller-data"), "target": "/var/lib/camact"},
                {"type": "bind", "source": str(root / "caller-secrets"), "target": "/secrets"}]}},
            "secrets": {name: {"file": str(root / "caller-secrets" / name)}
                for name in ["agent_api_key", "judge_api_key", "simulator_api_key"]},
            "networks": {"default": {"name": "caller-private-network"}}}))
    elif "config" in args or "build" in args:
        config = json.loads(compose_path.read_text())
        assert os.environ["CALLER_CANARY"] not in json.dumps(config)
        outcome("compose-build" if "build" in args else "compose-quiet")
    elif "down" in args:
        outcome("compose-project-cleanup")
    elif "create" in args:
        import hashlib
        if "--no-deps" in args:
            print("unknown flag: --no-deps", file=sys.stderr)
            raise SystemExit(16)
        assert args[args.index("create"):] == ["create", "--no-build", "--pull", "never", "runner"]
        config=json.loads(compose_path.read_text())
        assert set(config["services"]) == {"runner"}
        if "runner-policy-create" in failures:
            print("compose create fixture failure: " + os.environ["CALLER_CANARY"] + " hf_" + "0" * 40,
                  file=sys.stderr)
            raise SystemExit(failures["runner-policy-create"])
        identity=hashlib.sha256(str(compose_path).encode()).hexdigest()
        containers[identity]={"config":config,"stage":compose_path.stem.removesuffix("-compose")}
        if containers[identity]["stage"] == "offline-tests-in-compose":
            command=config["services"]["runner"]["command"]
            assert command[:4] == ["python","-B","scripts/run-compose-offline-tests.py","--output"]
            assert len(command) == 5 and re.fullmatch(r"/var/lib/camact/scratch/docker-gates-[a-z0-9-]+/offline-tests", command[4])
            assert "TMPDIR" not in config["services"]["runner"].get("environment",{})
        save_state()
        with (root / "docker-calls.jsonl").open("a") as stream:
            stream.write(json.dumps(["synthetic-command",*config["services"]["runner"]["command"]])+"\\n")
    elif "ps" in args:
        import hashlib
        print(hashlib.sha256(str(compose_path).encode()).hexdigest())
    elif "run" in args:
        config = json.loads(compose_path.read_text())
        assert config["services"]["runner"]["image"] == "sha256:" + "1" * 64
        assert config["services"]["runner"]["user"] == "10001:10001"
        assert config["services"]["runner"]["read_only"] is True
        assert config["services"]["runner"]["network_mode"] == "none"
        assert os.environ["CALLER_CANARY"] not in json.dumps(config)
        for secret in config["secrets"].values():
            assert pathlib.Path(secret["file"]).read_text() == "local-fixture-only"
        models = pathlib.Path(config["services"]["runner"]["env_file"][0]["path"]).read_text()
        assert "http://127.0.0.1" in models
        assert os.environ["CALLER_CANARY"] not in models
        if "storage-init" in args:
            outcome("storage-initialization")
        elif "scripts/check-runtimes.py" in args:
            outcome("native-gvisor-runtimes-and-credential-boundary")
        elif "scripts/check-codecs.py" in args:
            outcome("native-image-codecs")
        elif "scripts/run-offline-tests.py" in args or "scripts/run-compose-offline-tests.py" in args:
            offline_report("offline-tests-in-compose")
            outcome("offline-tests-in-compose")
        elif "scripts/gvisor-preflight.py" in args:
            outcome("runner-sandbox-preflight")
            print("CAMACT_DIAGNOSTIC_JSON=" + json.dumps({"schema": "camact.sandbox-diagnostics.v1",
                "diagnostic_only": True, "context": "container", "security": {"uid": 10001,
                "seccomp_mode": 2, "no_new_privileges": 1}, "namespaces": {"user_mount": {"exit_code": 1,
                "steps": [{"stage": "unshare_user", "errno": 1, "errno_name": "EPERM", "result": "FAIL"}]}},
                "runsc": {"result": "FAIL", "stage": "runsc_run"}}))
        elif "scripts/verify-benchmark-cache.py" in args:
            outcome("synthetic-benchmark-cache-creation" if "--create" in args else "synthetic-benchmark-cache-reuse")
            print(json.dumps({"file_count": 1, "manifest_sha256": "fixture-manifest"}))
        elif "scripts/native-loop-smoke.py" in args:
            stage = "native-loop-" + args[args.index("--harness") + 1] + "-" + args[args.index("--mode") + 1]
            outcome(stage)
        elif "-c" in args:
            code = args[args.index("-c") + 1]
            if "CAMACT_VERIFY_REPO" in code:
                outcome("synthetic-benchmark-cache-reuse")
                print(json.dumps({"file_count": 1, "manifest_sha256": "fixture-manifest"}))
            elif "p.write_text" in code:
                outcome("persistence-marker-creation")
            elif "p.read_text" in code:
                outcome("persistence-marker-recreated-container")
    else:
        sys.exit(98)
else:
    sys.exit(99)
''')
            docker.chmod(0o700)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CAMACT_", "AGENT_", "JUDGE_", "SIMULATOR_", "HF_", "COMPOSE_"))}
            env.update(PATH=str(bin_dir),
                       CAMACT_IMAGE="fixture-image", CAMACT_VERIFY_SKIP_BUILD=skip_build,
                       CALLER_CANARY=CALLER_CANARY, AGENT_API_KEY=CALLER_CANARY,
                       COMPOSE_FILE="caller-private-compose.yml", COMPOSE_PROFILES="caller-private-profile",
                       COMPOSE_PROJECT_NAME="caller-private-project", COMPOSE_ENV_FILES="caller-private.env",
                       GITHUB_OUTPUT=str(project / "github-output.txt"))
            if expected_version:
                env["CAMACT_EXPECT_VERSION"] = expected_version
            process = subprocess.run(["bash", "scripts/verify-docker.sh"], cwd=project, env=env,
                                     capture_output=True, text=True, timeout=60)
            git_calls = [json.loads(line) for line in (project / "git-calls.jsonl").read_text().splitlines()]
            self.assertTrue(git_calls)
            self.assertTrue(all(call in (["ls-files", "-z"], ["rev-parse", "HEAD"]) for call in git_calls))
            output = project / "github-output.txt"
            process.image_output = output.read_text() if output.exists() else ""
            evidence = next((project / "harness/_log").glob("*/camact-docker-v1-*"))
            summary = json.loads((evidence / "verification-summary.json").read_text())
            scan_path = evidence / "image-security-scan.json"
            scan = json.loads(scan_path.read_text()) if scan_path.exists() else None
            calls = [json.loads(line) for line in (project / "docker-calls.jsonl").read_text().splitlines()]
            config_path = evidence / "private/compose.json"
            config = json.loads(config_path.read_text()) if config_path.exists() else None
            public = "".join(path.read_text() for path in evidence.rglob("*") if path.is_file() and "private" not in path.relative_to(evidence).parts)
            process.runner_policy_reports = {path.stem: json.loads(path.read_text())
                                             for path in (evidence / "runner-policy").glob("*.json")}
            containers_path = project / "containers.json"
            process.remaining_containers = json.loads(containers_path.read_text()) if containers_path.exists() else {}
            self.assertFalse((project / ".validation").exists())
        return process, summary, scan, calls, config, public

    def test_scan_failure_is_visible_redacted_and_stops_integration(self):
        process, summary, scan, calls, _, public = self.run_gate(dirty=True)
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertEqual(summary["stage"], "image-security-scan")
        self.assertEqual(summary["result"], "FAIL")
        self.assertIn('"kind": "provider_key"', process.stdout)
        self.assertIn("opt/camact/fixture.txt", process.stdout)
        self.assertNotIn(SYNTHETIC_KEY, process.stdout + process.stderr + public)
        self.assertFalse(any("run" in call for call in calls))
        self.assertEqual(process.image_output, "")

    def test_later_compose_failure_reports_its_stage_and_exit_status(self):
        process, summary, scan, calls, _, public = self.run_gate(failures={"storage-initialization": 23})
        self.assertEqual(scan["result"], "PASS")
        self.assertEqual(process.returncode, 23, process.stderr)
        self.assertEqual(summary["stage"], "storage-initialization")
        stages = {item["stage"]: item for item in summary["stages"]}
        self.assertEqual(stages["network-disabled-offline-tests"]["result"], "PASS")
        self.assertEqual(stages["native-image-codecs"]["result"], "SKIP")
        self.assertEqual(stages["storage-initialization"]["observed_error_categories"], ["permission_denied"])
        self.assertEqual(process.image_output, "")
        self.assertFalse(any("scripts/native-loop-smoke.py" in call for call in calls))
        self.assertNotIn(CALLER_CANARY, process.stdout + process.stderr + public)

    def test_runner_create_failure_preserves_cli_status_redacts_and_keeps_gate_closed(self):
        process, summary, scan, calls, _, public = self.run_gate(failures={"runner-policy-create": 23})
        self.assertEqual(scan["result"], "PASS")
        self.assertEqual(process.returncode, 125, process.stderr)
        self.assertEqual(summary["stage"], "synthetic-benchmark-cache-creation")
        self.assertEqual(summary["result"], "FAIL")
        self.assertEqual(process.image_output, "")
        self.assertTrue(process.runner_policy_reports)
        for report in process.runner_policy_reports.values():
            self.assertEqual(report["result"], "FAIL")
            self.assertEqual(report["checks"], [])
            self.assertEqual(report["cleanup_returncode"], 0)
            self.assertNotIn("command_exit_code", report)
            operations = report["operations"]
            self.assertEqual(len(operations), 1)
            self.assertEqual(operations[0]["operation"], "compose_create")
            self.assertEqual(operations[0]["returncode"], 23)
            self.assertEqual(operations[0]["status"], "FAIL")
            self.assertIn("compose create fixture failure:", operations[0]["stderr"])
            self.assertFalse(operations[0]["truncated"])
        self.assertTrue(any("create" in call for call in calls))
        self.assertTrue(any("down" in call for call in calls))
        self.assertFalse(any(call[0] in {"inspect", "start", "cp", "wait", "logs", "rm", "synthetic-command"}
                             for call in calls))
        self.assertFalse(any("scripts/native-loop-smoke.py" in call for call in calls))
        self.assertEqual(process.remaining_containers, {})
        self.assertNotIn(CALLER_CANARY, process.stdout + process.stderr + public)
        self.assertNotIn(HF_CANARY, process.stdout + process.stderr + public)

    def test_independent_failures_and_all_native_cases_are_collected(self):
        failures = {"native-image-codecs": 31, "native-loop-claude-single_turn": 41,
                    "native-loop-openclaw-users_history": 42}
        process, summary, _, calls, config, public = self.run_gate(failures=failures)
        self.assertEqual(process.returncode, 31, process.stderr)
        failed = {item["stage"]: item["exit_code"] for item in summary["stages"] if item["result"] == "FAIL"}
        self.assertEqual(failed, failures)
        self.assertEqual(sum("scripts/native-loop-smoke.py" in call for call in calls), 15)

        scoped = [call for call in calls if call[:1] == ["synthetic-command"] and "scripts/run-compose-offline-tests.py" in call]
        self.assertEqual(len(scoped), 1)
        self.assertRegex(scoped[0][-1], r"^/var/lib/camact/scratch/docker-gates-[a-z0-9-]+/offline-tests$")
        original = [call for call in calls if call[:1] == ["run"] and "scripts/run-offline-tests.py" in call]
        self.assertEqual(len(original), 1)
        self.assertEqual(summary["stages"][-1]["stage"], "compose-project-cleanup")
        self.assertEqual(summary["stages"][-1]["result"], "PASS")
        self.assertTrue(any("down" in call for call in calls))
        self.assertEqual(config["services"]["runner"]["image"], IMAGE_ID)
        self.assertNotIn("name", config["networks"]["default"])
        self.assertNotIn(CALLER_CANARY, process.stdout + process.stderr + public + json.dumps(config))

    def test_gvisor_failure_skips_dependent_loops_but_collects_other_failures(self):
        process, summary, _, calls, _, _ = self.run_gate(failures={
            "native-gvisor-runtimes-and-credential-boundary": 32, "native-image-codecs": 33})
        self.assertEqual(process.returncode, 32)
        stages = {item["stage"]: item for item in summary["stages"]}
        self.assertEqual(stages["native-image-codecs"]["result"], "FAIL")
        self.assertEqual(stages["native-loop-codex-multi_turn"]["result"], "SKIP")
        self.assertEqual(stages["persistence-marker-recreated-container"]["result"], "PASS")
        self.assertFalse(any("scripts/native-loop-smoke.py" in call for call in calls))

    def test_offline_failure_exports_test_assertion_and_traceback_without_raw_logs(self):
        process, summary, _, _, _, public = self.run_gate(failures={"offline-tests-in-compose": 1})
        self.assertEqual(process.returncode, 1)
        stages = {item["stage"]: item for item in summary["stages"]}
        self.assertEqual(stages["offline-tests-in-compose"]["diagnostics_file"], "offline-tests-compose.json")
        for value in (public, process.stdout):
            self.assertIn("test_fixture.Offline.test_compose", value)
            self.assertIn("assertEqual", value)
            self.assertIn("tests/test_fixture.py", value)
            self.assertNotIn(CALLER_CANARY, value)
        self.assertIn('"observed_status": "FAIL"', public)
        self.assertIn('"context": "host"', public)

    def test_nested_initialization_failure_cannot_be_hidden_by_later_command(self):
        process, summary, scan, calls, _, public = self.run_gate(failures={"compose-source": 37})
        self.assertEqual(process.returncode, 37, process.stderr)
        self.assertEqual(summary["stage"], "compose-initialization")
        self.assertIsNone(scan)
        self.assertFalse(any("--quiet" in call or "run" in call for call in calls))
        self.assertNotIn(CALLER_CANARY, process.stdout + process.stderr + public)

    def test_identity_mismatch_prevents_scan_and_all_container_commands(self):
        process, summary, scan, calls, _, _ = self.run_gate(expected_version="wrong-version")
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(summary["stage"], "image-identity")
        self.assertIsNone(scan)
        self.assertFalse(any("run" in call for call in calls))

    def test_build_has_no_prescan_storage_initialization_and_success_is_strict(self):
        process, summary, scan, calls, _, _ = self.run_gate(skip_build="0")
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        self.assertEqual(scan["result"], "PASS")
        self.assertEqual(summary["result"], "PASS")
        self.assertTrue(all(item["result"] == "PASS" or item.get("diagnostic_only") is True and item["result"] == "COLLECTED" for item in summary["stages"]))
        save = next(index for index, call in enumerate(calls) if call[0] == "save")
        self.assertTrue(any("build" in call for call in calls[:save]))
        self.assertFalse(any("run" in call for call in calls[:save]))
        self.assertEqual(calls[save][1], IMAGE_ID)
        self.assertEqual(process.image_output, "image_id=" + IMAGE_ID + "\n")
        self.assertEqual(sum("scripts/native-loop-smoke.py" in call for call in calls), 15)

    def test_project_cleanup_failure_keeps_publication_closed(self):
        process, summary, _, calls, _, _ = self.run_gate(failures={"compose-project-cleanup": 52})
        self.assertEqual(process.returncode, 52)
        self.assertEqual(summary["result"], "FAIL")
        self.assertEqual(summary["stage"], "compose-project-cleanup")
        self.assertEqual(process.image_output, "")
        self.assertEqual(sum("scripts/native-loop-smoke.py" in call for call in calls), 15)
