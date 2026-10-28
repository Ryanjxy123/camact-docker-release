"""Full-cache acceptance contracts; synthetic files and mocked Docker only."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("full_cache_validation", ROOT / "scripts/verify-full-cache.py")
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)
b = validation.benchmark
SOURCE = "a" * 40
IMAGE = "sha256:" + "b" * 64
REPO = "Fixture/Full-Cache-Validation"
REVISION = "0" * 40
FILES = {"benchmark_manifest.json": b'{"synthetic_only":true}\n', "fixture/plain.txt": b"synthetic text\n",
         "fixture/image.bin": b"synthetic bitmap bytes only\n"}


def manifest():
    return {"schema": validation.IMAGE_SCHEMA, "image_id": IMAGE, "source_revision": SOURCE,
            "version": "0.1.0-rc.1", "image_archive_sha256": "c" * 64}


def run_record():
    return {"status": "completed", "conclusion": "success", "event": "workflow_dispatch",
            "path": ".github/workflows/publish.yml", "head_sha": SOURCE,
            "head_repository": {"full_name": "Fixture/release"}}


def fake_metadata():
    siblings = []
    for name, content in FILES.items():
        large = name.endswith(".bin")
        hashed = hashlib.sha256(content).hexdigest() if large else hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        siblings.append(SimpleNamespace(rfilename=name, size=len(content),
            blob_id="f" * 40 if large else hashed, lfs={"sha256": hashed} if large else None))
    return SimpleNamespace(sha=REVISION, siblings=siblings)


class CompleteCache(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="full-cache-fixture-", dir=os.environ.get("CAMACT_TEST_OUTPUT"))
        self.addCleanup(self.temporary.cleanup)
        self.cache = Path(self.temporary.name)

    def create_cache(self):
        def download(repo, name, **kwargs):
            self.assertEqual(repo, REPO)
            self.assertEqual(kwargs["revision"], REVISION)
            self.assertIs(kwargs["token"], False)
            self.assertEqual(kwargs["endpoint"], "https://huggingface.co")
            path = Path(kwargs["local_dir"]) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(FILES[name])
            return str(path)
        api = SimpleNamespace(dataset_info=lambda *_args, **_kwargs: fake_metadata())
        with patch.dict(os.environ, {"HF_TOKEN_FILE": ""}), patch("huggingface_hub.HfApi", return_value=api), \
                patch("huggingface_hub.hf_hub_download", side_effect=download):
            return validation.validate_cache(self.cache, REPO, REVISION, offline=False, workers=1)

    def test_full_manifest_hashes_marker_and_real_process_locks(self):
        online = self.create_cache()
        offline = validation.validate_cache(self.cache, REPO, REVISION, offline=True)
        self.assertEqual(online["cache"], offline["cache"])
        self.assertEqual(offline["cache"]["file_count"], 3)
        self.assertEqual(offline["cache"]["git_sha1_files"], 2)
        self.assertEqual(offline["cache"]["lfs_sha256_files"], 1)
        self.assertEqual(offline["cache"]["total_bytes"], sum(map(len, FILES.values())))
        self.assertEqual(offline["offline"]["calls"], dict.fromkeys(validation.CALLS, 0))
        self.assertTrue(all(offline["offline"]["locks"].values()))
        # Public output has no per-file list, snapshot path or synthetic contents.
        text = json.dumps(offline)
        for name in FILES:
            self.assertNotIn(name, text)
        self.assertNotIn(str(self.cache), text)

    def test_same_size_corruption_rejects_offline_start(self):
        self.create_cache()
        directory, _ = b._location(self.cache, REPO, REVISION)
        (directory / "snapshot/fixture/plain.txt").write_bytes(b"X" * len(FILES["fixture/plain.txt"]))
        with self.assertRaises(b.BenchmarkError):
            validation.validate_cache(self.cache, REPO, REVISION, offline=True)
        self.assertFalse((directory / "complete.json").exists())

    def test_marker_count_drift_is_not_accepted_from_fast_path(self):
        self.create_cache()
        directory, _ = b._location(self.cache, REPO, REVISION)
        marker = json.loads((directory / "complete.json").read_text())
        marker["file_count"] += 1
        b._atomic(directory / "complete.json", marker)
        with self.assertRaisesRegex(validation.ValidationError, "completion_marker_mismatch"):
            validation.validate_cache(self.cache, REPO, REVISION, offline=True)

    def test_missing_marker_is_not_reconstructed_during_offline_acceptance(self):
        self.create_cache()
        directory, _ = b._location(self.cache, REPO, REVISION)
        (directory / "complete.json").unlink()
        with patch.object(b, "ensure", wraps=b.ensure) as ensure, self.assertRaises(validation.ValidationError):
            validation.validate_cache(self.cache, REPO, REVISION, offline=True)
        ensure.assert_not_called()
        self.assertFalse((directory / "complete.json").exists())

    def test_offline_client_and_credential_calls_are_counted_and_blocked(self):
        with validation.OfflineGuard() as guard:
            with self.assertRaises(validation.ValidationError):
                b._token(None)
            with self.assertRaises(validation.ValidationError):
                b._metadata(REPO, REVISION)
            import socket
            with self.assertRaises(validation.ValidationError):
                socket.create_connection(("example.invalid", 443))
        self.assertEqual(guard.calls["token"], 1)
        self.assertEqual(guard.calls["metadata"], 1)
        self.assertEqual(guard.calls["socket_helper"], 1)

    def test_explicit_token_is_not_silently_enabled(self):
        with patch.dict(os.environ, {"HF_TOKEN_FILE": "/fixture/never-read"}), patch.object(b, "ensure") as ensure:
            with self.assertRaisesRegex(validation.ValidationError, "explicit_hf_token_not_enabled"):
                validation.validate_cache(self.cache, REPO, REVISION, offline=False)
            ensure.assert_not_called()

    def test_failure_summary_never_contains_signed_url_or_values(self):
        exc = b.BenchmarkError("Cannot fetch metadata (HTTP 403) https://private.invalid?access_token=synthetic")
        self.assertEqual(validation.failure_reason(exc), "hf_http_403")
        self.assertEqual(validation.failure_reason(OSError("/private/user/photo.jpg")), "filesystem_or_process_failure")


class ProvenanceAndDocker(unittest.TestCase):
    def verify(self, run=None, image=None, **kwargs):
        validation.verify_provenance(run or run_record(), image or manifest(), repository="Fixture/release",
            source=SOURCE, version="0.1.0-rc.1", current_source=kwargs.get("current_source", SOURCE))

    def test_only_successful_exact_official_run_and_source_are_accepted(self):
        self.verify()
        changes = {"status": "in_progress", "conclusion": "failure", "event": "push", "head_sha": "d" * 40,
                   "path": ".github/workflows/diagnose-gvisor.yml", "head_repository": {"full_name": "Other/release"}}
        for key, value in changes.items():
            changed = {**run_record(), key: value}
            with self.subTest(key=key), self.assertRaises(validation.ValidationError):
                self.verify(run=changed)
        with self.assertRaises(validation.ValidationError):
            self.verify(current_source="d" * 40)

    def test_diagnostic_schema_image_version_digest_and_extra_fields_are_rejected(self):
        for key, value in {"schema": "camact.gvisor.diagnostic-image.v1", "image_id": "mutable:tag",
                "source_revision": "d" * 40, "version": "local", "image_archive_sha256": "invalid", "extra": "unapproved"}.items():
            with self.subTest(key=key), self.assertRaises(validation.ValidationError):
                self.verify(image={**manifest(), key: value})

    def test_archive_contents_checksum_and_symlink_are_verified_before_load(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "image.tar.zst"
            archive.write_bytes(b"synthetic compressed-image fixture")
            expected = manifest() | {"image_archive_sha256": validation.digest(archive)}
            (root / "image-manifest.json").write_text(json.dumps(expected))
            self.assertEqual(validation.verify_archive(root, expected), archive)
            archive.write_bytes(b"corrupt fixture")
            with self.assertRaises(validation.ValidationError):
                validation.verify_archive(root, expected)
            archive.unlink()
            (root / "outside").write_bytes(b"synthetic compressed-image fixture")
            archive.symlink_to(root / "outside")
            with self.assertRaises(validation.ValidationError):
                validation.verify_archive(root, expected)

    def test_failed_full_scan_never_releases_a_container(self):
        class Stream:
            def __init__(self):
                self.stdout = io.BytesIO(b"synthetic docker archive stream")
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def wait(self, **_kwargs):
                return 0
            def poll(self):
                return 0
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(output=directory, image_run_id="123", repository="Fixture/release",
                                   expected_source_revision=SOURCE, version="0.1.0-rc.1")
            controller = validation.Controller(args)
            controller.private.mkdir()
            calls = []
            def command(argv, **_kwargs):
                argv = [str(value) for value in argv]
                calls.append(argv)
                if argv[:3] == ["git", "rev-parse", "HEAD"]:
                    stdout = SOURCE
                elif argv[:2] == ["gh", "api"]:
                    stdout = json.dumps(run_record())
                elif argv[:3] == ["gh", "run", "download"]:
                    target = Path(argv[-1])
                    archive = target / "image.tar.zst"
                    archive.write_bytes(b"synthetic archive fixture")
                    expected = manifest() | {"image_archive_sha256": validation.digest(archive)}
                    (target / "image-manifest.json").write_text(json.dumps(expected))
                    stdout = ""
                elif argv[:3] == ["docker", "image", "inspect"]:
                    stdout = json.dumps({"Id": IMAGE, "Os": "linux", "Architecture": "amd64", "Config": {
                        "Labels": {"org.opencontainers.image.revision": SOURCE, "org.opencontainers.image.version": "0.1.0-rc.1"},
                        "Env": ["CAMACT_SOURCE_REVISION=" + SOURCE, "CAMACT_IMAGE_VERSION=0.1.0-rc.1"]}})
                elif "scripts/scan-image.py" in argv:
                    return SimpleNamespace(returncode=1, stdout=json.dumps({"result": "FAIL", "issue_count": 1, "issues": [{}]}))
                else:
                    self.fail("Unexpected external command in fixture: " + argv[0])
                return SimpleNamespace(returncode=0, stdout=stdout)
            with patch.object(controller, "call", side_effect=command), patch.object(validation.subprocess, "Popen", return_value=Stream()), \
                    patch.object(validation.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    patch.dict(os.environ, {"GITHUB_SHA": SOURCE, "GITHUB_REPOSITORY": "Fixture/release"}):
                with self.assertRaisesRegex(validation.ValidationError, "complete_image_scan"):
                    controller.image()
                with self.assertRaises(validation.ValidationError):
                    controller.create("never-created", stage="download")
            self.assertFalse(controller.scanned)
            self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in calls))

    def actual(self, source, *, started=False, stage="offline-1"):
        profile = validation.runner_policy()
        tmpfs = {target: f"rw,nosuid,nodev,size={size},uid=10001,gid=10001,mode={mode}"
                 for target, (size, mode) in profile.TMPFS.items()}
        seccomp = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        item = {"Image": IMAGE, "Config": {"User": "10001:10001"}, "AppArmorProfile": validation.PROFILE if started else "",
            "State": {"Running": True}, "HostConfig": {"CapDrop": ["ALL"], "CapAdd": [], "ReadonlyRootfs": True,
            "Privileged": False, "PidsLimit": 4096, "NetworkMode": "bridge" if stage == "download" else "none",
            "SecurityOpt": ["no-new-privileges:true", "apparmor=" + validation.PROFILE, "seccomp=" + json.dumps(seccomp)],
            "Tmpfs": tmpfs, "Mounts": [{"Type": "bind", "Source": str(source), "Target": "/var/lib/camact", "ReadOnly": False}]},
            "Mounts": [{"Type": "bind", "Source": str(source), "Destination": "/var/lib/camact", "RW": True}]}
        return item, tmpfs, seccomp

    def test_actual_security_and_single_bind_are_required_before_release(self):
        source = Path(tempfile.gettempdir()) / "full-cache-fixture-data"
        for stage in validation.STAGES:
            for started in (False, True):
                actual, tmpfs, seccomp = self.actual(source, started=started, stage=stage)
                self.assertEqual(validation.container_errors(actual, manifest(), source, tmpfs, seccomp, started=started, stage=stage), [])
                mutations = [lambda value: value["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
                    lambda value: value["HostConfig"].update(Privileged=True),
                    lambda value: value["HostConfig"].update(ReadonlyRootfs=False),
                    lambda value: value["HostConfig"].update(NetworkMode="host"),
                    lambda value: value["HostConfig"].update(SecurityOpt=["apparmor=unconfined"]),
                    lambda value: value.update(Image="sha256:" + "f" * 64)]
                if started:
                    mutations.append(lambda value: value["Mounts"].append({"Type": "bind", "Source": "/fixture/secret",
                        "Destination": "/run/secrets/agent_api_key", "RW": False}))
                else:
                    mutations.append(lambda value: value["HostConfig"]["Mounts"].append({"Type": "bind", "Source": "/fixture/secret",
                        "Target": "/run/secrets/agent_api_key", "ReadOnly": True}))
                for mutate in mutations:
                    changed = deepcopy(actual)
                    mutate(changed)
                    self.assertTrue(validation.container_errors(changed, manifest(), source, tmpfs, seccomp, started=started, stage=stage))

    def test_no_container_can_be_created_before_complete_image_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(output=directory, image_run_id="123", repository="Fixture/release",
                                   expected_source_revision=SOURCE, version="0.1.0-rc.1")
            controller = validation.Controller(args)
            controller.manifest = manifest()
            with patch.object(controller, "call") as docker, self.assertRaisesRegex(validation.ValidationError, "scan_before"):
                controller.create("fixture-container", stage="download")
            docker.assert_not_called()

    def test_inside_environment_rejects_model_credentials_and_hf_home_token_injection(self):
        policy = SimpleNamespace(inside_evidence=lambda: {"checks": dict.fromkeys(validation.INNER_CHECKS - {"credential_environment"}, True)})
        env = {"HF_HUB_DISABLE_IMPLICIT_TOKEN": "1", "HF_HUB_DISABLE_TELEMETRY": "1", "HF_HUB_DISABLE_PROGRESS_BARS": "1",
               "HF_HOME": "/var/lib/camact/cache/huggingface", "HF_XET_CACHE": "/var/lib/camact/cache/huggingface/xet"}
        with patch.object(validation, "runner_policy", return_value=policy), patch.dict(os.environ, env, clear=True):
            self.assertTrue(all(validation.inside_checks().values()))
            for key in ("AGENT_API_KEY", "HF_TOKEN", "HF_TOKEN_FILE"):
                with patch.dict(os.environ, {key: "synthetic-only"}), self.assertRaises(validation.ValidationError):
                    validation.inside_checks()


class CancellationCleanup(unittest.TestCase):
    def test_labels_use_the_actual_run_and_attempt_and_are_unique_locally(self):
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "2"}, clear=True):
            self.assertEqual(validation.validation_run_label(), "1234-2")
        with patch.dict(os.environ, {}, clear=True):
            self.assertNotEqual(validation.validation_run_label(), validation.validation_run_label())
        for values in ({"GITHUB_RUN_ID": "1234"}, {"GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "../2"}):
            with patch.dict(os.environ, values, clear=True), self.assertRaises(validation.ValidationError):
                validation.validation_run_label()

    def controller(self, directory):
        args = SimpleNamespace(output=directory, image_run_id="123", repository="Fixture/release",
                               expected_source_revision=SOURCE, version="0.1.0-rc.1")
        controller = validation.Controller(args)
        controller.scanned = True
        controller.manifest = manifest()
        controller.tmpfs = {}
        controller.seccomp = {}
        return controller

    def test_storage_and_validation_create_include_both_scope_labels(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,
                {"GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "2"}, clear=True):
            controller = self.controller(directory)
            with patch.object(controller, "call") as docker, patch.object(controller, "inspect"):
                controller.create("fixture-helper")
                controller.create("fixture-download", stage="download")
            for call in docker.call_args_list:
                argv = call.args[0]
                self.assertEqual([argv[index + 1] for index, value in enumerate(argv) if value == "--label"],
                    ["camact.validation-run=1234-2", "camact.validation-kind=full-cache"])

    def test_actual_label_drift_cannot_pass_policy_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            actual = {"Config": {"Labels": dict(controller.container_labels)}}
            with patch.object(validation, "container_errors", return_value=[]), patch.object(controller, "call") as docker:
                docker.return_value.stdout = json.dumps(actual)
                controller.inspect("fixture", stage="download")
                actual["Config"]["Labels"]["camact.validation-kind"] = "recovery"
                docker.return_value.stdout = json.dumps(actual)
                with self.assertRaisesRegex(validation.ValidationError, "download_created_policy"):
                    controller.inspect("fixture", stage="download")

    def cleanup(self, inventories, *, removal=None, run="1234-2", kind="full-cache"):
        calls = []
        lists = iter(inventories)
        def command(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["docker", "ps"]:
                result = next(lists)
                if isinstance(result, Exception):
                    raise result
                return SimpleNamespace(returncode=0, stdout="\n".join(result))
            if removal is not None:
                return removal(argv)
            return SimpleNamespace(returncode=0, stdout="")
        with patch.object(validation.subprocess, "run", side_effect=command), patch("sys.stdout", new_callable=io.StringIO) as output:
            code = validation.cleanup_scope(run, kind)
        return code, json.loads(output.getvalue()), calls

    def test_empty_scope_passes_and_every_inventory_is_filtered_by_run_and_kind(self):
        code, report, calls = self.cleanup([[], []])
        self.assertEqual(code, 0)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["unexpected_containers"], 0)
        self.assertEqual(len(calls), 2)
        for argv in calls:
            self.assertEqual(argv, ["docker", "ps", "--all", "--quiet", "--filter", "label=camact.validation-run=1234-2",
                                   "--filter", "label=camact.validation-kind=full-cache"])

    def test_unexpected_container_is_removed_but_cleanup_still_fails(self):
        identifier = "a" * 12
        code, report, calls = self.cleanup([[identifier], []])
        self.assertEqual(code, 1)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["unexpected_containers"], 1)
        self.assertEqual(report["remaining_containers"], 0)
        self.assertEqual([argv for argv in calls if argv[:2] == ["docker", "rm"]], [["docker", "rm", "--force", identifier]])

    def test_removal_timeout_continues_other_scoped_cleanup_and_cannot_pass(self):
        identifiers = ["a" * 12, "b" * 12]
        def remove(argv):
            if argv[-1] == identifiers[0]:
                raise subprocess.TimeoutExpired(argv, 60)
            return SimpleNamespace(returncode=0)
        code, report, calls = self.cleanup([identifiers, identifiers[:1]], removal=remove)
        self.assertEqual(code, 1)
        self.assertEqual(report["remaining_containers"], 1)
        self.assertEqual(len([argv for argv in calls if argv[:2] == ["docker", "rm"]]), 2)

    def test_invalid_scope_inventory_or_timeout_never_removes_an_unproven_container(self):
        cases = [([], {"run": "1234-2 --all"}), ([], {"kind": "arbitrary"}),
                 ([["not-a-container-id"]], {}), ([subprocess.TimeoutExpired(["docker", "ps"], 60)], {})]
        for inventories, kwargs in cases:
            with self.subTest(kwargs=kwargs, inventories=str(inventories)):
                code, report, calls = self.cleanup(inventories, **kwargs)
                self.assertEqual(code, 1)
                self.assertEqual(report["result"], "FAIL")
                self.assertFalse(any(argv[:2] == ["docker", "rm"] for argv in calls))


class MemoryLayout(unittest.TestCase):
    def test_every_real_inside_stage_requires_the_memory_layout_check(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            gate = output / "release"
            gate.write_text("verified\n")
            with patch.object(validation, "READY", str(output / "ready.json")), \
                    patch.object(validation, "RELEASE", str(gate)), \
                    patch.object(validation, "inside_checks", return_value=dict.fromkeys(validation.INNER_CHECKS, True)), \
                    patch.object(validation, "validate_cache", return_value={"cache": {}, "offline": None}), \
                    patch.object(validation, "memory_layout", return_value={"synthetic_test": True}) as check, \
                    patch.dict(os.environ, {"CAMACT_SOURCE_REVISION": SOURCE, "CAMACT_IMAGE_VERSION": "0.1.0-rc.1", "CAMACT_IMAGE_DIGEST": IMAGE}):
                for stage in validation.STAGES:
                    args = SimpleNamespace(stage=stage, expected_source_revision=SOURCE, version="0.1.0-rc.1",
                                           image_id=IMAGE, output=output / (stage + ".json"))
                    self.assertEqual(validation.inside(args), 0)
                    self.assertEqual(json.loads(args.output.read_text())["memory_layout"], {"synthetic_test": True})
                self.assertEqual(check.call_count, 3)

    def fixture(self, directory, *, root_value=None, missing=False, symlink=False, no_tasks=False, missing_target=False):
        cache = Path(directory) / "cache"
        location, _ = b._location(cache, REPO, REVISION)
        snapshot = location / "snapshot"
        memory = snapshot / "users/fixture_a/base_memory"
        memory.mkdir(parents=True)
        (snapshot / "users/fixture_b/base_memory").mkdir(parents=True)
        content = {} if missing_target else {"users/fixture_a/base_memory/fixture.txt": b"synthetic-only\n"}
        if not no_tasks:
            for number in (1, 2):
                task = f"tasks/fixture_a/task_{number}"
                content[task + "/task.yaml"] = b"This sentinel is deliberately not YAML.\n"
                name = task + "/workspace/memory_snapshot/memory_manifest.json"
                if missing and number == 2:
                    continue
                value = str(memory) if number == 1 else os.path.relpath(memory, snapshot / task / "workspace/memory_snapshot")
                if root_value is not None and number == 1:
                    value = root_value(memory, snapshot)
                content[name] = (json.dumps({"runtime_root": value}) + "\n").encode()
        for name, value in content.items():
            path = snapshot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        files = {name: {"size": len(value), "algorithm": "git-sha1",
                       "digest": hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()}
                 for name, value in content.items()}
        b._atomic(location / "manifest.json", {"schema": b.SCHEMA, "repo_id": REPO, "revision": REVISION, "files": files})
        if symlink:
            target = memory.parent / "retained-memory"
            memory.rename(target)
            memory.symlink_to(target, target_is_directory=True)
        if missing_target:
            memory.rmdir()
        return cache, memory

    def test_absolute_and_parent_relative_roots_match_without_loading_task_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            cache, memory = self.fixture(directory)
            observed = validation.memory_layout(cache, REPO, REVISION)
        self.assertEqual(observed, {"tasks": 2, "users": 1, "absolute_roots": 1, "relative_roots": 1,
            "all_current_user_snapshot_roots_match": True, "alias_contract_valid": True})
        for private in ("fixture_a", "fixture_b", str(memory), "runtime_root", "task_1"):
            self.assertNotIn(private, json.dumps(observed))

    def test_every_scheduler_task_needs_a_memory_manifest_and_at_least_one_task(self):
        for options in ({"missing": True}, {"no_tasks": True}, {"symlink": True}, {"missing_target": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                cache, _ = self.fixture(directory, **options)
                with self.assertRaisesRegex(validation.ValidationError, "^memory_layout_invalid$"):
                    validation.memory_layout(cache, REPO, REVISION)

    def test_old_cross_user_cross_version_and_noncanonical_absolute_roots_are_rejected(self):
        values = [lambda memory, snapshot: "/old-host/users/fixture_a/base_memory",
            lambda memory, snapshot: str(snapshot / "users/fixture_b/base_memory"),
            lambda memory, snapshot: str(snapshot.parent.parent / ("1" * 40) / "snapshot/users/fixture_a/base_memory"),
            lambda memory, snapshot: str(memory.parent) + "/../fixture_a/base_memory",
            lambda memory, snapshot: "/" + str(memory), lambda memory, snapshot: str(memory) + "\0",
            lambda memory, snapshot: {"not": "a string"}, lambda memory, snapshot: None]
        for value in values:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                cache, _ = self.fixture(directory, root_value=value)
                with self.assertRaisesRegex(validation.ValidationError, "^memory_layout_invalid$"):
                    validation.memory_layout(cache, REPO, REVISION)

    def summary(self, layout):
        return {"schema": validation.SCHEMA, "stage": "download", "status": "PASS", "errors": [],
            "external_model_requests": 0, "canonical_tasks_run": 0, "security": dict.fromkeys(validation.INNER_CHECKS, True),
            "memory_layout": layout, "offline": None,
            "cache": {"schema": b.SCHEMA, "repo_id": b.DEFAULT_REPO, "revision": b.DEFAULT_REVISION,
                "file_count": 1, "total_bytes": 1, "manifest_sha256": "a" * 64, "marker_sha256": "b" * 64,
                "git_sha1_files": 1, "lfs_sha256_files": 0}}

    def test_summary_requires_complete_positive_counts_and_matching_recreated_layout(self):
        layout = {"tasks": 2, "users": 1, "absolute_roots": 1, "relative_roots": 1,
                  "all_current_user_snapshot_roots_match": True, "alias_contract_valid": True}
        validation.validate_inner(self.summary(layout), "download", expected_memory_layout=dict(layout))
        for changed in ({}, dict(layout, tasks=0), dict(layout, users=3), dict(layout, absolute_roots=True),
                        dict(layout, relative_roots=0), dict(layout, alias_contract_valid=False)):
            with self.subTest(changed=changed), self.assertRaises(validation.ValidationError):
                validation.validate_inner(self.summary(changed), "download")
        missing = self.summary(layout)
        missing.pop("memory_layout")
        with self.assertRaises(validation.ValidationError):
            validation.validate_inner(missing, "download")
        with self.assertRaisesRegex(validation.ValidationError, "memory_layout_changed"):
            validation.validate_inner(self.summary(layout), "download", expected_memory_layout=dict(layout, tasks=3))


if __name__ == "__main__":
    unittest.main()
