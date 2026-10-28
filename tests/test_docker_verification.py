"""Exercise real shell failure gates with a disposable Docker protocol stub."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_image_security import SYNTHETIC_KEY, image_archive, tar_payload

ROOT = Path(__file__).resolve().parents[1]


class DockerVerificationDiagnostics(unittest.TestCase):
    def run_gate(self, *, dirty):
        with tempfile.TemporaryDirectory(prefix="camact-gate-regression-") as temporary:
            project = Path(temporary)
            (project / "scripts").mkdir()
            for name in ("verify-docker.sh", "scan-image.py", "scan-release.py"):
                shutil.copy2(ROOT / "scripts" / name, project / "scripts" / name)
            shutil.copytree(ROOT / "locks", project / "locks")
            shutil.copy2(ROOT / "Dockerfile", project / "Dockerfile")
            (project / "camactctl").write_text("#!/bin/sh\nexit 0\n")
            (project / "camactctl").chmod(0o700)
            fixture = project / "fixture.tar"
            fixture.write_bytes(image_archive(layers=[tar_payload([
                ("opt/camact/fixture.txt", SYNTHETIC_KEY.encode() if dirty else b"safe")])]))
            bin_dir = project / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text("#!" + sys.executable + "\n" + '''import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(__file__).resolve().parents[1]
with (root / "docker-calls.jsonl").open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
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
elif "storage-init" in args:
    sys.exit(23)
elif args[:1] != ["compose"]:
    sys.exit(99)
''')
            docker.chmod(0o700)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CAMACT_", "AGENT_", "JUDGE_", "SIMULATOR_", "HF_"))}
            env.update(PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       CAMACT_IMAGE="fixture-image", CAMACT_VERIFY_SKIP_BUILD="1")
            process = subprocess.run(["bash", "scripts/verify-docker.sh"], cwd=project, env=env,
                                     capture_output=True, text=True, timeout=30)
            evidence = next((project / ".validation").glob("docker-gates-*"))
            summary = json.loads((evidence / "verification-summary.json").read_text())
            scan = json.loads((evidence / "image-security-scan.json").read_text())
            calls = [json.loads(line) for line in (project / "docker-calls.jsonl").read_text().splitlines()]
        return process, summary, scan, calls

    def test_scan_failure_is_visible_redacted_and_stops_integration(self):
        process, summary, scan, calls = self.run_gate(dirty=True)
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertEqual(summary["stage"], "image-security-scan")
        self.assertEqual(summary["result"], "FAIL")
        self.assertIn('"kind": "provider_key"', process.stdout)
        self.assertIn("opt/camact/fixture.txt", process.stdout)
        self.assertIn("stage=image-security-scan", process.stdout + process.stderr)
        self.assertNotIn(SYNTHETIC_KEY, process.stdout + process.stderr + json.dumps(scan))
        self.assertFalse(any("storage-init" in call for call in calls))

    def test_later_compose_failure_reports_its_stage_and_exit_status(self):
        process, summary, scan, calls = self.run_gate(dirty=False)
        self.assertEqual(scan["result"], "PASS")
        self.assertEqual(process.returncode, 23, process.stderr)
        self.assertEqual(summary["stage"], "storage-initialization")
        self.assertEqual(summary["exit_code"], 23)
        self.assertIn("stage=storage-initialization", process.stdout + process.stderr)
