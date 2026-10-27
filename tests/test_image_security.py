"""Offline tests for the Docker archive security scanner."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "scan-image.py"
SYNTHETIC_KEY = "sk-" + "S" * 24


def tar_payload(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, value in entries:
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


def image_archive(config=None, layers=None, layer_names=None, include_layers=True):
    config = config or {"config": {"Env": ["SAFE=1"], "Labels": {"org.example.kind": "fixture"}}, "history": []}
    layers = layers or [tar_payload([("usr/local/bin/tool", b"\x00\x01safe-tool\x00")])]
    layer_names = layer_names or [f"layer-{number}/layer.tar" for number in range(len(layers))]
    config_name = "config.json"
    manifest = [{"Config": config_name, "RepoTags": ["camact:test"], "Layers": layer_names}]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, value in [("manifest.json", json.dumps(manifest).encode()), (config_name, json.dumps(config).encode())]:
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
        if include_layers:
            for name, value in zip(layer_names, layers):
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


def run_scan(payload):
    with tempfile.NamedTemporaryFile(suffix=".tar") as archive:
        archive.write(payload)
        archive.flush()
        process = subprocess.run(
            [sys.executable, "-B", str(SCANNER), "--archive", archive.name],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    return process.returncode, json.loads(process.stdout)


class ImageSecurityScannerTests(unittest.TestCase):
    def test_clean_binary_tool_archive_passes(self):
        code, result = run_scan(image_archive())
        self.assertEqual(code, 0)
        self.assertEqual(result["issue_count"], 0)
        self.assertFalse(result["candidate_values_printed"])

    def test_metadata_env_history_and_labels_are_scanned_without_values(self):
        config = {
            "config": {
                "Env": ["SERVICE_API_KEY=" + SYNTHETIC_KEY],
                "Labels": {"com.example.note": "token=" + SYNTHETIC_KEY},
            },
            "history": [{"created_by": "RUN export ACCESS_TOKEN=" + SYNTHETIC_KEY}],
        }
        code, result = run_scan(image_archive(config=config))
        self.assertNotEqual(code, 0)
        self.assertGreater(result["issue_count"], 0)
        serialized = json.dumps(result)
        self.assertNotIn(SYNTHETIC_KEY, serialized)
        self.assertTrue(any(issue["file"].startswith("config[0]") for issue in result["issues"]))

    def test_deleted_secret_is_detected_in_earlier_layer(self):
        first = tar_payload([("opt/camact/old.txt", ("value=" + SYNTHETIC_KEY).encode())])
        second = tar_payload([("opt/camact/.wh.old.txt", b"")])
        code, result = run_scan(image_archive(layers=[first, second]))
        self.assertNotEqual(code, 0)
        self.assertTrue(any(issue["kind"] == "provider_key" and issue["file"].startswith("layer[0]:") for issue in result["issues"]))
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))

    def test_personal_and_runtime_secret_paths_are_rejected(self):
        layer = tar_payload([
            ("opt/camact/.npmrc", b"opaque"),
            ("run/secrets/api_key", b"opaque"),
            ("opt/camact/third-party.log", b"ordinary log"),
        ])
        code, result = run_scan(image_archive(layers=[layer], layer_names=["layer/layer.tar"]))
        self.assertNotEqual(code, 0)
        kinds = {issue["kind"] for issue in result["issues"]}
        self.assertIn("personal_config_or_credential_path", kinds)
        self.assertIn("nonempty_runtime_secret_path", kinds)

    def test_missing_and_malformed_layers_fail_closed(self):
        missing = image_archive(layers=[tar_payload([("tool", b"ok")])], layer_names=["missing/layer.tar"], include_layers=False)
        code, result = run_scan(missing)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["issues"][0]["kind"], "scan_failed")
        malformed = image_archive(layers=[b"not a tar archive"])
        code, result = run_scan(malformed)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["issues"][0]["kind"], "scan_failed")
        malformed_config = image_archive(config={"history": []})
        code, result = run_scan(malformed_config)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["issues"][0]["kind"], "scan_failed")
        trailing = image_archive() + b"trailing bytes"
        code, result = run_scan(trailing)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["issues"][0]["kind"], "scan_failed")


if __name__ == "__main__":
    unittest.main()
