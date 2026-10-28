"""Offline tests for the Docker archive security scanner."""
from __future__ import annotations

import io
import hashlib
import importlib.util
import gzip
import json
import os
import ssl
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "scan-image.py"
_spec = importlib.util.spec_from_file_location("image_scanner", SCANNER)
scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner)
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


def oci_archive(*, dirty=False, extra_blob=False, secret_metadata=False, corrupt_layer=False):
    config = json.dumps({"config": {"Env": ["SAFE=1"]}, "history": []}).encode()
    layer = gzip.compress(tar_payload([("opt/camact/tool", SYNTHETIC_KEY.encode() if dirty else b"safe")]))
    def descriptor(raw, media_type):
        return {"mediaType": media_type, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    def name(item):
        return "blobs/sha256/" + item["digest"].split(":", 1)[1]
    cfg = descriptor(config, "application/vnd.oci.image.config.v1+json")
    compressed = descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
    document = {"schemaVersion": 2, "config": cfg, "layers": [compressed]}
    if secret_metadata:
        document["annotations"] = {"com.example.note": "SERVICE_API_KEY=" + SYNTHETIC_KEY}
    manifest = json.dumps(document).encode()
    image = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    entries = [("manifest.json", json.dumps([{"Config": name(cfg), "Layers": [name(compressed)]}]).encode()),
               ("index.json", json.dumps({"schemaVersion": 2, "manifests": [image]}).encode()),
               ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
               (name(cfg), config), (name(image), manifest),
               (name(compressed), layer[:-8] if corrupt_layer else layer)]
    if extra_blob:
        raw = tar_payload([("hidden", SYNTHETIC_KEY.encode())])
        entries.append(("blobs/sha256/" + hashlib.sha256(raw).hexdigest(), raw))
    return tar_payload(entries)


class ImageSecurityScannerTests(unittest.TestCase):
    def test_clean_binary_tool_archive_passes(self):
        code, result = run_scan(image_archive())
        self.assertEqual(code, 0)
        self.assertEqual(result["issue_count"], 0)
        self.assertFalse(result["candidate_values_printed"])

    def test_chunk_boundary_does_not_hide_binary_secret(self):
        data = b"\0" * (scanner.CHUNK_SIZE - 7) + SYNTHETIC_KEY.encode() + b"\0"
        code, result = run_scan(image_archive(layers=[tar_payload([("usr/bin/tool", data)])]))
        self.assertNotEqual(code, 0)
        self.assertIn("provider_key", {item["kind"] for item in result["issues"]})
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))

    def test_filename_candidates_are_redacted_too(self):
        filename = "opt/camact/" + SYNTHETIC_KEY + "/API_KEY=fixture-private-value"
        code, result = run_scan(image_archive(layers=[tar_payload([(filename, SYNTHETIC_KEY.encode())])]))
        self.assertNotEqual(code, 0)
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
        self.assertNotIn("fixture-private-value", json.dumps(result))

    def test_reviewed_findings_require_exact_path_file_hash_and_match(self):
        name = "opt/camact/.tools/node/bin/node"
        data = ("/" + "home/" + "upstream-builder\nAPI_KEY=fixture-literal\n").encode()
        known = []
        scanner.scan_stream(io.BytesIO(data), name, known)
        digest = hashlib.sha256(data).hexdigest()
        policy = {name: {digest: {"findings": [{key: value for key, value in item.items() if key != "file"} for item in known]}}}
        payload = image_archive(layers=[tar_payload([(name, data)])])
        self.assertEqual(scanner.scan_archive_bytes(io.BytesIO(payload), policy), [])
        with self.subTest("a separately pinned older layer at the same path"):
            older = b"safe-published-older-version"
            policy[name][hashlib.sha256(older).hexdigest()] = {"findings": []}
            payload = image_archive(layers=[tar_payload([(name, older)]), tar_payload([(name, data)])])
            self.assertEqual(scanner.scan_archive_bytes(io.BytesIO(payload), policy), [])
        with self.subTest("modified upstream file"):
            payload = image_archive(layers=[tar_payload([(name, data + SYNTHETIC_KEY.encode())])])
            findings = scanner.scan_archive_bytes(io.BytesIO(payload), policy)
            self.assertIn("upstream_file_digest_mismatch", {item["kind"] for item in findings})
            self.assertIn("provider_key", {item["kind"] for item in findings})
        with self.subTest("same contents at another path"):
            payload = image_archive(layers=[tar_payload([(name + "-copy", data)])])
            self.assertTrue(scanner.scan_archive_bytes(io.BytesIO(payload), policy))
        with self.subTest("unreviewed finding in the exact file"):
            partial = {name: {digest: {"findings": [known[0]]}}}
            payload = image_archive(layers=[tar_payload([(name, data)])])
            findings = scanner.scan_archive_bytes(io.BytesIO(payload), partial)
            self.assertIn("nonempty_secret_assignment", {item["kind"] for item in findings})
        with self.subTest("secret elsewhere in an approved dependency directory"):
            payload = image_archive(layers=[tar_payload([(name, data), (name + ".extra", SYNTHETIC_KEY.encode())])])
            findings = scanner.scan_archive_bytes(io.BytesIO(payload), policy)
            self.assertIn("provider_key", {item["kind"] for item in findings})

    def test_docker_save_preserves_specific_sanitized_failure(self):
        payload = image_archive(include_layers=False)
        class DockerSave:
            stdout = io.BytesIO(payload)
            def wait(self): return 0
            def poll(self): return 0
        with patch.object(scanner.subprocess, "Popen", return_value=DockerSave()):
            with self.assertRaises(scanner.ScanFailure) as error:
                scanner.run_archive(None, "fixture-image", {})
        self.assertEqual(error.exception.reason, "missing_image_layer")

    def test_docker_save_error_never_prints_raw_stderr(self):
        with tempfile.TemporaryDirectory() as temporary:
            docker = Path(temporary) / "docker"
            docker.write_text("#!/bin/sh\nprintf '%s' '" + SYNTHETIC_KEY + "' >&2\nexit 17\n")
            docker.chmod(0o700)
            process = subprocess.run([sys.executable, "-B", str(SCANNER), "--image", "fixture-image"],
                capture_output=True, text=True, env=os.environ | {"CAMACT_DOCKER": str(docker)})
        self.assertNotEqual(process.returncode, 0)
        result = json.loads(process.stdout)
        self.assertEqual(result["issues"][0]["reason"], "docker_save_failed")
        self.assertEqual(result["issues"][0]["exit_code"], 17)
        self.assertNotIn(SYNTHETIC_KEY, process.stdout + process.stderr)

    def test_large_archives_do_not_require_unbounded_reads(self):
        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                if size < 0:
                    raise AssertionError("Entire Docker archive was read into memory")
                return super().read(size)
        payload = image_archive(layers=[tar_payload([("tool", b"\0" * (scanner.CHUNK_SIZE * 2))])])
        self.assertEqual(scanner.scan_archive_bytes(BoundedReader(payload)), [])

    def test_directory_and_symlink_only_layer_is_valid(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            root = tarfile.TarInfo("./")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            directory = tarfile.TarInfo("var/lib/camact")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            link = tarfile.TarInfo("usr/bin/python3")
            link.type = tarfile.SYMTYPE
            link.linkname = "/usr/local/bin/python3"
            archive.addfile(link)
        code, result = run_scan(image_archive(layers=[output.getvalue()]))
        self.assertEqual(code, 0, result)

    def test_root_directory_allowance_does_not_allow_unsafe_paths(self):
        for name in ("../escape", "/absolute/file", "./"):
            with self.subTest(name=name):
                code, result = run_scan(image_archive(layers=[tar_payload([(name, b"safe")])]))
                self.assertNotEqual(code, 0)
                self.assertEqual(result["issues"][0]["reason"], "unsafe_archive_path")

    def test_oci_docker_save_and_compressed_layers_are_scanned(self):
        code, result = run_scan(oci_archive())
        self.assertEqual(code, 0, result)
        self.assertEqual(result["files_scanned"], 1)
        for option in ("dirty", "secret_metadata"):
            with self.subTest(option=option):
                code, result = run_scan(oci_archive(**{option: True}))
                self.assertNotEqual(code, 0)
                self.assertIn("provider_key", {item["kind"] for item in result["issues"]})
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))

    def test_undeclared_oci_blobs_and_truncated_compression_fail_closed(self):
        for option in ("extra_blob", "corrupt_layer"):
            with self.subTest(option=option):
                code, result = run_scan(oci_archive(**{option: True}))
                self.assertNotEqual(code, 0)
                self.assertEqual(result["issues"][0]["kind"], "scan_failed")
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))

    def test_only_valid_public_certificates_qualify_for_pem_paths(self):
        certificates = ssl.create_default_context().get_ca_certs(binary_form=True)
        self.assertTrue(certificates, "The release runtime must provide public CA certificates")
        pem = ssl.DER_cert_to_PEM_cert(certificates[0]).encode()
        code, result = run_scan(image_archive(layers=[tar_payload([("usr/share/camact/ca.pem", pem)])]))
        self.assertEqual(code, 0, result)
        for path, data in (("usr/share/camact/ca.pem", pem + SYNTHETIC_KEY.encode()),
                           ("usr/share/camact/ca.pem", b"-----BEGIN CERTIFICATE-----\nabcd\n-----END CERTIFICATE-----\n"),
                           ("opt/camact/.ssh/ca.pem", pem), ("run/secrets/ca.pem", pem)):
            with self.subTest(path=path, size=len(data)):
                code, result = run_scan(image_archive(layers=[tar_payload([(path, data)])]))
                self.assertNotEqual(code, 0)

    def test_ca_symlinks_require_a_verified_public_target(self):
        certificates = ssl.create_default_context().get_ca_certs(binary_form=True)
        pem = ssl.DER_cert_to_PEM_cert(certificates[0]).encode()
        for link_path, content, expected in (("etc/ssl/certs/Fixture.pem", pem, 0),
                                              ("etc/ssl/certs/Fixture.pem", SYNTHETIC_KEY.encode(), 1),
                                              ("etc/ssl/certs/.ssh/Fixture.pem", pem, 1),
                                              ("etc/ssl/certs/.env.pem", pem, 1)):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w") as archive:
                link = tarfile.TarInfo(link_path)
                link.type = tarfile.SYMTYPE
                link.linkname = "/usr/share/ca-certificates/fixture.crt"
                archive.addfile(link)
                certificate = tarfile.TarInfo("usr/share/ca-certificates/fixture.crt")
                certificate.size = len(content)
                archive.addfile(certificate, io.BytesIO(content))
            code, result = run_scan(image_archive(layers=[output.getvalue()]))
            self.assertEqual(code, expected, result)

    def test_exception_provenance_must_match_current_locks(self):
        read_text = Path.read_text
        def tampered(path, *args, **kwargs):
            text = read_text(path, *args, **kwargs)
            if path.name == "image-scan-exceptions.json":
                policy = json.loads(text)
                source = next(iter(policy["sources"].values()))
                source["integrity"] = "sha256:" + "0" * 64
                return json.dumps(policy)
            return text
        with patch.object(Path, "read_text", tampered):
            with self.assertRaises(scanner.ScanFailure) as error:
                scanner.load_exceptions()
        self.assertEqual(error.exception.reason, "invalid_upstream_exception_policy")

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
