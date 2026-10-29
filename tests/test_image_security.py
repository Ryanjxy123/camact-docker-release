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


def moby_archive(*, dirty_layer=False, secret_legacy=False, secret_history=False,
                 legacy_mutation=None, config_mutation=None, single_layer=False,
                 intermediate_created="1970-01-01T00:00:00Z", extra_members=()):
    """Model Moby v28.5.1 image/tarexport/save.go's hybrid Docker/OCI export.

    saveConfig writes one unreferenced V1 JSON blob per diff ID. CreateID
    hashes sorted top-level RawMessages while retaining nested struct order.
    """
    def go_json(value):
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return (encoded.replace("&", "\\u0026").replace("<", "\\u003c")
                .replace(">", "\\u003e").replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029")).encode()

    # Mandatory fields in the zero-valued Docker container.Config struct,
    # in the order emitted by Go's encoding/json (optional fields are absent).
    container_config = {"Hostname": "", "Domainname": "", "User": "", "AttachStdin": False,
                        "AttachStdout": False, "AttachStderr": False, "Tty": False,
                        "OpenStdin": False, "StdinOnce": False, "Env": None, "Cmd": None,
                        "Image": "", "Volumes": None, "WorkingDir": "", "Entrypoint": None,
                        "OnBuild": None, "Labels": None}
    first = tar_payload([("opt/camact/old.txt", SYNTHETIC_KEY.encode() if dirty_layer else b"safe")])
    second = tar_payload([("opt/camact/.wh.old.txt", b"")])
    layers = [first] if single_layer else [first, second]
    diff_ids = ["sha256:" + hashlib.sha256(raw).hexdigest() for raw in layers]
    config = {"created": "2026-10-28T00:00:00Z", "container_config": container_config,
              "config": {"Env": ["SAFE=1"], "Labels": {"org.example.note": "<>& 中文\u2028\u2029"}},
              "architecture": "amd64", "os": "linux",
              "rootfs": {"type": "layers", "diff_ids": diff_ids},
              "history": [{"created_by": "COPY old.txt /opt/camact/old.txt"},
                          {"created_by": "RUN rm /opt/camact/old.txt"}]}
    if secret_history:
        config["history"][0]["created_by"] = "RUN export SERVICE_API_KEY=" + SYNTHETIC_KEY
    config["history"] = config["history"][:len(layers)]
    legacy = []
    parent = ""
    chain_id = ""
    for index, diff_id in enumerate(diff_ids):
        chain_id = diff_id if index == 0 else "sha256:" + hashlib.sha256(
            (chain_id + " " + diff_id).encode()).hexdigest()
        original = ({"created": intermediate_created, "container_config": container_config}
                    if index < len(diff_ids) - 1 else {key: value for key, value in config.items()
                                                      if key not in {"rootfs", "history"}})
        if secret_legacy and index == len(diff_ids) - 1:
            # Historical V1 metadata can hold credentials absent from the final config.
            original["container_config"] = dict(container_config, Env=["SERVICE_API_KEY=" + SYNTHETIC_KEY])
        identity = dict(original, layer_id=chain_id)
        if parent:
            identity["parent"] = "sha256:" + parent
        legacy_id = hashlib.sha256(go_json(dict(sorted(identity.items())))).hexdigest()
        value = {"id": legacy_id}
        if parent:
            value["parent"] = parent
        value.update(original)
        value["os"] = config["os"]  # Moby sets this after CreateID on intermediate configs.
        legacy.append(value)
        parent = legacy_id

    if legacy_mutation is not None:
        legacy_mutation(legacy, chain_id)
    if config_mutation is not None:
        config_mutation(config)

    def descriptor(raw, media_type):
        return {"mediaType": media_type, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "size": len(raw)}

    def blob_name(item):
        return "blobs/sha256/" + item["digest"].split(":", 1)[1]

    config_raw = go_json(config)
    cfg = descriptor(config_raw, "application/vnd.oci.image.config.v1+json")
    layer_descriptors = [descriptor(raw, "application/vnd.oci.image.layer.v1.tar") for raw in layers]
    manifest_raw = go_json({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "config": cfg, "layers": layer_descriptors})
    image = descriptor(manifest_raw, "application/vnd.oci.image.manifest.v1+json")
    entries = [("manifest.json", go_json([{"Config": blob_name(cfg), "RepoTags": ["camact:test"],
                                         "Layers": [blob_name(item) for item in layer_descriptors]}])),
               ("index.json", go_json({"schemaVersion": 2, "manifests": [image]})),
               ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
               (blob_name(cfg), config_raw), (blob_name(image), manifest_raw)]
    entries.extend((blob_name(item), raw) for item, raw in zip(layer_descriptors, layers))
    for value in legacy:
        raw = go_json(value)
        entries.append(("blobs/sha256/" + hashlib.sha256(raw).hexdigest(), raw))
    entries.extend(extra_members)
    return tar_payload(entries)


class ImageSecurityScannerTests(unittest.TestCase):
    def test_empty_regular_and_opaque_whiteouts_are_valid(self):
        markers = tar_payload([("etc/ssl/certs/.wh.Comodo_AAA_Services_root.pem", b""),
                               ("etc/ssl/certs/.wh..wh..opq", b""),
                               (".wh..wh..opq", b""), ("run/secrets/.wh.api_key", b"")])
        for layer in (markers, gzip.compress(markers)):
            with self.subTest(compressed=layer != markers):
                code, result = run_scan(image_archive(layers=[layer]))
                self.assertEqual(code, 0, result)
                self.assertEqual(result["whiteouts_validated"], 4)
                self.assertEqual(result["opaque_whiteouts_validated"], 2)
                self.assertEqual(result["bytes_scanned"], 0)

    def test_abnormal_whiteouts_fail_closed_without_printing_candidates(self):
        cases = []
        for name in (".wh.", ".wh..", ".wh...", ".wh..wh.invalid", ".wh.deleted/hidden"):
            cases.append((tarfile.TarInfo(name), b""))
        for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE,
                     tarfile.CHRTYPE, tarfile.FIFOTYPE, tarfile.CONTTYPE):
            member = tarfile.TarInfo("etc/ssl/certs/.wh.fixture.pem")
            member.type = kind
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = "fixture"
            cases.append((member, b""))
        for data, attributes in ((SYNTHETIC_KEY.encode(), {}),
                                  (b"", {"linkname": "fixture"}),
                                  (b"", {"devminor": 1}),
                                  (b"", {"pax_headers": {"GNU.sparse.map": "0,0"}})):
            member = tarfile.TarInfo("etc/ssl/certs/.wh.fixture.pem")
            member.size = len(data)
            for key, value in attributes.items():
                setattr(member, key, value)
            cases.append((member, data))
        for member, data in cases:
            with self.subTest(name=member.name, kind=member.type, linkname=member.linkname,
                              devminor=member.devminor, attributes=member.pax_headers):
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w") as archive:
                    archive.addfile(member, io.BytesIO(data))
                payload = output.getvalue()
                if member.devminor:
                    # TarInfo serializes device fields only for device members.
                    # Encode the malformed regular header itself, with a valid checksum.
                    payload = bytearray(payload)
                    payload[337:345] = b"0000001\0"
                    payload[148:156] = b"        "
                    payload[148:156] = f"{sum(payload[:512]):06o}\0 ".encode()
                    payload = bytes(payload)
                code, result = run_scan(image_archive(layers=[payload]))
                self.assertNotEqual(code, 0, result)
                self.assertEqual(result["issues"][0]["kind"], "scan_failed")
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))

    def test_whiteouts_preserve_all_historical_sensitive_findings(self):
        first = tar_payload([("opt/camact/.ssh/id_rsa", b"opaque-private-data"),
                             ("opt/camact/old.txt", SYNTHETIC_KEY.encode())])
        for marker in ("opt/camact/.ssh/.wh.id_rsa", "opt/camact/.ssh/.wh..wh..opq"):
            with self.subTest(marker=marker):
                second = tar_payload([(marker, b""), ("opt/camact/.wh.old.txt", b"")])
                code, result = run_scan(image_archive(layers=[first, second]))
                self.assertNotEqual(code, 0)
                kinds = {item["kind"] for item in result["issues"] if item["file"].startswith("layer[0]:")}
                self.assertIn("personal_config_or_credential_path", kinds)
                self.assertIn("provider_key", kinds)
                self.assertEqual(result["whiteouts_validated"], 2)
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
        code, result = run_scan(image_archive(layers=[tar_payload([(".wh." + SYNTHETIC_KEY, b"")])]))
        self.assertNotEqual(code, 0)
        self.assertIn("provider_key", {item["kind"] for item in result["issues"]})
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))

    def test_whiteout_certificate_state_is_layer_local_and_order_independent(self):
        pem = ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0]).encode()
        target = "usr/share/ca-certificates/fixture.crt"
        def layer(entries, link=None):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w") as archive:
                for name, data in entries:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                if link:
                    member = tarfile.TarInfo("etc/ssl/certs/" + link + ".pem")
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/" + target
                    archive.addfile(member)
            return output.getvalue()
        first = layer([(target, pem)], "historical")
        for marker in ("usr/share/ca-certificates/.wh.fixture.crt",
                       "usr/share/ca-certificates/.wh..wh..opq"):
            with self.subTest(marker=marker):
                # A later deletion does not invalidate an already checked link.
                code, result = run_scan(image_archive(layers=[first, layer([(marker, b"")])]))
                self.assertEqual(code, 0, result)
                # A new link cannot inherit trust in the deleted certificate.
                code, result = run_scan(image_archive(layers=[first, layer([(marker, b"")], "new")]))
                self.assertNotEqual(code, 0)
                self.assertTrue(any(item["file"] == "layer[1]:etc/ssl/certs/new.pem" for item in result["issues"]))
                for entries in ([(target, pem), (marker, b"")], [(marker, b""), (target, pem)]):
                    code, result = run_scan(image_archive(layers=[first, layer(entries, "new")]))
                    self.assertEqual(code, 0, result)
        # A symlink replacing a former certificate is not a verified certificate.
        for replaced in (target, "usr/share/ca-certificates"):
            with self.subTest(replaced=replaced):
                replacement = io.BytesIO()
                with tarfile.open(fileobj=replacement, mode="w") as archive:
                    for name, destination in ((replaced, "/missing"), ("etc/ssl/certs/new.pem", "/" + target)):
                        member = tarfile.TarInfo(name)
                        member.type = tarfile.SYMTYPE
                        member.linkname = destination
                        archive.addfile(member)
                code, result = run_scan(image_archive(layers=[first, replacement.getvalue()]))
                self.assertNotEqual(code, 0)
                self.assertTrue(any(item["file"] == "layer[1]:etc/ssl/certs/new.pem" for item in result["issues"]))

    def test_clean_binary_tool_archive_passes(self):
        code, result = run_scan(image_archive())
        self.assertEqual(code, 0)
        self.assertEqual(result["issue_count"], 0)
        self.assertFalse(result["candidate_values_printed"])

    def test_production_compose_runtime_secret_references_pass(self):
        code, result = run_scan(image_archive(layers=[tar_payload([
            ("opt/camact/compose.yaml", (ROOT / "compose.yaml").read_bytes()),
        ])]))
        self.assertEqual(code, 0, result)
        self.assertEqual(result["issue_count"], 0)

    def test_only_complete_trusted_compose_secret_file_assignments_pass(self):
        for role in ("agent", "judge", "simulator"):
            name = role.upper() + "_API_KEY_FILE"
            path = "/run/secrets/" + role + "_api_key"
            for quote in ("", "'", '"'):
                with self.subTest(role=role, quote=quote):
                    issues = []
                    scanner.scan_text("\n\t " + name + ": " + quote + path + quote
                                      + "  # runtime mount\r\n",
                                      "layer[6]:opt/camact/compose.yaml", issues)
                    self.assertEqual(issues, [])

    def test_untrusted_secret_file_assignments_still_fail_without_values(self):
        for role in ("agent", "judge", "simulator"):
            name = role.upper() + "_API_KEY_FILE"
            path = "/run/secrets/" + role + "_api_key"
            cases = [
                name + ": opaque-hardcoded-value\n",
                name + ": " + SYNTHETIC_KEY + "\n",
                name + ": /tmp/" + role + "_api_key\n",
                name + ": /run/secrets/../" + role + "_api_key\n",
                name + ": /run/secrets//" + role + "_api_key\n",
                name + ": " + path + "/extra\n",
                name + ": " + path + ".backup\n",
                name + ": " + path + "?value=opaque-hardcoded-value\n",
                name + ": " + path + " extra-value\n",
                name + ": \"" + path + "\" + opaque-hardcoded-value\n",
                name + ": \"" + path + " opaque-hardcoded-value\"\n",
                name + ": '" + path + "\"\n",
                name + ": " + path + "#opaque-hardcoded-value\n",
                name + "=" + path + "\n",
                "export " + name + "=" + path + "\n",
                "ENV " + name + "=" + path + "\n",
                name + ": " + path,  # A chunk ending here does not prove a complete line.
                name + ": " + path + " " * (scanner.TAIL_SIZE + 1),
                name + ": /run/secrets/other_api_key\n",
                name + ": /run/secrets/" + ("judge" if role == "agent" else "agent") + "_api_key\n",
                role.upper() + "_API_KEY: " + path + "\n",
                "OTHER_API_KEY_FILE: " + path + "\n",
            ]
            for number, text in enumerate(cases):
                with self.subTest(role=role, case=number):
                    issues = []
                    scanner.scan_text(text, "layer[6]:opt/camact/compose.yaml", issues)
                    self.assertIn("nonempty_secret_assignment", {item["kind"] for item in issues})
                    self.assertNotIn("opaque-hardcoded-value", json.dumps(issues))
                    self.assertNotIn(SYNTHETIC_KEY, json.dumps(issues))

    def test_runtime_secret_reference_trust_does_not_extend_to_other_locations_or_metadata(self):
        text = "AGENT_API_KEY_FILE: /run/secrets/agent_api_key\n"
        for location, metadata in (("layer[6]:opt/camact/other.yaml", False),
                                   ("layer[6]:tmp/compose.yaml", False),
                                   ("layer[6]:opt/camact/compose.yaml.backup", False),
                                   ("layer[6]:opt/camact/compose.yaml", True),
                                   ("config[0].Env[0]", True),
                                   ("config[0].history[0]", True),
                                   ("config[0].labels[0]", True)):
            with self.subTest(location=location, metadata=metadata):
                issues = []
                scanner.scan_text(text, location, issues, metadata=metadata)
                expected = "nonempty_secret_metadata" if metadata else "nonempty_secret_assignment"
                self.assertIn(expected, {item["kind"] for item in issues})

    def test_compose_reference_does_not_hide_embedded_secrets_or_secret_file_contents(self):
        text = (ROOT / "compose.yaml").read_bytes()
        for extra, expected in ((b"\n      SERVICE_API_KEY: opaque-hardcoded-value\n", "nonempty_secret_assignment"),
                                (b"\n# " + SYNTHETIC_KEY.encode() + b"\n", "provider_key"),
                                (b"\n# -----BEGIN " + b"PRIVATE KEY-----\n", "private_key"),
                                (b"\n# https://" + b"198.51.100.23/api\n", "numeric_gateway")):
            with self.subTest(expected=expected):
                code, result = run_scan(image_archive(layers=[tar_payload([
                    ("opt/camact/compose.yaml", text + extra),
                ])]))
                self.assertNotEqual(code, 0)
                self.assertIn(expected, {item["kind"] for item in result["issues"]})
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
                self.assertNotIn("opaque-hardcoded-value", json.dumps(result))
        code, result = run_scan(image_archive(layers=[tar_payload([
            ("opt/camact/compose.yaml", text), ("run/secrets/agent_api_key", b"opaque-hardcoded-value"),
        ])]))
        self.assertNotEqual(code, 0)
        self.assertIn("nonempty_runtime_secret_path", {item["kind"] for item in result["issues"]})

    def test_chunk_boundary_does_not_turn_an_incomplete_reference_into_a_trusted_line(self):
        prefix = b"AGENT_API_KEY_FILE: /run/secrets/agent_api_key"
        data = prefix + b" " * (scanner.CHUNK_SIZE - len(prefix)) + b"opaque-hardcoded-value\n"
        code, result = run_scan(image_archive(layers=[tar_payload([("opt/camact/compose.yaml", data)])]))
        self.assertNotEqual(code, 0)
        self.assertIn("nonempty_secret_assignment", {item["kind"] for item in result["issues"]})
        self.assertNotIn("opaque-hardcoded-value", json.dumps(result))

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

    def test_moby_legacy_configs_bound_to_declared_layer_chain_pass(self):
        for single_layer, created in ((False, "1970-01-01T00:00:00Z"),
                                      (True, "1970-01-01T00:00:00Z"),
                                      (False, "1970-01-01T08:00:00+08:00")):
            with self.subTest(single_layer=single_layer, intermediate_created=created):
                code, result = run_scan(moby_archive(single_layer=single_layer, intermediate_created=created))
                self.assertEqual(code, 0, result)
                self.assertEqual(result["files_scanned"], 1 if single_layer else 2)
                self.assertEqual(result["issue_count"], 0)

    def test_moby_layers_history_and_legacy_metadata_keep_secret_detection(self):
        for option, location in (("dirty_layer", "layer[0]:"), ("secret_history", "config[0]"),
                                 ("secret_legacy", "blobs/sha256/")):
            with self.subTest(option=option):
                code, result = run_scan(moby_archive(**{option: True}))
                self.assertNotEqual(code, 0)
                self.assertTrue(any(item["kind"] == "provider_key" and item["file"].startswith(location)
                                    for item in result["issues"]), result)
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
                self.assertEqual(result["files_scanned"], 2)
        with self.subTest(option="JSON-escaped legacy secret"):
            with tarfile.open(fileobj=io.BytesIO(moby_archive(secret_legacy=True))) as archive:
                entries = [(member.name, archive.extractfile(member).read()) for member in archive if member.isfile()]
            assignment = "SERVICE_API_KEY=" + SYNTHETIC_KEY
            escaped = "".join("\\u%04x" % ord(character) for character in assignment).encode()
            raw = entries[-1][1].replace(assignment.encode(), escaped)
            self.assertNotEqual(raw, entries[-1][1])
            entries[-1] = ("blobs/sha256/" + hashlib.sha256(raw).hexdigest(), raw)
            code, result = run_scan(tar_payload(entries))
            self.assertNotEqual(code, 0)
            self.assertTrue(any(item["kind"] == "provider_key" and item["file"].startswith("blobs/sha256/")
                                for item in result["issues"]), result)
            self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
            self.assertEqual(result["files_scanned"], 2)
        with tarfile.open(fileobj=io.BytesIO(moby_archive())) as archive:
            clean_entries = [(member.name, archive.extractfile(member).read()) for member in archive if member.isfile()]
        raw = clean_entries[-1][1]
        duplicates = {
            "top-level key": b'{"container_config":{"Env":["' + escaped + b'"]},' + raw[1:],
            "nested key": raw.replace(b'"Env":null', b'"Env":["' + escaped + b'"],"Env":null', 1),
        }
        for kind, duplicate in duplicates.items():
            with self.subTest(option="duplicate JSON " + kind):
                entries = clean_entries[:-1] + [("blobs/sha256/" + hashlib.sha256(duplicate).hexdigest(), duplicate)]
                code, result = run_scan(tar_payload(entries))
                self.assertNotEqual(code, 0)
                self.assertEqual(result["issues"][0]["reason"], "undeclared_image_layer", result)
                self.assertEqual(result["issues"][0]["stage"], "layer-inventory")
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))

    def test_invalid_or_incomplete_moby_legacy_chains_fail_closed(self):
        def malformed_field(key, item):
            def mutate(values, chain_id):
                value = values[-1]
                value[key] = item
                identity = {key: item for key, item in value.items() if key not in {"id", "parent"}}
                identity.update(layer_id=chain_id, parent="sha256:" + value["parent"])
                encoded = json.dumps(dict(sorted(identity.items())), ensure_ascii=False, separators=(",", ":"))
                for character in "<>&\u2028\u2029":
                    encoded = encoded.replace(character, "\\u" + format(ord(character), "04x"))
                value["id"] = hashlib.sha256(encoded.encode()).hexdigest()
            return mutate

        mutations = {
            "wrong id": lambda values, _: values[-1].update(id="0" * 64),
            "wrong parent": lambda values, _: values[-1].update(parent="0" * 64),
            "unknown field": malformed_field("unexpected", "fixture"),
            "incomplete chain": lambda values, _: values.pop(),
            "wrong intermediate OS": lambda values, _: values[0].update(os="unexpected-os"),
            "invalid config type": malformed_field("config", []),
            "invalid container config type": malformed_field("container_config", []),
            "invalid created type": malformed_field("created", {}),
            "invalid Size type": malformed_field("Size", True),
            "invalid author type": malformed_field("author", []),
            "non-JSON NaN": malformed_field("config", {"Healthcheck": {"Interval": float("nan")}}),
            "non-JSON Infinity": malformed_field("config", {"Healthcheck": {"Interval": float("inf")}}),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                code, result = run_scan(moby_archive(legacy_mutation=mutation))
                self.assertNotEqual(code, 0)
                self.assertEqual(result["issues"][0]["reason"], "undeclared_image_layer", result)
                self.assertGreater(result["issues"][0]["inventory"]["unreferenced_blobs"], 0)
        rootfs_mutations = {
            "missing rootfs": lambda config: config.pop("rootfs"),
            "invalid rootfs type": lambda config: config.update(rootfs=[]),
            "unsupported rootfs format": lambda config: config["rootfs"].update(type="unexpected"),
            "invalid diff IDs type": lambda config: config["rootfs"].update(diff_ids="invalid"),
            "wrong layer count": lambda config: config["rootfs"]["diff_ids"].pop(),
            "invalid diff ID": lambda config: config["rootfs"]["diff_ids"].__setitem__(0, "sha256:invalid"),
            "unrelated diff ID": lambda config: config["rootfs"]["diff_ids"].__setitem__(0, "sha256:" + "0" * 64),
        }
        for name, mutation in rootfs_mutations.items():
            with self.subTest(name=name):
                code, result = run_scan(moby_archive(config_mutation=mutation))
                self.assertNotEqual(code, 0)
                self.assertEqual(result["issues"][0]["reason"], "undeclared_image_layer", result)
        for created in ("1970-01-01T00:00:01Z", "1970-01-01T00:00:00"):
            with self.subTest(intermediate_created=created):
                code, result = run_scan(moby_archive(intermediate_created=created))
                self.assertNotEqual(code, 0)
                self.assertEqual(result["issues"][0]["reason"], "undeclared_image_layer", result)

    def test_moby_legacy_blob_digest_is_verified(self):
        with tarfile.open(fileobj=io.BytesIO(moby_archive())) as archive:
            entries = [(member.name, archive.extractfile(member).read()) for member in archive if member.isfile()]
        name, raw = entries[-1]
        entries[-1] = ("blobs/sha256/" + "0" * 64, raw)
        self.assertNotEqual(name, entries[-1][0])
        code, result = run_scan(tar_payload(entries))
        self.assertNotEqual(code, 0)
        self.assertEqual(result["issues"][0]["reason"], "legacy_config_digest_mismatch", result)

    def test_moby_unreferenced_json_layers_and_blobs_fail_with_safe_inventory(self):
        extras = [("hidden.tar", tar_payload([("hidden", SYNTHETIC_KEY.encode())])),
                  ("blobs/sha256/" + "a" * 64, b'{"unexpected":"metadata"}'),
                  ("blobs/sha256/" + "b" * 64, b"opaque-orphan-blob")]
        for extra in extras:
            with self.subTest(path=extra[0]):
                code, result = run_scan(moby_archive(extra_members=[extra]))
                self.assertNotEqual(code, 0)
                self.assertEqual(result["issues"][0]["reason"], "undeclared_image_layer", result)
                self.assertEqual(result["issues"][0]["inventory"]["actual_layers"], 3)
        for index in range(12):
            extras.append(("blobs/sha256/" + SYNTHETIC_KEY + str(index), b'{"note":"fixture-private-value"}'))
        code, result = run_scan(moby_archive(extra_members=extras))
        self.assertNotEqual(code, 0)
        failure = result["issues"][0]
        self.assertEqual(failure["reason"], "undeclared_image_layer", result)
        self.assertEqual(failure["stage"], "layer-inventory")
        self.assertEqual(failure["error_type"], "ScanFailure")
        inventory = failure["inventory"]
        self.assertEqual(inventory["declared_layers"], 2)
        self.assertEqual(inventory["legacy_config_blobs"], 2)
        self.assertEqual(inventory["unreferenced_blobs"], 14)
        self.assertEqual(inventory["unexpected_tar_members"], 1)
        self.assertEqual(inventory["actual_layers"], 17)
        self.assertEqual(inventory["missing_from_inventory"], 0)
        self.assertEqual(len(inventory["unexpected_path_sha256"]), 10)
        expected_hashes = [hashlib.sha256(name.encode()).hexdigest() for name, _ in sorted(extras)[:10]]
        self.assertEqual(inventory["unexpected_path_sha256"], expected_hashes)
        for path, _ in extras:
            self.assertNotIn(path, json.dumps(inventory))
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
        self.assertNotIn("fixture-private-value", json.dumps(result))

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
