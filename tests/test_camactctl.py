"""Exercise the real host wrapper against an executable Compose fixture."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from release import runner


class HostWrapper(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "config").mkdir()
        (self.root / ".env.example").write_text("CAMACT_DATA_DIR=./default\n")
        (self.root / "config/models.env.example").write_text("AGENT_MODEL=fixture\n")
        # The fixture returns Compose's resolved paths. The wrapper must use
        # these, including spaces, rather than interpret this .env itself.
        (self.root / ".env").write_text('CAMACT_DATA_DIR="${FIXTURE_ROOT}/data volume" # comment\n')
        self.data = self.root / "resolved/data volume"
        self.secrets = self.root / "resolved/secret volume"
        self.log = self.root / "docker-calls.jsonl"
        self.docker = self.root / "fake-docker"
        self.docker.write_text("#!" + os.sys.executable + "\n" + '''
import json, os, sys
arguments = sys.argv[1:]
record = {'argv': arguments}
if 'secret' in arguments:
    record['stdin_bytes'] = len(sys.stdin.buffer.read())
with open(os.environ['FAKE_DOCKER_LOG'], 'a') as stream:
    stream.write(json.dumps(record) + '\\n')
if arguments[0] == 'compose':
    command = arguments[5:]
    if command[:3] == ['config', '--format', 'json']:
        print(json.dumps({'services': {'storage-init': {'volumes': [
            {'type': 'bind', 'source': os.environ['FAKE_DATA_ROOT'], 'target': '/var/lib/camact'},
            {'type': 'bind', 'source': os.environ['FAKE_SECRETS_ROOT'], 'target': '/secrets'}]}}}))
    elif command == ['config', '--images']:
        print('fixture:local')
elif arguments[:2] == ['image', 'inspect']:
    print('sha256:fixture-image')
''')
        self.docker.chmod(0o700)
        loader = importlib.machinery.SourceFileLoader("camactctl_fixture", str(runner.PROJECT / "camactctl"))
        self.wrapper = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        loader.exec_module(self.wrapper)
        self.wrapper.ROOT = self.root
        self.environment = {"CAMACT_DOCKER": str(self.docker), "FAKE_DOCKER_LOG": str(self.log),
                            "FAKE_DATA_ROOT": str(self.data), "FAKE_SECRETS_ROOT": str(self.secrets)}

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, *arguments):
        with patch.dict(os.environ, self.environment), patch.object(os.sys, "argv", ["camactctl", *arguments]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.wrapper.main()
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_run_forwards_backend_arguments_literally_and_consumes_run_id_once(self):
        payload = "fixture-user; touch MUST_NOT_EXIST"
        calls = self.invoke("run", "--harness", "baseline,codex", "--users", payload,
                            "--parallel", "6", "--run-id", "chosen-run")
        command = calls[-1]["argv"][5:]
        position = command.index("runner")
        self.assertEqual(command[position + 1:], ["run", "--run-id", "chosen-run", "--harness", "baseline,codex",
                                                "--users", payload, "--parallel", "6"])
        self.assertIn("CAMACT_IMAGE_DIGEST=sha256:fixture-image", command)
        self.assertEqual(json.loads((self.root / ".state/last-run.json").read_text())["run_id"], "chosen-run")
        self.assertFalse((self.root / "MUST_NOT_EXIST").exists())
        self.assertTrue(self.data.is_dir())
        self.assertTrue(self.secrets.is_dir())
        self.assertFalse((self.root / "default").exists())
        self.assertIn("--no-env-resolution", calls[0]["argv"])

    def test_secret_retains_role_and_passes_value_only_on_stdin(self):
        value = "synthetic-secret-value"
        with patch.object(self.wrapper.getpass, "getpass", return_value=value):
            calls = self.invoke("secret", "agent")
        command = calls[-1]
        self.assertEqual(command["argv"][-3:], ["storage-init", "secret", "agent"])
        self.assertEqual(command["stdin_bytes"], len(value))
        self.assertNotIn(value, self.log.read_text())

    def test_resume_uses_saved_id_and_detach_is_host_only(self):
        (self.root / ".state").mkdir()
        (self.root / ".state/last-run.json").write_text(json.dumps({"run_id": "saved-run"}))
        calls = self.invoke("resume", "--detach", "--offline")
        command = calls[-1]["argv"][5:]
        self.assertEqual(command[:5], ["run", "--rm", "-d", "--name", "camact-saved-run"])
        self.assertEqual(command[command.index("runner") + 1:], ["resume", "--run-id", "saved-run", "--offline"])


if __name__ == "__main__":
    unittest.main()
