"""Session, process-lifetime and provider-file evidence regression contracts.

Fixtures are synthetic and never reported as real model/benchmark results.
Set CAMACT_TEST_OUTPUT to an explicit archive directory before running.
"""
from __future__ import annotations
from release import runner as deployment_import_roots
import gzip
import hashlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from PIL import Image
from camact_multi.config import METHODS, NAMES, load, provider_ready
from camact_multi.coordinator import invoke
from camact_multi.deepseek_runtime import DeepSeekSessionCapture
from camact_multi.drivers import prepare, resume_command
from camact_multi.fixture import create
from camact_multi.session import RuntimeSession, export_artifact
from camact_multi.transport import Transport, allowed
from evaluation.camact_eval.visual_capture import _captured_file_upload, _payloads, load_requests

PROJECT = Path(__file__).resolve().parents[1]


def fixture_config():
    from release.config import build
    from unittest.mock import patch
    values = {role + '_' + field: value for role in ('AGENT','JUDGE','SIMULATOR')
        for field,value in [('MODEL','fixture-model'),('BASE_URL','http://127.0.0.1'),('API_KEY','fixture-key')]}
    with patch.dict(os.environ, values, clear=True):
        return build(Path('/synthetic-fixture'))

class NativeContracts(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.keys = patch.dict(os.environ, {name + '_API_KEY': 'fixture-key' for name in ('AGENT', 'JUDGE', 'SIMULATOR')})
        self.keys.start()
        self.addCleanup(self.keys.stop)
        parent = Path(os.environ.get('CAMACT_TEST_OUTPUT', str(PROJECT / '.validation/source-integration/native')))
        parent.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='native-contract-', dir=parent)
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_six_formal_groups_and_no_retired_adapter(self):
        config = fixture_config()
        self.assertEqual(tuple(config['harnesses']), METHODS)
        self.assertEqual(len(METHODS), 6)
        self.assertEqual(len(NAMES), 5)
        for name, entry in config['harnesses'].items():
            self.assertEqual(entry['provider']['provider'], 'configured')
            self.assertEqual(entry['provider']['model'], 'fixture-model')
            provider_ready(name, entry['provider'], require_key=False)
        config['harnesses']['retired-cli'] = {}
        path=self.root/'invalid.json';path.write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError,'exactly'):load(path)
        self.assertFalse(allowed('google-generative-language','POST','/v1beta/models/retired:generateContent'))

    def test_official_session_continuation_and_persistence_configuration(self):
        config=fixture_config()
        argv,env=prepare('deepseek',config['harnesses']['deepseek'],self.root/'home',config['limits'],prompt='original user request')
        import yaml
        rows=yaml.safe_load((self.root/'home/provider.patch.yml').read_text())
        persistence=next(r['config'] for r in rows if r['id']=='session-persistence-jsonl')
        self.assertEqual(persistence,{'root':'/home/agent/.dsh/sessions','compression':'none'})
        continued=resume_command('deepseek',argv,'session-specific','Simulator real reply')
        self.assertEqual(continued[-3:],['--session-id','session-specific','Simulator real reply'])
        again=resume_command('deepseek',continued,'session-specific','Next reply')
        self.assertEqual(again.count('--session-id'),1)
        self.assertNotIn('--last',again)
        self.assertEqual(again[-1],'Next reply')
        with self.assertRaises(ValueError):resume_command('deepseek',argv,None,'reply')

    def test_opencode_metadata_opt_out_keeps_explicit_model_and_native_continuation(self):
        config = fixture_config()
        entry = config['harnesses']['opencode']
        limits = dict(config['limits'])
        argv, env = prepare('opencode', entry, self.root / 'home', limits,
                            prompt='original user request')
        self.assertEqual(env['OPENCODE_DISABLE_MODELS_FETCH'], '1')
        self.assertEqual(env['OPENCODE_DISABLE_AUTOUPDATE'], '1')
        self.assertEqual(limits, config['limits'])
        model = entry['provider']['model']
        self.assertEqual(argv[argv.index('--model') + 1], 'camact/' + model)
        self.assertEqual(argv[-1], 'original user request')
        provider = json.loads((self.root / 'home/.config/opencode/opencode.json').read_text())
        self.assertEqual(provider['model'], 'camact/' + model)
        self.assertEqual(provider['providers']['camact']['models'],
                         {model: entry['provider'].get('model_options', {})})
        continued = resume_command('opencode', argv, 'session-specific', 'Simulator real reply')
        self.assertEqual(continued[:-3], argv[:-1])
        self.assertEqual(continued[-3:], ['--session', 'session-specific', 'Simulator real reply'])
        self.assertEqual(env['OPENCODE_DISABLE_MODELS_FETCH'], '1')

    def test_claude_uses_declared_protocol_for_non_anthropic_model(self):
        from claude_code_harness.core import ClaudeSettings
        from camact_multi.coordinator import claude_settings
        from unittest.mock import patch
        config=fixture_config()
        with patch.dict(os.environ,{'DEEPSEEK_API_KEY':'fixture-only-key'}):
            settings=claude_settings(config,config['harnesses']['claude'])
        self.assertFalse(settings.protocol_bridge_required)
        self.assertTrue(settings.provider_config_authoritative)
        self.assertTrue(settings.token_tracking)
        self.assertEqual(settings.agent_provider['protocol'],'anthropic-messages')
        self.assertTrue(ClaudeSettings(model='fixture-model').protocol_bridge_required)
        self.assertTrue(ClaudeSettings(model='fixture-model',agent_provider={'protocol':'openai-chat'}).protocol_bridge_required)

    def test_full_session_capture_keeps_long_results_and_excludes_torn_tail(self):
        with DeepSeekSessionCapture(self.root) as capture:
            path=capture.home/'.dsh/sessions/--tmp--/session-one/session.v4.jsonl';path.parent.mkdir(parents=True)
            first=json.dumps({'type':'tool/result','data':{'text':'x'*40000}})+'\n'
            path.write_text(first+'{"type":"turn/end"')
            capture.collect();capture.collect()
            self.assertEqual(len(capture.events),1)
            self.assertEqual(len(capture.events[0]['native_event']['data']['text']),40000)
            with path.open('a') as f:f.write('}\n')
            capture.collect();self.assertEqual(len(capture.events),2)
        report=json.loads((self.root/'native-session-capture.json').read_text())
        self.assertEqual(report['files'][0]['incomplete_tail_bytes'],0)
        self.assertEqual(report['errors'],[])

    def test_session_capture_refuses_symlink(self):
        capture=DeepSeekSessionCapture(self.root)
        capture.home.mkdir();path=capture.home/'.dsh/sessions/--tmp--/session-one';path.mkdir(parents=True)
        target=self.root/'unowned';target.write_text('{}\n');(path/'session.v4.jsonl').symlink_to(target)
        with self.assertRaisesRegex(RuntimeError,'symlink'):capture.collect()

    def test_dsh_output_budget_serializes_complete_agent_failure_episode(self):
        handle = create(self.root / 'fixture')
        runtime = RuntimeSession(handle, self.root / 'session', handle.task_dir.parents[2],
                                 {'max_agent_turns': 50}, lambda *args: '###STOP###')
        output = self.root / 'artifact'
        output.mkdir()
        try:
            artifact = export_artifact(runtime, name='deepseek',
                entry={'executable': 'offline-dsh-fixture', 'version': 'fixture',
                       'provider': {'model': 'fixture-model'}},
                run_id='offline-output-budget', final_text='',
                events=[{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'max-tokens'}}],
                run_dir=output, trajectory_class='infrastructure_failure', error='Official CLI exit=1',
                capture={'requests': [], 'native_process': {'returncode': 1, 'timed_out': False}},
                fixture=True)
            self.assertEqual(artifact.trajectory_class, 'agent_failure')
            self.assertEqual(artifact.final_state['session']['termination_reason'], 'native_output_token_limit')
            self.assertFalse(artifact.final_state['session']['strict_success'])
            self.assertEqual(artifact.diagnostics['episode_validation_error'], None)
            self.assertFalse(artifact.errors.get('infrastructure'))
        finally:
            runtime.close()

    def _running_child(self):
        path=self.root/'child.pid'
        code="import subprocess,time,pathlib; p=subprocess.Popen(['sleep','60']); pathlib.Path("+repr(str(path))+").write_text(str(p.pid)); time.sleep(60)"
        # This fixture tests process-group cleanup, not site-packages startup
        # on the shared filesystem. Keep dependency initialization out of its
        # deliberately short timeout while still spawning a real child.
        return [sys.executable,'-S','-c',code],path

    def _assert_dead(self,path):
        self.assertTrue(path.is_file())
        proc=Path('/proc')/path.read_text()/'stat'
        if proc.exists():self.assertEqual(proc.read_text().split()[2],'Z')

    def test_timeout_reaps_native_process_group(self):
        command,path=self._running_child()
        result=invoke(command,os.environ.copy(),.4)
        self.assertTrue(result['timed_out']);self.assertTrue(result['process_reaped']);self._assert_dead(path)
        self.assertFalse(result['controlled_stop'])

    def test_stop_reaps_native_process_group(self):
        command,path=self._running_child()
        result=invoke(command,os.environ.copy(),5,stop_condition=lambda:path.exists())
        self.assertTrue(result['simulator_stop']);self.assertFalse(result['timed_out']);self._assert_dead(path)
        self.assertTrue(result['controlled_stop'])

    def test_late_stop_condition_does_not_claim_an_unexpected_signal(self):
        path = self.root / 'self-killed.pid'
        code = ("import os,pathlib,signal; pathlib.Path(" + repr(str(path)) +
                ").write_text(str(os.getpid())); os.kill(os.getpid(), signal.SIGKILL)")
        def stopped_after_exit():
            if not path.exists():
                return False
            stat = Path('/proc') / path.read_text() / 'stat'
            return not stat.exists() or stat.read_text().split()[2] == 'Z'
        result = invoke([sys.executable, '-c', code], os.environ.copy(), 5,
                        stop_condition=stopped_after_exit)
        self.assertEqual(result['returncode'], -9)
        self.assertTrue(result['simulator_stop'])
        self.assertFalse(result['controlled_stop'])
        from types import SimpleNamespace
        from harness.camact_compatibility_v2.terminal import classify_native
        runtime = SimpleNamespace(infrastructure_error=None, environment=SimpleNamespace(
            simulator_stopped=True, state={'session': {'status': 'agent_failure',
                'termination_reason': 'agent_turn_limit_exceeded'}}))
        terminal = classify_native(runtime, requested='agent_failure',
            capture={'native_process': result, 'stop_reason': 'agent_turn_limit_exceeded'},
            events=[], native_harness='deepseek')
        self.assertEqual(terminal[0], 'infrastructure_failure')

    def test_coordinator_simulator_stop_keeps_classifier_signal_decision(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from camact_multi.coordinator import invoke_turns
        for controlled, expected in ((True, 'finished'), (False, 'infrastructure_failure')):
            with self.subTest(controlled=controlled):
                root = self.root / str(controlled)
                runtime = SimpleNamespace(infrastructure_error=None, environment=SimpleNamespace(
                    simulator_stopped=True, simulator=object(), agent_turns=1, max_agent_turns=50,
                    simulator_rounds=1, conversation_trace=[], state={'session': {}}))
                relay = SimpleNamespace(path=root, stop_reason=None,
                    summary=lambda: {'stop_reason': None, 'requests': []})
                invocation = {'returncode': -9, 'timed_out': False,
                    'simulator_stop': True, 'controlled_stop': controlled,
                    'stdout': '{"type":"turn.completed"}\n', 'stderr': '',
                    'started_at': 'fixture', 'ended_at': 'fixture'}
                with patch('camact_multi.coordinator.sandbox_command', return_value=['fixture']), \
                        patch('camact_multi.coordinator.invoke', return_value=invocation):
                    result = invoke_turns(runtime, 'codex', {}, [], {}, root, root, relay,
                        root / 'output', {'task_timeout_seconds': 5}, time.monotonic())
                self.assertEqual(result['trajectory_class'], expected)
                self.assertEqual(bool(runtime.infrastructure_error), not controlled)

    def test_interrupt_reaps_native_process_group(self):
        command,path=self._running_child()
        def interrupt():
            if path.exists():raise KeyboardInterrupt()
            return False
        with self.assertRaises(KeyboardInterrupt):invoke(command,os.environ.copy(),5,stop_condition=interrupt)
        self._assert_dead(path)

    def _file_capture(self):
        image=Image.new('RGB',(16,16),'green');out=io.BytesIO();image.save(out,format='PNG');data=out.getvalue()
        boundary='native-files-fixture'
        body=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="source.png"\r\nContent-Type: image/png\r\n\r\n').encode()+data+f'\r\n--{boundary}--\r\n'.encode()
        reply=json.dumps({'id':'file-api-native-fixture','size_bytes':len(data),'mime_type':'image/png'}).encode()
        return data,body,reply,'multipart/form-data; boundary='+boundary

    def test_files_relay_forwards_official_bytes_and_response(self):
        data,body,reply,content_type=self._file_capture();seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                seen.append((self.path,self.rfile.read(int(self.headers['Content-Length'])),self.headers.get('x-api-key')))
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(reply)));self.end_headers();self.wfile.write(reply)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        handle=create(self.root/'fixture');session=RuntimeSession(handle,self.root/'session',handle.task_dir.parents[2],{'max_agent_turns':50},lambda *args:'###STOP###')
        key='fixture-key-only';os.environ['CAMACT_TEST_KEY']=key
        class UnixConnection(http.client.HTTPConnection):
            def connect(client):
                client.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.sock.connect(str(relay.path/'provider.sock'))
        try:
            with Transport(session,{'protocol':'deepseek-messages','base_url':f'http://127.0.0.1:{server.server_port}/anthropic','api_key_env':'CAMACT_TEST_KEY'},self.root/'capture',{},harness_name='deepseek') as relay:
                client=UnixConnection('localhost');client.request('POST','/v1/files',body,{'Content-Type':content_type});response=client.getresponse()
                self.assertEqual(response.status,200);self.assertEqual(response.read(),reply);client.close()
                self.assertEqual(seen,[('/anthropic/v1/files',body,key)])
            records=json.loads((self.root/'capture/requests.json').read_text())
            self.assertEqual(records[0]['file_api_backend'],'official_provider')
            self.assertFalse(records[0]['counts_agent_step'])
            identity,upload=_captured_file_upload(records[0],self.root/'capture/request-00001')
            self.assertEqual(identity,'file-api-native-fixture');self.assertEqual(upload['data'],data)
        finally:session.close();server.shutdown();server.server_close();thread.join(5);os.environ.pop('CAMACT_TEST_KEY',None)

    def test_file_evidence_requires_verified_upload_before_model_input(self):
        data,body,reply,content_type=self._file_capture();capture=self.root/'capture';capture.mkdir()
        def write(sequence,request,response,**fields):
            prefix=capture/f'request-{sequence:05d}'
            for suffix,raw in [('request',request),('response',response)]:
                with gzip.open(str(prefix)+'.'+suffix+'.gz','wb') as f:f.write(raw)
            return {'sequence':sequence,'upstream_request_sha256':hashlib.sha256(request).hexdigest(),'response_sha256':hashlib.sha256(response).hexdigest(),'status':'succeeded','http_status':200,**fields}
        upload=write(1,body,reply,component='file_api',method='POST',route='/v1/files',request_content_type=content_type)
        document={'messages':[{'role':'user','content':[{'type':'image','source':{'type':'file','file_id':'file-api-native-fixture'}}]}]}
        model=write(2,json.dumps(document).encode(),json.dumps({'type':'message','id':'msg-fixture','model':'fixture-model','stop_reason':'end_turn','content':[]}).encode(),component='agent_with_tools')
        source=self.root/'source.png';source.write_bytes(data)
        (capture/'requests.json').write_text(json.dumps([upload,model]));requests,issues=load_requests(self.root);self.assertEqual(issues,[])
        _payloads(requests,{'source.png':source},issues)
        self.assertEqual(requests[0]['images'][0]['image_ids'],['source.png'])
        self.assertEqual(requests[0]['images'][0]['file_reference_provenance']['upload_sequence'],1)
        (capture/'requests.json').write_text(json.dumps([model,upload]));requests,issues=load_requests(self.root);_payloads(requests,{'source.png':source},issues)
        self.assertEqual(requests[0]['images'][0]['image_ids'],[])
        upload['upstream_request_sha256']='0'*64
        (capture/'requests.json').write_text(json.dumps([upload,model]));requests,issues=load_requests(self.root);self.assertTrue(issues);_payloads(requests,{'source.png':source},issues)
        self.assertEqual(requests[0]['images'][0]['image_ids'],[])

    def test_file_error_allows_native_inline_recovery(self):
        _, body, _, content_type = self._file_capture()
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                raw = self.rfile.read(int(self.headers['Content-Length']))
                seen.append((self.path, raw, self.headers.get('Authorization'), self.headers.get('x-api-key')))
                payload = (b'{"error":{"message":"Files unsupported"}}' if self.path.endswith('/files') else
                           b'{"type":"message","id":"native-inline-recovery","model":"fixture","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}')
                self.send_response(400 if self.path.endswith('/files') else 200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        handle = create(self.root / 'fixture')
        session = RuntimeSession(handle, self.root / 'session', handle.task_dir.parents[2], {'max_agent_turns': 50})
        os.environ['CAMACT_TEST_KEY'] = 'fixture-key-only'
        class UnixConnection(http.client.HTTPConnection):
            def connect(client):
                client.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.sock.connect(str(relay.path / 'provider.sock'))
        try:
            with Transport(session, {'protocol': 'deepseek-messages', 'base_url': f'http://127.0.0.1:{server.server_port}',
                    'api_key_env': 'CAMACT_TEST_KEY'}, self.root / 'capture', {}, harness_name='deepseek') as relay:
                client = UnixConnection('localhost')
                client.request('POST', '/v1/files', body, {'Content-Type': content_type})
                response = client.getresponse(); self.assertEqual(response.status, 400); response.read(); client.close()
                self.assertIsNone(relay.stop_reason)
                client = UnixConnection('localhost')
                client.request('POST', '/v1/messages', json.dumps({'model': 'fixture', 'messages': [{'role': 'user', 'content': 'OK'}], 'max_tokens': 32}), {'Content-Type': 'application/json'})
                response = client.getresponse(); self.assertEqual(response.status, 200); response.read(); client.close()
            self.assertEqual(seen[0][1], body)
            self.assertEqual(seen[0][2:], ('Bearer fixture-key-only', 'fixture-key-only'))
            self.assertIsNone(relay.stop_reason)
            records = json.loads((self.root / 'capture/requests.json').read_text())
            self.assertEqual(records[0]['failure_type'], 'file_api_error')
            self.assertEqual(records[1]['http_status'], 200)
            self.assertEqual(session.environment.agent_turns, 1)
        finally:
            session.close(); server.shutdown(); server.server_close(); thread.join(5)
            os.environ.pop('CAMACT_TEST_KEY', None)

if __name__=='__main__':unittest.main(verbosity=2)
