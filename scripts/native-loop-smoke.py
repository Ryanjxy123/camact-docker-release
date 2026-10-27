#!/usr/bin/env python3
"""Execute actual official CLI loops against a local synthetic protocol server.

No canonical Benchmark data, paid API or actual model is used. Each case uses
the production coordinator, gVisor, business Adapter, Simulator and evaluator.
"""
from __future__ import annotations
import argparse
import copy
import http.server
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from release import runner as deployment_import_roots
from native_protocol_fixture import anthropic, responses


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def successful_tool_texts(value):
    """Read only native returned tool output, excluding echoed tool arguments."""
    def text_content(content):
        if isinstance(content, str):
            return [content]
        if isinstance(content, list):
            return [text for item in content for text in text_content(item)]
        if isinstance(content, dict) and content.get('type') == 'text':
            return [content.get('text', '')]
        return []
    if isinstance(value, dict):
        if value.get('type') in ('tool_result', 'function_call_output'):
            return [] if value.get('is_error') else text_content(value.get('content', value.get('output')))
        return [text for item in value.values() for text in successful_tool_texts(item)]
    if isinstance(value, list):
        return [text for item in value for text in successful_tool_texts(item)]
    return []


def accounting_assertions(report, name, agent_calls, simulator_calls):
    agent = report['views']['all_attempts'][name]
    all_roles = report['all_roles_all_attempts']
    return {
        'agent_request_count': agent['http_attempt_count'] == agent_calls,
        'agent_capture_complete': agent['capture_complete'] is True,
        'agent_usage_complete': agent['usage_coverage'] == 1.0 and agent['unknown_or_unreliable_usage_requests'] == 0,
        'agent_tokens_exact': all(agent['exact_tokens'][key] == multiple * agent_calls
            for key, multiple in [('input_tokens', 10), ('output_tokens', 5), ('total_tokens', 15)]),
        'all_roles_request_count': all_roles['http_attempt_count'] == agent_calls + simulator_calls,
        'all_roles_tokens_exact': all_roles['exact_tokens']['total_tokens'] == 15 * (agent_calls + simulator_calls),
        'all_roles_capture_complete': all_roles['capture_complete'] is True,
        'formal_evaluation_linked': report['formal_results'][name]['scored_tasks'] == 1
            and report['formal_results'][name]['strict_success_count'] == 1,
    }


def worker(args):
    from release.config import build
    from camact_multi.fixture import create
    from camact_multi.cli import run_evaluated
    from camact_multi.offline import CLIENT
    from camact_multi.gvisor import trusted_secret_name
    import yaml
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    handle = create(output / 'synthetic-benchmark')
    path = handle.task_dir / 'task.yaml'
    task = yaml.safe_load(path.read_text())
    if args.mode != 'multi_turn':
        task['task_type'] = args.mode
        task['user_agent']['enabled'] = False
        if args.mode == 'users_history':
            task['context'] = {'kind': 'agent_history', 'source': 'messages', 'thread_id': 'fixture-history',
                'messages': [{'role': 'user', 'content': 'Use Fixture Recipient.'},
                             {'role': 'assistant', 'content': 'I will prepare a draft.'}]}
        path.write_text(yaml.safe_dump(task, sort_keys=False))
    config = build(handle.task_dir.parents[2])
    name = args.harness
    entry = config['harnesses'][name]
    if name == 'deepseek':
        entry['provider']['model_options'] = {'inputModalities': ['text', 'image'],
            'contextWindow': 1048576, 'maxTokens': 2048}
    if name == 'opencode':
        entry['provider']['model_options'] = {'modalities': {'input': ['text', 'image'], 'output': ['text']},
            'attachment': True, 'tool_call': True, 'limit': {'context': 1048576, 'output': 2048}}
    if name == 'openclaw':
        entry['provider']['model_options'] = {'input': ['text', 'image'], 'maxTokens': 2048,
            'contextWindow': 1048576, 'reasoning': False}
    protocol = entry['provider']['protocol']
    shell_name = {'claude': 'Bash', 'codex': 'exec_command', 'opencode': 'shell',
                  'deepseek': 'bash', 'openclaw': 'exec'}[name]
    image_name = {'claude': 'Read', 'codex': 'view_image', 'opencode': 'read',
                  'deepseek': 'read_image', 'openclaw': 'read'}[name]
    def shell(command):
        if name == 'codex':
            return shell_name, {'cmd': command, 'workdir': '/tmp', 'login': False, 'max_output_tokens': 3000}
        return shell_name, {'command': command, 'description': 'Execute synthetic offline deployment validation'}
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
    if args.mode == 'users_history':
        resource += """public=json.loads(pathlib.Path('/tmp/context/public_state.json').read_text())
thread,=[t for t in public['messaging']['threads'] if t['thread_id']=='fixture-history']
assert thread['context_kind']=='agent_history'
assert thread['messages'][0]['content']=='Use Fixture Recipient.'
print('CAMACT_HISTORY_OK')
"""
    actions = [shell('/usr/bin/python3 -c ' + shlex.quote(resource)),
               (image_name, {('file_path' if name in {'claude', 'deepseek'} else 'path'): '/tmp/album/images/1001.png'})]
    if args.mode == 'multi_turn':
        actions.append(shell('/usr/bin/python3 .camact/adapter.py ask-user --message ' + shlex.quote('Who is the fixture recipient?')))
    draft = {'to': 'Fixture Recipient', 'text': 'Offline fixture draft', 'attachments': ['1001.png']}
    actions.append(shell('/usr/bin/python3 .camact/adapter.py action message_create_draft --json ' + shlex.quote(json.dumps(draft))))
    negative = ('import json,pathlib,subprocess\n' + CLIENT[CLIENT.index('def call('):CLIENT.index("assert call('status')")] + CLIENT[CLIENT.index('# Each CLI invocation'):]).replace("'real_agent_loop_executed':False", "'native_tool_assertions_executed':True")
    actions.append(shell('/usr/bin/python3 -c ' + shlex.quote(negative)))

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            content_type = 'application/json'
            status = 200
            with self.server.lock:
                if self.path.rstrip('/').endswith('/files'):
                    role = 'files'
                    request = {'multipart_bytes': len(raw)}
                    body = json.dumps({'error': {'type': 'new_api_error', 'message': 'model name is required'}}).encode()
                    status = 400  # Original dsh performs its supported native inline fallback.
                else:
                    request = json.loads(raw)
                    role = 'simulator' if '/chat/completions' in self.path else 'agent'
                    tools = [t.get('name', t.get('function', {}).get('name')) for t in request.get('tools', [])]
                    tool = None
                    if role == 'simulator':
                        self.server.simulator_calls += 1
                        answer = ['The fixture recipient is Fixture Recipient.', 'Please keep the draft unsent.', '###STOP###'][min(self.server.simulator_calls - 1, 2)]
                        body = json.dumps({'id': 'fixture_simulator_' + str(self.server.simulator_calls), 'object': 'chat.completion', 'model': 'fixture-model',
                            'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': answer}, 'finish_reason': 'stop'}],
                            'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15}}).encode()
                    elif 'count' in self.path:
                        body = b'{"input_tokens":10}'
                    else:
                        self.server.agent_calls += 1
                        if tools and self.server.stage < len(actions):
                            tool = actions[self.server.stage]
                            if tool[0] not in tools:
                                raise RuntimeError(f'Required official tool absent: {tool[0]}')
                            self.server.stage += 1
                        body = responses(tool) if protocol == 'openai-responses' else anthropic(tool)
                        suffix = str(self.server.agent_calls)
                        for token in ('msg_fixture', 'toolu_fixture', 'resp_fixture', 'call_fixture', 'fc_fixture'):
                            body = body.replace(token.encode(), (token + '_' + suffix).encode())
                        content_type = 'text/event-stream'
                self.server.seen.append({'path': self.path, 'role': role, 'request': request,
                    'script_stage': self.server.stage, 'fixture_only': True})
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try: self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError): pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.lock, server.seen, server.stage = threading.RLock(), [], 0
    server.agent_calls = server.simulator_calls = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    for role in ('simulator', 'judge'):
        config[role].update(base_url=base, protocol='openai-chat')
    entry['provider']['base_url'] = base
    config['limits']['task_timeout_seconds'] = 180
    row = {'fixture_only': True, 'real_model_calls': 0, 'canonical_tasks_run': 0,
           'harness': name, 'mode': args.mode}
    try:
        row['execution'] = run_evaluated(config, name, handle.user_id, handle.task_name, output / 'run',
                                        save_artifacts=True, evaluation_python=sys.executable)
        evaluation = json.loads((output / 'run/result.json').read_text())['evaluations'][0]
        artifact_path = output / 'run/runs/standard_run_artifacts.jsonl'
        artifact = json.loads(artifact_path.read_text().splitlines()[0])
        row['evaluation'] = evaluation
        row['visual_status'] = artifact.get('visual_evidence', {}).get('status')
        row['script_completed'] = server.stage == len(actions)
        row['prompt_injected'] = all('<camact_public_task_rules>' in json.dumps(r['request'])
            for r in server.seen if r['role'] == 'agent' and 'count' not in r['path'])
        row['token_request_ledgers'] = [str(p.relative_to(output)) for p in (output / 'run').rglob('token_usage/**/requests.jsonl')]
        row['native_turns'] = len(list((output / 'run').rglob('turn.json')))
        returned_text = '\n'.join(text for request in server.seen if request['role'] == 'agent'
            for text in successful_tool_texts(request['request']))
        row['native_tool_assertions'] = {
            'readonly_resources_and_no_secrets': 'CAMACT_RESOURCE_OK' in returned_text,
            'rejected_invalid_business_actions': '"fixture_client": "passed"' in returned_text,
            'history_context': args.mode != 'users_history' or 'CAMACT_HISTORY_OK' in returned_text,
        }
        accounting = json.loads((output / 'run/token_usage/accounting_v3/summary.json').read_text())
        row['token_accounting_assertions'] = accounting_assertions(accounting, name, server.agent_calls, server.simulator_calls)
        lifecycles = [json.loads(path.read_text()) for path in (output / 'run').rglob('sandbox-launches/*/lifecycle.json')]
        row['sandbox_lifecycle_assertions'] = {
            'production_gvisor_executed': bool(lifecycles),
            'all_states_removed': bool(lifecycles) and all(item['cleanup_returncode'] == 0 and item['state_removed'] for item in lifecycles),
            'trusted_credentials_absent': bool(lifecycles) and not any(trusted_secret_name(key)
                for item in lifecycles for key in item['guest_environment_keys']),
        }
        expected_simulator = 3 if args.mode == 'multi_turn' else 0
        row['passed'] = (evaluation.get('strict_success') is True and not evaluation.get('infrastructure_failure')
            and row['script_completed'] and server.simulator_calls == expected_simulator and row['prompt_injected']
            and row['visual_status'] == 'visual_verified' and bool(row['token_request_ledgers'])
            and all(row['native_tool_assertions'].values()) and all(row['token_accounting_assertions'].values())
            and all(row['sandbox_lifecycle_assertions'].values()))
    except Exception as exc:
        row.update(passed=False, error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
    finally:
        server.shutdown(); server.server_close(); thread.join(5)
        row.update(agent_requests=server.agent_calls, simulator_requests=server.simulator_calls,
                   script_stage=server.stage, listener_closed=not thread.is_alive())
        write(output / 'fixture-upstream.json', server.seen)
        write(output / 'validation.json', row)
    print(json.dumps({k: v for k, v in row.items() if k not in {'execution', 'evaluation', 'traceback'}}), flush=True)
    return 0 if row['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--harness', choices=['claude', 'codex', 'opencode', 'deepseek', 'openclaw'], required=True)
    parser.add_argument('--mode', choices=['single_turn', 'multi_turn', 'users_history'], default='multi_turn')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        # The entire trusted fixture process, including scoring child, may only
        # use its loopback protocol server. The Agent has gVisor network=none.
        def loopback_only(event, values):
            if event == 'socket.connect' and isinstance(values[1], tuple):
                if not ipaddress.ip_address(values[1][0]).is_loopback:
                    raise RuntimeError('Offline fixture blocked non-loopback connection')
        sys.addaudithook(loopback_only)
        return worker(args)
    arguments = [sys.executable, '-B', str(Path(__file__).resolve()), '--worker',
                 '--harness', args.harness, '--mode', args.mode, '--output', str(args.output.resolve())]
    with tempfile.TemporaryDirectory(prefix='camact-native-relay-') as transport:
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'PYTHONPATH': os.pathsep.join([str(ROOT), str(ROOT / 'benchmark'), str(ROOT / 'deployment'),
                   str(ROOT / 'harness/camact_multi_harness_v1'), str(ROOT / 'harness/claude code'), str(ROOT / 'harness/baseline harness')]),
               'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'NO_PROXY': '127.0.0.1,localhost,::1',
               'CAMACT_DATA_ROOT': str(args.output.resolve().parent), 'CAMACT_RESULTS_ROOT': str(args.output.resolve().parent),
               'CAMACT_GVISOR_STATE_ROOT': str(args.output.resolve().parent / 'gvisor-state'),
               'CAMACT_TRANSPORT_TMPDIR': transport,
               **{role + '_' + field: value for role in ('AGENT', 'JUDGE', 'SIMULATOR')
                  for field, value in [('MODEL', 'fixture-model'), ('BASE_URL', 'http://127.0.0.1'), ('API_KEY', 'local-fixture-only')]}}
        openclaw_tmpfs = os.environ.get('CAMACT_OPENCLAW_TMPDIR')
        if args.harness == 'openclaw' and openclaw_tmpfs:
            env['CAMACT_OPENCLAW_TMPDIR'] = openclaw_tmpfs
        elif args.harness == 'openclaw':
            identifier = uuid.uuid4().hex
            steward = ROOT / 'harness/camact_multi_harness_v1/camact_multi/private_tmpfs.py'
            arguments = ['unshare', '--user', '--map-current-user', '--keep-caps', '--mount', '--fork',
                sys.executable, '-B', str(steward), '--outer-mount-namespace', os.readlink('/proc/self/ns/mnt'),
                '--parent', str(args.output.resolve().parent / ('openclaw-tmpfs-' + identifier)),
                '--recovery', str(args.output.resolve().parent / ('openclaw-recovery-' + identifier)), '--', *arguments]
        return subprocess.run(arguments, env=env).returncode


if __name__ == '__main__':
    raise SystemExit(main())
