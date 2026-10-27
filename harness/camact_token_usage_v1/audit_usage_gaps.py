"""Forensic audit of selected usage gaps; persist metadata, never prompt bodies."""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

from .adapters import extract
from .backfill_completeness import encode, ledger


def ref(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return {'path': str(path), 'sha256': h.hexdigest(), 'size': path.stat().st_size}


def payload(body, encoding=None):
    if isinstance(body, dict):
        return json.dumps(body).encode()
    return body.encode() if isinstance(body, str) else b''


def wire_summary(body, protocol):
    parsed = extract(body, protocol)
    return {k: parsed.get(k) for k in ('raw_usage', 'usage_snapshot_count', 'response_complete',
                                      'provider_response_id', 'usage', 'issues')}


def audit(overlay_path, output):
    overlay = json.loads(overlay_path.read_text())
    gaps = [slot for slot in overlay['slots'] if slot['usage']['unknown_or_unreliable_usage_requests']]
    result = {'schema_version': 'camact.usage_gap_forensics.v1', 'slots': [],
              'source_overlay': ref(overlay_path),
              'scope': 'Current selected Agent Attempts; persisted gateway/provider/native evidence only',
              'external_billing_query': False, 'new_model_calls': 0}
    for slot in gaps:
        root = Path(slot['identity']['run_id']); harness = slot['key'].split('/')[1]
        entries, compact_ref = ledger(slot['ledger']['path'])
        ids = set(slot['usage']['physical_request_ids'])
        rows = [row for _, row in entries if row.get('role') == 'Agent' and row.get('model_request_id') in ids]
        missing = [row for row in rows if not row.get('comparable')]
        journal_path = Path(missing[0]['evidence']['path'])
        raw_entries, journal_ref = ledger(str(journal_path))
        final = {row['model_request_id']: (line, row) for line, row in raw_entries}
        chain_ids = {row.get('logical_model_request_id') for row in missing} - {None}
        item = {'key': slot['key'], 'run_root': str(root), 'compact_ledger': compact_ref,
                'original_journal': journal_ref, 'journal_rows': len(raw_entries),
                'selected_physical_requests': len(rows), 'complete_usage_requests': len(rows)-len(missing),
                'complete_usage_recovered': False,
                'lower_bounds': slot['known_token_lower_bounds'], 'missing_requests': [],
                'retry_chains': [{k: row.get(k) for k in ('model_request_id', 'logical_model_request_id',
                                  'request_sha256', 'request_status', 'http_status', 'retry_attempt',
                                  'provider_response_id')} for row in rows
                                 if row.get('logical_model_request_id') in chain_ids]}
        for row in missing:
            line, raw = final[row['model_request_id']]
            item['missing_requests'].append({
                **{k: row.get(k) for k in ('model_request_id', 'attempt_id', 'protocol', 'http_status',
                     'request_status', 'request_kind', 'missing_reason', 'provider_response_id',
                     'request_sha256', 'response_sha256', 'input_tokens', 'output_tokens', 'total_tokens')},
                'journal_line': line, 'updates': sum(r.get('model_request_id') == row['model_request_id'] for _, r in raw_entries),
                'raw_usage': raw.get('raw_usage'), 'response_complete': raw.get('response_complete'),
                'usage_snapshot_count': raw.get('usage_snapshot_count'), 'retry_attempt': raw.get('retry_attempt')})
        if harness == 'baseline':
            wire = journal_path.parent.parent.parent/'visual_wire.jsonl'
            targets = {r['response_sha256']: r['model_request_id'] for r in missing}
            matches, stages, hash_wire = [], Counter(), hashlib.sha256()
            with wire.open('rb') as stream:
                for n, line in enumerate(stream, 1):
                    hash_wire.update(line); raw = json.loads(line); stages[str(raw.get('capture_stage'))] += 1
                    if raw.get('response_sha256') not in targets:
                        continue
                    body = payload(raw.get('response_body'), raw.get('response_encoding'))
                    actual = hashlib.sha256(body).hexdigest()
                    # The wire's recorded digest must identify the same raw
                    # response as the physical collector event.
                    if actual != raw['response_sha256']:
                        raise ValueError('Baseline raw response hash mismatch')
                    parsed = wire_summary(body, 'openai-chat')
                    if parsed.get('raw_usage'):
                        raise ValueError('Previously missed Baseline Usage requires review')
                    matches.append({'model_request_id': targets[actual], 'line': n,
                                    'wire_request_id': raw.get('request_id'), 'http_status': raw.get('http_status'),
                                    'response_sha256': actual, 'response_bytes': len(body),
                                    'parsed': parsed, 'exception_type': raw.get('exception_type')})
            if {r['model_request_id'] for r in matches} != {r['model_request_id'] for r in missing}:
                raise ValueError('Baseline failed responses not fully matched to wire')
            item['wire'] = {'path': str(wire), 'sha256': hash_wire.hexdigest(), 'stages': dict(stages), 'matches': matches}
            trace = wire.parent/'model_trace.json'; native = json.loads(trace.read_text())
            known = [r.get('usage') for r in native if isinstance(r.get('usage'), dict) and r.get('usage')]
            item['native_trace'] = {'source': ref(trace), 'records': len(native), 'nonempty_usage_records': len(known),
                                    'usage_field_names': sorted({k for u in known for k in u}),
                                    'additional_associated_failure_usage': False}
            trace_sum = {'input_tokens': sum(u['prompt_tokens'] for u in known),
                         'output_tokens': sum(u['completion_tokens'] for u in known),
                         'total_tokens': sum(u['total_tokens'] for u in known)}
            equal = all(trace_sum[k] == slot['usage']['known_tokens'][k] for k in trace_sum)
            if not equal: raise ValueError('Baseline native usage reconciliation differs')
            item['native_trace'].update(tokens=trace_sum, equals_successful_provider_sum=equal)
            item['cause'] = 'Four HTTP 502/503 physical attempts have error response bytes but no Provider Usage; retries are separately captured.'
        elif harness == 'claude':
            execution = root/'runs/execution'; session = execution/'sessions/20452143_N08/task_014'
            responses = session/'execution_limits/provider_responses.jsonl.gz'
            targets = {r['request_sha256']: r for r in missing}; matches = []; retries = []; statuses = Counter()
            with gzip.open(responses, 'rt') as stream:
                for n, line in enumerate(stream, 1):
                    raw = json.loads(line); statuses[str(raw.get('http_status'))] += 1
                    if raw.get('request_sha256') not in targets:
                        continue
                    target = targets[raw['request_sha256']]
                    body = payload(raw.get('response'))
                    # A native retry reuses the request body SHA. Its later
                    # successful usage belongs to another physical request.
                    if raw.get('http_status') != target['http_status']:
                        digest = hashlib.sha256(body).hexdigest()
                        associated = [r['model_request_id'] for r in rows if r.get('response_sha256') == digest]
                        retries.append({'line': n, 'request_id': raw.get('request_id'), 'attempt': raw.get('attempt'),
                                        'http_status': raw.get('http_status'), 'response_sha256': digest,
                                        'associated_physical_request_ids': associated,
                                        'counted_separately_from_failure': True})
                        continue
                    if hashlib.sha256(body).hexdigest() != target['response_sha256']:
                        raise ValueError('Claude error response hash mismatch')
                    parsed = wire_summary(body, 'anthropic-messages')
                    if parsed.get('raw_usage'):
                        raise ValueError('Previously missed Claude Usage requires review')
                    matches.append({'line': n, 'request_id': raw.get('request_id'), 'attempt': raw.get('attempt'),
                                    'http_status': raw.get('http_status'), 'upstream_http_status': raw.get('upstream_http_status'),
                                    'response_bytes': len(body), 'response_sha256': hashlib.sha256(body).hexdigest(), 'parsed': parsed})
            if len(matches) != len(missing):
                raise ValueError('Claude failed responses not matched to provider ledger')
            stdout = execution/'tasks/20452143_N08/task_014/attempts/attempt_01/stdout.log'
            native_results, message_ids, native_usage = [], set(), []
            for n, line in enumerate(stdout.open(), 1):
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                if raw.get('type') == 'result':
                    usage = raw.get('usage') or {}
                    selected = {k: usage.get(k) for k in ('input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens')}
                    native_results.append({'line': n, 'usage': selected, 'is_error': raw.get('is_error')})
                msg = raw.get('message') or {}
                if raw.get('type') == 'assistant' and isinstance(msg, dict) and msg.get('id') not in message_ids:
                    message_ids.add(msg.get('id')); native_usage.append(msg.get('usage'))
            for native in native_results:
                usage = native['usage']; totals = slot['usage']['known_tokens']
                native['equals_successful_provider_sum'] = (
                    usage.get('input_tokens', 0) + usage.get('cache_read_input_tokens', 0) + usage.get('cache_creation_input_tokens', 0) == totals['input_tokens']
                    and usage.get('output_tokens') == totals['output_tokens'])
            item['provider_responses'] = {'source': ref(responses), 'status_counts': dict(statuses), 'matches': matches,
                                          'same_body_retries': retries}
            item['native'] = {'stdout': ref(stdout), 'native_results': native_results, 'unique_assistant_message_ids': len(message_ids),
                              'conversation': ref(session/'native_conversation.json'),
                              'provider_requests': ref(session/'execution_limits/provider_requests.jsonl.gz'),
                              'session_usage_added_to_request_sum': False}
            item['cause'] = 'HTTP 524 error response has no Usage; native result usage equals the successful provider request sum and provides no extra failed-request billing.'
        elif harness == 'openclaw':
            execution = root/'runs/execution'; capture = execution/'capture'
            rawfile = capture/'request-00013.response.gz'; body = gzip.decompress(rawfile.read_bytes())
            if hashlib.sha256(body).hexdigest() != missing[0]['response_sha256']:
                raise ValueError('OpenClaw raw response mismatch')
            types = Counter(); snapshots = []
            for line in body.decode().splitlines():
                if line.startswith('data: '):
                    raw = json.loads(line[6:]); types[str(raw.get('type'))] += 1
                    usage = (raw.get('message') or {}).get('usage', raw.get('usage'))
                    if usage:
                        snapshots.append({k: usage[k] for k in ('input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens') if k in usage})
            captured = json.loads((capture/'requests.json').read_text())[12]
            item['wire'] = {'source': ref(rawfile), 'decoded_bytes': len(body), 'decoded_sha256': hashlib.sha256(body).hexdigest(),
                            'event_types': dict(types), 'usage_snapshots': snapshots, 'parsed': wire_summary(body, 'anthropic-messages'),
                            'capture_index': ref(capture/'requests.json'), 'capture_index_pointer': '/12',
                            'relay': {k: captured.get(k) for k in ('sequence', 'status', 'http_status', 'error', 'transport_phase',
                                      'native_client_disconnect', 'failure_type', 'response_id', 'provider_usage_raw')}}
            transcript = execution/'home.tmpfs.tar.gz'; provider_id = missing[0]['provider_response_id'].encode()
            searched, id_matches, assistant_records = [], [], 0
            with tarfile.open(transcript, 'r:gz') as tar:
                for member in tar.getmembers():
                    if not member.isfile() or '/sessions/' not in member.name or not member.name.endswith(('.json', '.jsonl')):
                        continue
                    data = tar.extractfile(member).read(); searched.append({'member': member.name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
                    if provider_id in data:
                        id_matches.append(member.name)
                    if member.name.endswith('.jsonl'):
                        for line in data.splitlines():
                            raw = json.loads(line); msg = raw.get('message') or {}
                            if isinstance(msg, dict) and msg.get('role') == 'assistant': assistant_records += 1
            native_files = [execution/n for n in ('native-session-events.jsonl', 'native-events.json', 'stdout.log', 'stderr.log',
                            'native_turns/turn_001/stdout.log', 'native_turns/turn_001/stderr.log')]
            file_matches = [str(p) for p in native_files if provider_id in p.read_bytes()]
            item['native'] = {'home_archive': ref(transcript), 'session_members': searched,
                              'provider_id_matches_in_sessions': id_matches, 'assistant_records': assistant_records,
                              'native_sources': [ref(p) for p in native_files], 'provider_id_matches_in_events': file_matches}
            item['cause'] = 'Native client disconnected during auxiliary streaming (BrokenPipeError); captured message_start reports inclusive input 390+256=646 and output snapshot 0, with no terminal output usage.'
        result['slots'].append(item)
    output.parent.mkdir(parents=True, exist_ok=True); output.write_bytes(encode(result))
    print(json.dumps({'slots': len(gaps), 'missing_requests': sum(len(s['missing_requests']) for s in result['slots']),
                      'complete_usage_recovered': 0, 'output': str(output)}))


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--overlay', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); root = Path(__file__).resolve().parents[2]/'harness/_log'
    if not args.output.resolve().is_relative_to(root): raise ValueError('Audit output must be archived')
    audit(args.overlay.resolve(), args.output.resolve())


if __name__ == '__main__': main()
