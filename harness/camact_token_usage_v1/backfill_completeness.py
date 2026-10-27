"""Read-only selected-request replay and deterministic usage reporting overlay.

No execution, model calls, scoring or historical writes. A current Manifest's
physical request IDs bind every replay; an old audit index may locate mirrors
but cannot supply a different selection or token value.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import sys

from .completeness import FIELDS, PRIMARY, summarize_bounds
from .normalization import normalize_request, enrich_terminal_usage
from .unified_report import IDENTITY, aggregate, deduplicate_roles

ROOT = Path(__file__).resolve().parents[2]


def digest(content):
    return hashlib.sha256(content).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def key(slot):
    return '/'.join(slot[k] for k in ('user_id', 'harness', 'task'))


def harness(value):
    return 'baseline' if value == 'canonical-baseline' else value


@lru_cache(maxsize=None)
def ledger(path):
    p = Path(path)
    content = p.read_bytes()
    rows = [(n, json.loads(line)) for n, line in enumerate(content.splitlines(), 1) if line.strip()]
    return rows, {'path': str(p), 'sha256': digest(content), 'size': len(content)}


def direct_source(slot):
    binding = (slot.get('selected_agent_usage') or {}).get('usage_binding') or {}
    p = Path(binding.get('requests_path') or Path(slot['result']).parent / 'token_usage/accounting_v3/requests.jsonl')
    return str(p) if p.is_file() else None


def locate(slots, audit_index):
    with ThreadPoolExecutor(max_workers=12) as pool:
        direct = dict(zip((key(s) for s in slots), pool.map(direct_source, slots)))
    missing = [s for s in slots if not direct[key(s)]]
    mirrors = defaultdict(set)
    needed = {r for s in missing for r in s['selected_agent_usage']['physical_request_ids']}
    if needed:
        with Path(audit_index).open() as stream:
            for line in stream:
                row = json.loads(line)
                if row.get('model_request_id') in needed:
                    ref = row.get('audit_source') or {}
                    if ref.get('path'):
                        mirrors[row['model_request_id']].add(ref['path'])
        for slot in missing:
            ids = slot['selected_agent_usage']['physical_request_ids']
            sources = set.intersection(*(mirrors[r] for r in ids)) if ids else set()
            if not sources:
                raise ValueError(f'No exact selected request source for {key(slot)}')
            # All candidate mirrors are validated against this current
            # selection's IDs, identity and original totals during replay.
            direct[key(slot)] = sorted(sources)[0]
    return direct


def replay_slot(slot, path):
    old = slot['selected_agent_usage']
    entries, ref = ledger(path)
    expected = old['physical_request_ids']
    if len(expected) != len(set(expected)):
        raise ValueError(f'Duplicate selected request IDs: {key(slot)}')
    wanted = set(expected)
    selected = [(line, row) for line, row in entries
                if row.get('role') == 'Agent' and row.get('model_request_id') in wanted
                and row.get('user_id') == slot['user_id'] and row.get('task_id') == slot['task']
                and harness(row.get('harness_id')) == slot['harness']]
    if len(selected) != len(expected) or {r['model_request_id'] for _, r in selected} != wanted:
        raise ValueError(f'Selected physical request association mismatch: {key(slot)}')
    identities = {tuple(row.get(f) for f in IDENTITY) for _, row in selected}
    if len(identities) != 1 or any(v is None for v in next(iter(identities))):
        raise ValueError(f'Ambiguous selected Attempt identity: {key(slot)}')
    rows = [row for _, row in selected]
    usage = aggregate(deduplicate_roles(rows))
    compare = ('http_attempt_count', 'known_tokens', 'exact_tokens', 'exact_run_tokens',
               'reliable_usage_requests', 'unknown_or_unreliable_usage_requests', 'capture_complete')
    differences = {f: {'before': old.get(f), 'after': usage.get(f)} for f in compare if old.get(f) != usage.get(f)}
    if differences:
        raise ValueError(f'Historical usage mismatch {key(slot)}: {json.dumps(differences)}')
    binding = old.get('usage_binding') or {}
    if binding.get('requests_sha256') and binding['requests_sha256'] != ref['sha256']:
        raise ValueError('Bound request ledger changed')
    overlay = {'key': key(slot), 'result': slot['result'], 'identity': dict(zip(IDENTITY, next(iter(identities)))),
               'ledger': ref, 'usage': usage, **summarize_bounds([usage])}
    index = []
    for line, row in selected:
        index.append({**{f: row.get(f) for f in (*IDENTITY, 'model_request_id', 'role', 'protocol',
                       *FIELDS, 'standardized_tokens', 'field_status', 'usage_status', 'comparable',
                       'coverage_status', 'http_status', 'request_status', 'request_kind',
                       'request_sha256', 'response_sha256', 'provider_response_id', 'evidence')},
                      'selected_slot': key(slot), 'compact_source': {**ref, 'line': line}})
    return overlay, index, rows


def raw_replay(items):
    """Replay original append journals, selecting their last physical update."""
    journal_cache = {}
    results = []
    for slot_key, rows in items:
        restored, refs, updates = [], {}, Counter()
        for row in rows:
            evidence = row['evidence']
            path = evidence['path']
            if path not in journal_cache:
                entries, ref = ledger(path)
                latest, counts = {}, Counter()
                for line, raw in entries:
                    identity = (*tuple(raw.get(f) for f in IDENTITY), raw.get('model_request_id'))
                    latest[identity] = (line, raw)
                    counts[identity] += 1
                journal_cache[path] = latest, counts, ref
            latest, counts, ref = journal_cache[path]
            identity = (*tuple(row.get(f) for f in IDENTITY), row['model_request_id'])
            line, raw = latest[identity]
            source = enrich_terminal_usage(raw, ROOT)
            normalized = {**source, **normalize_request(source), 'role': 'Agent',
                          'request_capture_complete': row.get('request_capture_complete')}
            fields = (*FIELDS, 'standardized_tokens', 'usage_status', 'comparable')
            differences = [f for f in fields if normalized.get(f) != row.get(f)]
            if differences:
                raise ValueError(f'Raw journal replay mismatch {slot_key}/{row["model_request_id"]}: {differences}')
            restored.append(normalized)
            refs[path] = ref
            updates[row['model_request_id']] = counts[identity]
        usage = aggregate(restored)
        original = aggregate(rows)
        for f in ('known_token_lower_bounds', 'exact_tokens', 'http_attempt_count'):
            if usage[f] != original[f]:
                raise ValueError(f'Raw aggregate mismatch {slot_key}: {f}')
        results.append({'key': slot_key, 'physical_requests': len(rows), 'journal_updates': sum(updates.values()),
                        'journal_sources': list(refs.values()), 'usage': {f: usage[f] for f in
                        ('known_token_lower_bounds', 'exact_tokens', 'reliable_usage_requests',
                         'unknown_or_unreliable_usage_requests')}, 'all_fields_equal': True})
    return results


def run(manifest, archive, output, audit_index):
    content = manifest.read_bytes(); document = json.loads(content)
    output.mkdir(parents=True, exist_ok=True)
    slots = [s for s in document['tasks'] if s['scored']]
    sources = locate(slots, audit_index)
    unique_paths = sorted(set(sources.values()))
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(ledger, unique_paths))
    overlays, index, replay_examples = [], [], []
    physical = set(); by_harness = defaultdict(list); by_user = defaultdict(list)
    for slot in slots:
        overlay, requests, rows = replay_slot(slot, sources[key(slot)])
        overlays.append(overlay); index.extend(requests)
        by_harness[slot['harness']].append(overlay['usage'])
        by_user[(slot['user_id'], slot['harness'])].append(overlay['usage'])
        for row in rows:
            identity = (*tuple(row.get(f) for f in IDENTITY), row['model_request_id'])
            if identity in physical:
                raise ValueError('One physical Agent request selected by multiple slots')
            physical.add(identity)
        if (overlay['usage']['unknown_or_unreliable_usage_requests'] or
                slot['user_id'] == '10129939_N08' and slot['task'] == 'task_001'):
            replay_examples.append((key(slot), rows))
    summary = {method: summarize_bounds(usages) for method, usages in by_harness.items()}
    per_user = {'/'.join(k): summarize_bounds(v) for k, v in by_user.items()}
    payload = {'schema_version': 'camact.selected_usage_completeness_overlay.v1',
               'source_manifest': {'path': str(manifest), 'sha256': digest(content)},
               'selection_unchanged': True, 'selected_slots': len(slots),
               'selected_physical_requests': len(physical),
               'counts': document['counts'], 'final_scoring_contract': document.get('final_scoring_contract'),
               'harnesses': summary, 'users': per_user, 'slots': sorted(overlays, key=lambda x: x['key'])}
    (output/'usage-overlay.json').write_bytes(encode(payload))
    # Deterministic gzip: no wall clock or output directory in the payload.
    data = b''.join((json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode()
                    for row in sorted(index, key=lambda r: (r['selected_slot'], r['model_request_id'])))
    (output/'selected-request-index.jsonl.gz').write_bytes(gzip.compress(data, mtime=0))
    replay = raw_replay(replay_examples)
    (output/'raw-journal-replay.json').write_bytes(encode(replay))
    validation = {'source_manifest_sha256': digest(content), 'selected_slots': len(slots),
                  'physical_requests': len(physical), 'unique_compact_ledgers': len(unique_paths),
                  'legacy_usage_differences': 0, 'duplicate_selected_requests': 0,
                  'raw_replay_slots': len(replay), 'raw_replay_requests': sum(x['physical_requests'] for x in replay),
                  'raw_replay_differences': 0, 'agent_calls': 0, 'simulator_calls': 0, 'judge_calls': 0}
    (output/'validation.json').write_bytes(encode(validation))
    print(json.dumps(validation), flush=True)
    return payload


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--audit-index', type=Path, required=True)
    args = p.parse_args()
    archive = args.archive.resolve(); output = args.output.resolve()
    if not archive.is_relative_to(ROOT/'harness/_log') or not output.is_relative_to(archive):
        raise ValueError('Backfill outputs must stay in the explicit archive')
    run(args.manifest.resolve(), archive, output, args.audit_index.resolve())


if __name__ == '__main__':
    main()
