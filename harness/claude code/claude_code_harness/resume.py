"""Resume interrupted infrastructure attempts without resetting trial budgets."""
import json
from pathlib import Path

from .core import read_json, write_json, utc_now


def previous_attempts(run_root, handle):
    task_root = run_root / 'tasks' / handle.user_id / handle.task_name
    session_root = run_root / 'session_attempts' / handle.user_id / handle.task_name
    numbers = {int(p.name.split('_')[-1]) for root in (session_root, task_root / 'attempts')
               for p in root.glob('attempt_*') if p.is_dir()}
    if not numbers:
        return []
    if numbers != set(range(1, max(numbers) + 1)):
        raise ValueError('Non-contiguous previous attempt numbers')
    trace = read_json(run_root / 'traces' / handle.user_id / f'{handle.task_name}.json', {})
    records = {r['attempt']: r for r in trace.get('attempts', [])}
    return [records.get(n, {'attempt': n, 'status': 'infrastructure_failure',
        'error': 'Interrupted coordinator during infrastructure recovery',
        'preserved_session': str(session_root / f'attempt_{n:02d}'),
        'preserved_cli_attempt': str(task_root / 'attempts' / f'attempt_{n:02d}')})
        for n in sorted(numbers)]


def prepare_resume(run_root, benchmark, settings, handles, allow_retry_policy_change=False):
    config = read_json(run_root / 'config.json', {})
    public = settings.public_dict()
    retry_changes = {}
    for name, default in (('agent_request_attempts', config.get('request_attempts', 4)), ('agent_retry_delay', None)):
        before, after = config.get(name, default), public.get(name)
        if before != after:
            if not allow_retry_policy_change:
                raise ValueError(f'Resume configuration differs: {name}')
            retry_changes[name] = {'original': before, 'resumed': after}
    for name in ('tool_profile', 'model', 'base_url', 'timeout', 'request_attempts',
                 'retries', 'task_timeout', 'max_agent_turns', 'max_simulator_rounds',
                 'max_output_tokens', 'simulator_max_output_tokens', 'judge_timeout',
                 'judge_request_attempts', 'judge_max_output_tokens', 'parallel', 'claude_version'):
        if config.get(name) != public.get(name):
            raise ValueError(f'Resume configuration differs: {name}')
    if Path(config['benchmark']).resolve() != benchmark:
        raise ValueError('Resume benchmark differs')
    original = read_json(run_root / 'run_manifest.json', {})
    if {(h.user_id, h.task_name) for h in handles} != {(r['user_id'], r['task']) for r in original['tasks']}:
        raise ValueError('Resume task selection differs')
    rows = [json.loads(line) for line in (run_root / 'task_results.jsonl').read_text().splitlines() if line.strip()] if (run_root / 'task_results.jsonl').exists() else []
    keys = [(r['user_id'], r['task']) for r in rows]
    if len(keys) != len(set(keys)):
        raise ValueError('Duplicate terminal task result')
    pending = [h for h in handles if (h.user_id, h.task_name) not in keys]
    document = {'resumed_at': utc_now(), 'retained_results': rows,
        'authorized_agent_retry_policy_changes': retry_changes,
        'effective_config': public,
        'pending': [{'user_id': h.user_id, 'task': h.task_name,
                     'spent_attempts': len(previous_attempts(run_root, h))} for h in pending],
        'policy': 'Retain all terminal results; total infrastructure attempts remain unchanged'}
    index = len(list((run_root / 'logs').glob('resume_*.json'))) + 1
    write_json(run_root / 'logs' / f'resume_{index:02d}.json', document)
    return rows, pending


def defer_exhausted(run_root, handles, limit):
    ready, deferred = [], []
    for handle in handles:
        (deferred if len(previous_attempts(run_root, handle)) >= limit else ready).append(handle)
    return ready, deferred
