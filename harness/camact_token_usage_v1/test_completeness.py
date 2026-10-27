"""Reporting contracts for missing usage, snapshots and physical retries."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from .completeness import (request_bounds, summarize_bounds,
                           token_field_display, token_completeness_text, slot_usage_with_bounds)
from .unified_report import aggregate, deduplicate_roles


def request(identity, inp=10, out=2, *, partial=False, missing=False):
    values = dict(input_tokens=inp, output_tokens=out,
                  total_tokens=inp + out, cache_read_tokens=4, cache_write_tokens=0)
    return dict(run_id='run', harness_id='claude', user_id='user', task_id='task',
                attempt_id='attempt', model_request_id=identity, role='Agent',
                provider_response_id='reused-upstream-id', request_sha256='same-body',
                protocol='anthropic-messages', request_capture_complete=True,
                request_status='error' if missing else 'interrupted' if partial else 'succeeded',
                http_status=524 if missing else 200,
                usage_status='missing' if missing else 'partial' if partial else 'complete',
                comparable=not partial and not missing,
                coverage_status='usage_unobserved' if missing else 'partial_response' if partial else 'complete',
                field_status={f: 'missing' if missing else 'known' for f in values},
                standardized_tokens=dict.fromkeys(values) if partial or missing else values.copy(),
                **(dict.fromkeys(values) if missing else values))


class CompletenessTests(unittest.TestCase):
    def test_incomplete_slot_keeps_its_successful_requests(self):
        usages = [aggregate([request('a')]), aggregate([request('b', 7, 3), request('c', missing=True)])]
        stats = summarize_bounds(usages)
        self.assertEqual(stats['known_token_lower_bounds']['total_tokens'], 22)
        self.assertEqual(stats['token_completeness']['complete_slots'], 1)
        self.assertEqual(stats['token_completeness']['missing_usage_requests'], 1)
        self.assertEqual(token_field_display(stats, 'total_tokens'), '≥22')

    def test_message_start_zero_is_only_a_snapshot_bound(self):
        row = request('a', 646, 0, partial=True)
        row['issues'] = ['response_incomplete']
        usage = aggregate([row])
        self.assertIsNone(usage['exact_tokens']['output_tokens'])
        self.assertEqual(usage['known_token_lower_bounds']['input_tokens'], 646)
        self.assertEqual(usage['known_token_lower_bounds']['output_tokens'], 0)
        self.assertEqual(usage['token_bound_coverage']['output_tokens']['snapshot_requests'], 1)
        self.assertEqual(token_field_display(usage, 'output_tokens'), '≥0')

    def test_missing_counters_never_become_zero(self):
        usage = aggregate([request('a', missing=True)])
        stats = summarize_bounds([usage])
        self.assertIsNone(stats['known_token_lower_bounds']['total_tokens'])
        self.assertEqual(token_field_display(stats, 'total_tokens'), 'N/A')

    def test_explicit_zero_remains_exact(self):
        usage = aggregate([request('a', 0, 0)])
        self.assertEqual(token_field_display(usage, 'output_tokens'), '0')
        self.assertEqual(usage['known_token_lower_bounds']['cache_write_tokens'], 0)

    def test_retry_physical_ids_survive_identical_body_and_response_ids(self):
        a, b = request('a'), request('b')
        rows = deduplicate_roles([a, copy.deepcopy(a), b])
        self.assertEqual(len(rows), 2)
        self.assertEqual(aggregate(rows)['known_token_lower_bounds']['total_tokens'], 24)

    def test_cache_and_reasoning_are_not_added_twice(self):
        row = request('a', 100, 12)
        row.update(cache_read_tokens=80, reasoning_tokens=7)
        row['standardized_tokens'].update(cache_read_tokens=80, reasoning_tokens=7)
        self.assertEqual(request_bounds(row)['total_tokens'], 112)
        self.assertEqual(request_bounds(row)['input_tokens'], 100)

    def test_invalid_or_conflicting_partial_counters_are_rejected(self):
        for state in ('inconsistent', 'parse_error'):
            row = request('a', partial=True); row['usage_status'] = state
            self.assertTrue(all(v is None for v in request_bounds(row).values()))
        row = request('a', partial=True); row['total_tokens'] = 999
        self.assertTrue(all(v is None for v in request_bounds(row).values()))
        for value in (True, -1, 1.5):
            row = request('a', partial=True); row['input_tokens'] = value
            self.assertIsNone(request_bounds(row)['input_tokens'])

    def test_legacy_unverified_known_sum_is_not_promoted(self):
        stats = summarize_bounds([{'known_tokens': {'input_tokens': 999}, 'usage_statuses': {'inconsistent': 1}}])
        self.assertIsNone(stats['known_token_lower_bounds']['input_tokens'])

    def test_missing_capture_does_not_claim_complete_run(self):
        usage = aggregate([request('a')]); usage['capture_complete'] = False
        stats = summarize_bounds([usage])
        self.assertEqual(stats['token_completeness']['status'], 'partial')
        self.assertEqual(stats['token_completeness']['complete_slots'], 0)
        self.assertEqual(token_field_display({**usage, **stats}, 'input_tokens'), '≥10')

    def test_legacy_incomplete_slot_replays_only_selected_ids(self):
        parent = Path(os.environ.get('CAMACT_TEST_ARCHIVE', 'harness/_log/2026-10-27/camact-usage-recovery-v4-token-completeness'))/'validation'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory); path = root/'token_usage/accounting_v3/requests.jsonl'
            path.parent.mkdir(parents=True)
            selected = request('selected', 646, 0, partial=True)
            selected['run_id'] = str(root)
            path.write_text(json.dumps(request('other-attempt', 999, 999))+'\n'+json.dumps(selected)+'\n')
            usage = aggregate([selected]); usage.pop('known_token_lower_bounds'); usage.pop('token_bound_coverage')
            slot = dict(user_id='user', harness='claude', task='task', result=str(root/'result.json'), selected_agent_usage=usage)
            original = copy.deepcopy(slot)
            enriched = slot_usage_with_bounds(slot)
            self.assertEqual(enriched['known_token_lower_bounds']['input_tokens'], 646)
            self.assertEqual(slot, original)
            self.assertIsNone(enriched['exact_tokens']['output_tokens'])
            # Changing the selection cannot pull usage from a neighbouring
            # Attempt or reuse an unrelated native session counter.
            slot['selected_agent_usage'] = {**usage, 'physical_request_ids': ['absent']}
            self.assertIs(slot_usage_with_bounds(slot), slot['selected_agent_usage'])

    def test_bound_replay_is_idempotent_and_preserves_legacy_fields(self):
        rows = [request('a'), request('b', missing=True)]
        original = copy.deepcopy(rows)
        first = aggregate(rows)
        self.assertEqual(first, aggregate(rows))
        self.assertEqual(rows, original)
        self.assertIsNone(first['exact_tokens']['input_tokens'])
        stats = summarize_bounds([first])
        self.assertIn('缺完整 Usage 请求 1', token_completeness_text(stats))


if __name__ == '__main__':
    unittest.main()
