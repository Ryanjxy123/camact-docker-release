"""Synthetic terminal/budget regressions derived from the verified formal tests; no historical outputs needed."""
from __future__ import annotations
import json
import copy
import gzip
import re
from pathlib import Path
from types import SimpleNamespace
import unittest
from release import runner as deployment_import_roots
from harness.camact_compatibility_v2.terminal import classify_native, terminal_signal, last_provider_attempt_failed

def _session():
    environment = SimpleNamespace(state={'session': {}}, simulator_stopped=False)
    return SimpleNamespace(environment=environment, infrastructure_error=None)

def _local_budget_facts(reason='agent_turn_limit_exceeded'):
    """A small complete relay history; never a saved benchmark result."""
    session = _session()
    session.environment.state['session'].update(status='agent_failure', termination_reason=reason, failure_type=reason, agent_turns=2, max_agent_turns=2, simulator_rounds=1, max_simulator_rounds=1)
    records = [{'sequence': n, 'route': '/v1/responses', 'status': 'succeeded', 'http_status': 200, 'upstream_dispatched': True, 'generation_completed': True, 'step_counted': True, 'agent_step': n} for n in (1, 2)]
    records.append({'sequence': 3, 'route': '/v1/responses', 'status': 'error', 'failure_type': 'agent_budget_limit', 'transport_phase': 'local', 'counts_agent_step': True, 'error': reason})
    capture = {'requests': records, 'stop_reason': reason, 'native_process': {'returncode': -9, 'timed_out': False, 'controlled_stop': True}}
    events = [{'type': 'error', 'message': 'exceeded retry limit, last status: 429 Too Many Requests'}]
    return (session, capture, events)

class LocalBudgetCausality(unittest.TestCase):

    def test_recoverable_files_probe_does_not_override_confirmed_local_budget(self):
        session, capture, events = _local_budget_facts()
        capture['requests'].insert(-1, {'route': '/v1/files', 'component': 'file_api', 'status': 'http_error', 'http_status': 400, 'upstream_dispatched': True, 'failure_type': 'file_api_error', 'native_recovery_allowed': True})
        self.assertEqual(classify_native(session, requested='infrastructure_failure', capture=capture, events=events), ('agent_failure', 'agent_turn_limit_exceeded'))

    def test_old_recovered_upstream_error_does_not_block_local_budget(self):
        session, capture, events = _local_budget_facts()
        capture['requests'].insert(0, {'route': '/v1/responses', 'upstream_dispatched': True, 'status': 'http_error', 'http_status': 503, 'failure_type': 'upstream_error'})
        self.assertEqual(classify_native(session, requested='infrastructure_failure', capture=capture, events=events), ('agent_failure', 'agent_turn_limit_exceeded'))

    def test_unrecovered_upstream_error_precedes_local_budget(self):
        session, capture, events = _local_budget_facts()
        capture['requests'].insert(-1, {'route': '/v1/responses', 'upstream_dispatched': True, 'status': 'http_error', 'http_status': 503, 'failure_type': 'upstream_error'})
        self.assertEqual(classify_native(session, requested='infrastructure_failure', capture=capture, events=events), ('infrastructure_failure', 'upstream_error'))

    def test_independent_native_failure_after_local_budget_remains_infrastructure(self):
        session, capture, events = _local_budget_facts()
        events.append({'type': 'error', 'error': {'type': 'io_failure', 'message': 'disk read failed'}})
        self.assertEqual(classify_native(session, requested='infrastructure_failure', error='disk read failed', capture=capture, events=events), ('infrastructure_failure', 'disk read failed'))

    def test_simulator_round_budget_preserves_its_reason(self):
        session, capture, events = _local_budget_facts('simulator_round_limit_exceeded')
        self.assertEqual(classify_native(session, requested='infrastructure_failure', capture=capture, events=events), ('agent_failure', 'simulator_round_limit_exceeded'))

    def test_stale_budget_request_does_not_explain_a_later_http_error(self):
        session, capture, events = _local_budget_facts()
        capture['requests'].append({'route': '/v1/responses', 'upstream_dispatched': True, 'status': 'http_error', 'http_status': 429, 'failure_type': 'upstream_error'})
        self.assertEqual(classify_native(session, requested='infrastructure_failure', capture=capture, events=events), ('infrastructure_failure', 'upstream_error'))

    def test_native_429_requires_matching_completed_generation_count(self):
        session, capture, events = _local_budget_facts()
        capture['requests'].pop(0)
        self.assertEqual(classify_native(session, requested='infrastructure_failure', capture=capture, events=events)[0], 'infrastructure_failure')

    def test_legacy_forwarding_evidence_does_not_override_explicit_local_flag(self):
        legacy = {'status': 'http_error', 'http_status': 503, 'upstream_request_sha256': 'abc'}
        self.assertTrue(last_provider_attempt_failed([legacy]))
        self.assertFalse(last_provider_attempt_failed([{**legacy, 'upstream_dispatched': False}]))
        self.assertFalse(last_provider_attempt_failed([{**legacy, 'transport_phase': 'local'}]))
        self.assertFalse(last_provider_attempt_failed([{**legacy, 'failure_type': 'agent_budget_limit'}]))

class DeepSeekTerminalClassifier(unittest.TestCase):

    def test_provider_failure_precedes_a_coincident_budget_signal(self):
        events = [{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'max-tokens'}}]
        session = _session()
        result = classify_native(session, requested='infrastructure_failure', error='exit=1', capture={'requests': [{'upstream_dispatched': True, 'upstream_request_sha256': 'abc', 'status': 'http_error', 'http_status': 503}], 'native_process': {'returncode': 1, 'timed_out': False}}, events=events, native_harness='deepseek')
        self.assertEqual(result[0], 'infrastructure_failure')

    def test_child_durable_terminal_does_not_override_the_cli_turn(self):
        events = [{'type': 'deepseek.native_session_event', 'native_event': {'type': 'turn/end', 'data': {'turn': 1, 'reason': {'kind': 'max-tokens'}}}}]
        events.insert(0, {'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'completed'}})
        self.assertEqual(terminal_signal(events), ('finished', None))

    def test_output_cap_does_not_mask_a_later_official_failure(self):
        events = [{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'max-tokens'}}, {'type': 'error', 'error': {'type': 'io_failure'}}]
        self.assertEqual(terminal_signal(events), ('failed', None))
        result = classify_native(_session(), requested='infrastructure_failure', error='exit=1', capture={'native_process': {'returncode': 1, 'timed_out': False}}, events=events, native_harness='deepseek')
        self.assertEqual(result[0], 'infrastructure_failure')

    def test_later_official_failure_overrides_stale_runtime_and_relay_budget(self):
        events = [{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'max-tokens'}}, {'type': 'error', 'error': {'type': 'io_failure'}}]
        for origin in ('runtime', 'relay'):
            for controlled in (False, True):
                with self.subTest(origin=origin, controlled=controlled):
                    session = _session()
                    capture = {'native_process': {'returncode': 1, 'timed_out': False, 'controlled_stop': controlled}}
                    if origin == 'runtime':
                        session.environment.state['session'].update(status='agent_failure', termination_reason='native_output_token_limit')
                        if controlled:
                            capture['stop_reason'] = 'native_output_token_limit'
                    else:
                        capture['stop_reason'] = 'agent_turn_limit_exceeded'
                    result = classify_native(session, requested='agent_failure', error='official io failure', capture=capture, events=events, native_harness='deepseek')
                    self.assertEqual(result, ('infrastructure_failure', 'official io failure'))

    def test_later_official_failure_overrides_stale_simulator_completion(self):
        session = _session()
        session.environment.simulator_stopped = True
        result = classify_native(session, requested='finished', capture={'stop_reason': 'simulator_stop', 'native_process': {'returncode': 0, 'timed_out': False, 'simulator_stop': True, 'controlled_stop': False}}, events=[{'type': 'turn.completed'}, {'type': 'error'}], native_harness='deepseek')
        self.assertEqual(result[0], 'infrastructure_failure')

    def test_confirmed_host_stop_can_explain_official_cancellation(self):
        for reason, expected in (('simulator_stop', 'finished'), ('agent_turn_limit_exceeded', 'agent_failure')):
            with self.subTest(reason=reason):
                session = _session()
                session.environment.simulator_stopped = reason == 'simulator_stop'
                result = classify_native(session, requested='infrastructure_failure', capture={'stop_reason': reason, 'native_process': {'returncode': -15, 'timed_out': False, 'controlled_stop': True}}, events=[{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'aborted'}}], native_harness='deepseek')
                self.assertEqual(result[0], expected)

    def test_opencode_native_error_at_controlled_simulator_stop_stays_infrastructure(self):
        from unittest.mock import patch
        session = _session()
        session.environment.simulator_stopped = True
        with patch('camact_multi.opencode_runtime.terminal_signal', return_value=('failed', 'opencode_native_execution_error')):
            result = classify_native(session, requested='finished', capture={'stop_reason': 'simulator_stop', 'native_process': {'returncode': -15, 'timed_out': False, 'simulator_stop': True, 'controlled_stop': True}, 'opencode_terminal': {'stdout_errors': [{'type': 'error'}]}}, events=[], native_harness='opencode')
        self.assertEqual(result, ('infrastructure_failure', 'opencode_native_execution_error'))

    def test_opencode_controlled_budget_preserves_incomplete_or_cancelled_projection(self):
        from unittest.mock import patch
        for signal, reason in ((None, 'opencode_missing_supported_terminal_projection'), ('failed', 'opencode_execution_interrupted')):
            with self.subTest(signal=signal):
                with patch('camact_multi.opencode_runtime.terminal_signal', return_value=(signal, reason)):
                    result = classify_native(_session(), requested='agent_failure', capture={'stop_reason': 'agent_turn_limit_exceeded', 'native_process': {'returncode': -15, 'timed_out': False, 'simulator_stop': True, 'controlled_stop': True}}, events=[], native_harness='opencode')
                self.assertEqual(result, ('agent_failure', 'agent_turn_limit_exceeded'))

    def test_claude_native_typed_output_limit_and_provider_failure(self):
        from types import SimpleNamespace

        def classify(events, stop=None):
            runtime = SimpleNamespace(infrastructure_error=None, environment=SimpleNamespace(simulator_stopped=False, state={'session': {}}))
            return classify_native(runtime, requested='infrastructure_failure', error='CLI exit 1', capture={'stop_reason': stop, 'native_process': {'returncode': 1, 'timed_out': False}}, events=events)
        events = [{'type': 'assistant', 'error': 'max_output_tokens'}, {'type': 'result', 'subtype': 'success', 'is_error': True, 'api_error_status': None}]
        self.assertEqual(classify(events), ('agent_failure', 'native_output_token_limit'))
        self.assertEqual(classify(events, 'provider_auth_error')[0], 'infrastructure_failure')
        self.assertEqual(classify(events + [{'type': 'error', 'error': {'type': 'api_error'}}])[0], 'infrastructure_failure')
        self.assertEqual(classify([events[0], {'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'error'}}, events[1]])[0], 'infrastructure_failure')
        self.assertEqual(classify([events[1]])[0], 'infrastructure_failure')
        self.assertEqual(classify([events[0], {**events[1], 'api_error_status': 500}])[0], 'infrastructure_failure')

    def test_max_tokens_is_not_inferred_from_exit_code(self):
        result = classify_native(_session(), requested='infrastructure_failure', error='exit=1', capture={'requests': [], 'native_process': {'returncode': 1, 'timed_out': False}}, events=[], native_harness='deepseek')
        self.assertEqual(result[0], 'infrastructure_failure')

    def test_timeout_and_signal_remain_infrastructure_faults(self):
        events = [{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'max-tokens'}}]
        for process in ({'returncode': -9, 'timed_out': False}, {'returncode': 1, 'timed_out': True}):
            with self.subTest(process=process):
                result = classify_native(_session(), requested='infrastructure_failure', error='watchdog', capture={'native_process': process}, events=events, native_harness='deepseek')
                self.assertEqual(result[0], 'infrastructure_failure')

    def test_capture_fault_remains_infrastructure_fault(self):
        result = classify_native(_session(), requested='infrastructure_failure', capture={'native_session_capture_errors': ['invalid JSON in durable Session'], 'native_process': {'returncode': 1, 'timed_out': False}}, events=[{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'max-tokens'}}], native_harness='deepseek')
        self.assertEqual(result, ('infrastructure_failure', 'native_session_capture_error'))

    def test_controlled_simulator_stop_still_accepts_its_signal_exit(self):
        session = _session()
        session.environment.simulator_stopped = True
        result = classify_native(session, requested='finished', capture={'stop_reason': 'simulator_stop', 'native_process': {'returncode': -15, 'timed_out': False, 'simulator_stop': True}}, events=[], native_harness='deepseek')
        self.assertEqual(result, ('finished', None))

    def test_controlled_relay_budget_kill_preserves_existing_agent_failure(self):
        session = _session()
        session.environment.state['session'].update(status='agent_failure', termination_reason='agent_turn_limit_exceeded')
        result = classify_native(session, requested='agent_failure', capture={'stop_reason': 'agent_turn_limit_exceeded', 'native_process': {'returncode': -9, 'timed_out': False, 'simulator_stop': True}}, events=[], native_harness='deepseek')
        self.assertEqual(result, ('agent_failure', 'agent_turn_limit_exceeded'))

    def test_explicit_controlled_stop_accepts_budget_kill_only_with_matching_reason(self):
        process = {'returncode': -9, 'timed_out': False, 'controlled_stop': True}
        for reason, expected in (('agent_turn_limit_exceeded', 'agent_failure'), (None, 'infrastructure_failure')):
            with self.subTest(reason=reason):
                result = classify_native(_session(), requested='agent_failure', capture={'stop_reason': reason, 'native_process': process}, events=[], native_harness='claude')
                self.assertEqual(result[0], expected)

    def test_explicit_uncontrolled_signal_overrides_stale_simulator_and_budget_flags(self):
        for reason in ('simulator_stop', 'agent_turn_limit_exceeded'):
            with self.subTest(reason=reason):
                session = _session()
                session.environment.simulator_stopped = True
                session.environment.state['session'].update(status='agent_failure', termination_reason='agent_turn_limit_exceeded')
                result = classify_native(session, requested='finished', capture={'stop_reason': reason, 'native_process': {'returncode': -9, 'timed_out': False, 'simulator_stop': True, 'controlled_stop': False}}, events=[{'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'completed'}}], native_harness='deepseek')
                self.assertEqual(result[0], 'infrastructure_failure')
if __name__ == '__main__':
    unittest.main(verbosity=2)
