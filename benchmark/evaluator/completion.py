"""Deterministic public workflow checks reused by task graders."""
from __future__ import annotations

from typing import Any
import re


def _public_clarification_check(rule, submission):
    """Evaluate only public dialogue and its runtime sequence, never simulator state."""
    trace = submission.get('execution_trace')
    detail = {'required_tool': 'user_message', 'before_action': rule['before_action'],
              'matched_actions': []}
    def result(passed, reason):
        return {'constraint': rule['id'], 'passed': passed,
                'details': {**detail, 'reason': reason}}
    if not isinstance(trace, list) or not trace:
        return result(False, 'Missing public execution sequence')
    if any(not isinstance(e, dict) or type(e.get('sequence')) is not int for e in trace):
        return result(False, 'Invalid public execution sequence')
    sequences = [e['sequence'] for e in trace]
    if sequences != sorted(set(sequences)) or sequences[0] < 1:
        return result(False, 'Public execution sequence must be strictly increasing')
    # A truncated trace must not hide an earlier action or reorder tool calls.
    public_calls = [{'tool': e.get('name'), 'arguments': e.get('request', {}),
                     'status': e.get('status')} for e in trace if e.get('kind') == 'tool_call']
    expected_calls = [{'tool': c.get('tool'), 'arguments': c.get('arguments', {}),
                       'status': c.get('status', 'succeeded')}
                      for c in submission.get('tool_calls', [])]
    if public_calls != expected_calls:
        return result(False, 'Public execution trace does not match tool calls')
    questions, replies = rule.get('question_patterns'), rule.get('reply_patterns')
    if not questions or not replies:
        return result(False, 'Public question and reply topic patterns are required')
    denied = (r"\b(?:do not|don't|never)\s+(?:reveal|disclose|tell|share)\b|"
              r"\b(?:ground[ -]?truth|accepted[ -]?(?:images?|ids?)|evaluator|hidden annotation)\b|"
              r"\b(?:explain|define)\s+(?:the\s+)?(?:meaning|term|concept)\b|"
              r"\bwhat does\b.+\bmean\b")
    valid_turns = []
    try:
        for event in trace:
            if (event.get('kind'), event.get('name'), event.get('status')) != ('user_turn', 'user_message', 'succeeded'):
                continue
            question = str(event.get('request', {}).get('content', ''))
            reply = str(event.get('response', {}).get('content', ''))
            if (not re.search(denied, question, re.I)
                    and not re.search(r'could you clarify what information you need', reply, re.I)
                    and any(re.search(p, question, re.I) for p in questions)
                    and any(re.search(p, reply, re.I) for p in replies)):
                valid_turns.append(event['sequence'])
    except (re.error, TypeError):
        return result(False, 'Invalid public topic patterns')
    actions = [e for e in trace if e.get('kind') == 'tool_call'
               and e.get('name') == rule['before_action'] and e.get('status') == 'succeeded']
    detail['matched_actions'] = [any(s < e['sequence'] for s in valid_turns) for e in actions]
    return result(bool(actions) and all(detail['matched_actions']),
                  'A relevant public clarification and reply must precede every successful action')


def workflow_checks(constraints, submission):
    from .checks import _successful_tool_calls
    calls = _successful_tool_calls(submission)
    results = []
    for rule in constraints:
        if rule.get('type') == 'public_clarification_before_action':
            results.append(_public_clarification_check(rule, submission))
            continue
        after = [(i, call) for i, call in enumerate(calls) if call.get('tool') == rule['before_action']]
        matches = []
        for i, action in after:
            action_args = action.get('arguments', {})
            found = any(
                call.get('tool') == rule['required_tool']
                and all(call.get('arguments', {}).get(key) == action_args.get(key)
                        for key in rule.get('same_arguments', []))
                and (not rule.get('arguments_any_of') or any(
                    all(call.get('arguments', {}).get(key) == value for key, value in args.items())
                    for args in rule['arguments_any_of']))
                for call in calls[:i]
            )
            matches.append(found)
        results.append({'constraint': rule['id'], 'passed': bool(matches) and all(matches),
                        'details': {'required_tool': rule['required_tool'], 'before_action': rule['before_action'], 'matched_actions': matches}})
    return results


