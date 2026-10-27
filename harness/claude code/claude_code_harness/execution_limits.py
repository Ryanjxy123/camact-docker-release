"""Baseline-equivalent request limits around the stock Claude Code loop.

This is a transport policy, not an agent. Claude still chooses every message,
tool and continuation. HTTP retries do not consume logical generation turns.
"""
from __future__ import annotations

import hashlib
import gzip
import http.client
import json
import time
import threading
import urllib.error
import urllib.request
from pathlib import Path

from .core import redact_text, utc_now
from .anthropic_completion import completion_error


def completed_generation(data, protocol):
    """Recognize a completed provider generation, never a bare HTTP success.

    Empty but completed turns count (as in Baseline); countTokens, uploads and
    explicit Responses compaction are excluded by the calling route.
    """
    if data[:2] == b'\x1f\x8b':
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            return False
    if protocol in {'anthropic-messages', 'deepseek-messages'}:
        return completion_error(data) is None
    documents = []
    try:
        value = json.loads(data)
        documents.extend(value if isinstance(value, list) else [value])
    except (ValueError, UnicodeDecodeError):
        try:
            frames = data.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n').split('\n\n')
            if frames[-1].strip():
                return False
            for frame in frames[:-1]:
                lines = [line[5:].lstrip() for line in frame.splitlines() if line.startswith('data:')]
                if not lines:
                    continue
                text = '\n'.join(lines)
                if text.strip() != '[DONE]':
                    documents.append(json.loads(text))
        except (ValueError, UnicodeDecodeError):
            return False
    if any(not isinstance(doc, dict) or doc.get('error') for doc in documents):
        return False
    for doc in documents:
        if not isinstance(doc, dict) or doc.get('error'):
            continue
        if protocol in {'anthropic-messages', 'deepseek-messages'}:
            if doc.get('type') == 'message_stop' or (
                    doc.get('type') == 'message' and doc.get('stop_reason')):
                return True
        elif protocol == 'openai-responses':
            if doc.get('type') in {'response.completed', 'response.incomplete'}:
                response = doc.get('response', {})
                if isinstance(response, dict) and isinstance(response.get('output'), list):
                    return True
            if isinstance(doc.get('output'), list) and doc.get('id') and doc.get('status') not in {'failed', 'in_progress', 'queued'}:
                return True
        elif protocol == 'openai-chat':
            choices = doc.get('choices')
            if isinstance(choices, list) and any(c.get('finish_reason') is not None for c in choices if isinstance(c, dict)):
                return True
        elif protocol == 'google-generative-language':
            candidates = doc.get('candidates')
            if isinstance(candidates, list) and any(c.get('finishReason') for c in candidates if isinstance(c, dict)):
                return True
    return False


def provider_failure(status, data=b''):
    """Separate recoverable infrastructure failures from malformed Agent input."""
    upstream = False
    try:
        detail = json.loads(data).get('error', {})
        upstream = isinstance(detail, dict) and (
            detail.get('code') == 'upstream_error' or detail.get('type') == 'upstream_error')
    except (ValueError, UnicodeDecodeError, AttributeError):
        pass
    if status in {408, 409, 429} or status >= 500 or upstream:
        return 'upstream_error', True
    if status in {401, 403}:
        return 'provider_auth_error', False
    if status in {404, 405}:
        return 'provider_configuration_error', False
    return 'agent_request_error', False


class GenerationBudget:
    """Reserve remaining slots without serializing native concurrent requests."""
    def __init__(self, runtime):
        self.runtime = runtime
        self.condition = threading.Condition(runtime._lock)
        self.pending = 0

    def reserve(self, record, deadline):
        from benchmark.services.runtime_environment import AgentTurnLimit
        env = self.runtime.environment
        with self.condition:
            while env.agent_turns + self.pending >= env.max_agent_turns:
                if env.agent_turns >= env.max_agent_turns:
                    env._budget_limit(AgentTurnLimit)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Task deadline expired awaiting a generation slot")
                self.condition.wait(min(remaining, .1))
            self.pending += 1
            record['step_reserved'] = True

    def commit(self, record):
        with self.condition:
            step = self.runtime.environment.begin_agent_turn()
            record.update(step_counted=True, agent_step=step)
            self.release(record)
            return step

    def release(self, record):
        with self.condition:
            if record.pop('step_reserved', False):
                self.pending -= 1
                self.condition.notify_all()


class ExecutionLimits:
    def __init__(self, runtime, settings, log_dir: Path):
        self.runtime, self.settings = runtime, settings
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.stop_reason = None
        self.generations = 0
        self.requests = []
        self._native_reads = set()
        self.cancelled = threading.Event()
        self._log_lock = threading.Lock()
        self.request_attempts = settings.agent_request_attempts or settings.request_attempts
        self.budget = GenerationBudget(runtime)
        self.deadline = time.monotonic() + settings.task_timeout
        self.http_requests = 0
        self.retry_count = 0
        self.upstream_errors = 0

    def _append(self, name, value):
        if name in {'provider_requests.jsonl', 'provider_responses.jsonl'}:
            # Wire correlation must exist before a successful Agent Step commits.
            # Keep the live record and budget counters untouched; retries share ID.
            value = {**value, 'agent_generation': value.get('generation'),
                     'generation': value['request_id'],
                     'generation_kind': 'wire_request_sequence'}
        line = redact_text(json.dumps(value, ensure_ascii=False), [self.settings.api_key])
        with self._log_lock:
            with gzip.open(self.log_dir / (name + '.gz'), 'at', encoding='utf-8', compresslevel=1) as output:
                output.write(line + '\n')

    def generate(self, provider, path, document, headers):
        reservation = {}
        try:
            return self._generate(provider, path, document, headers, reservation)
        finally:
            self.budget.release(reservation)

    def _generate(self, provider, path, document, headers, record):
        from benchmark.services.runtime_environment import AgentTurnLimit
        is_generation = path.split("?", 1)[0] == "/v1/messages"
        if self.stop_reason and self.stop_reason != 'simulator_stop':
            return 409, 'application/json', json.dumps({'error': {'type': self.stop_reason,
                'message': 'Task transport is terminal'}}).encode()
        if time.monotonic() >= self.deadline:
            self.stop_reason = 'task_timeout'
            return 408, 'application/json', b'{"error":{"type":"task_timeout"}}'
        if document.get('model') != self.settings.model:
            self.stop_reason = 'model_policy_violation'
            return 403, 'application/json', b'{"error":{"type":"model_policy_violation","message":"requested model differs from configured model"}}'
        try:
            # The environment persists several files through fixed .tmp paths.
            # Share the adapter lock with business actions and native Read audit.
            with self.runtime._lock:
                if self.runtime.environment.simulator_stopped:
                    if self.stop_reason not in {'provider_request_failed', 'model_policy_violation'}:
                        self.stop_reason = 'simulator_stop'
                    return 409, 'application/json', b'{"error":{"type":"simulator_stop","message":"the user Simulator has stopped this task"}}'
            if is_generation:
                self.budget.reserve(record, self.deadline)
        except AgentTurnLimit:
            self.stop_reason = 'agent_turn_limit_exceeded'
            return 429, 'application/json', b'{"error":{"type":"agent_budget_limit","message":"agent_turn_limit_exceeded"}}'
        except TimeoutError:
            self.stop_reason = 'task_timeout'
            return 408, 'application/json', b'{"error":{"type":"task_timeout"}}'
        # Enforce the wire value as well as the CLI environment setting. Stock
        # recovery/compaction requests must not silently raise the token budget.
        if is_generation:
            document['max_tokens'] = self.settings.max_output_tokens
        thinking = document.get('thinking', {})
        if is_generation and thinking.get('type') == 'enabled' and thinking.get('budget_tokens', 0) >= self.settings.max_output_tokens:
            thinking['budget_tokens'] = self.settings.max_output_tokens - 1
        body = json.dumps(document, ensure_ascii=False).encode('utf-8')
        fingerprint = hashlib.sha256(body).hexdigest()
        record.update({'generation': None, 'request_sha256': fingerprint,
                  'model': document.get('model'), 'max_tokens': document.get('max_tokens'),
                  'component': 'generation' if is_generation else 'count_tokens',
                  'step_counted': False, 'attempts': 0})
        with self.runtime._lock:
            record['request_id'] = len(self.requests) + 1
            self.requests.append(record)
        self._append('provider_requests.jsonl', {**record, 'request': document})
        status, content_type, data = 502, 'application/json', b''
        for attempt in range(1, self.request_attempts + 1):
            if self.cancelled.is_set() or self.stop_reason:
                break
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                self.stop_reason = 'task_timeout'
                break
            with self.runtime._lock:
                self.http_requests += 1
                self.retry_count += int(attempt > 1)
            record['attempts'] = attempt
            started_at, started = utc_now(), time.monotonic()
            error = None
            try:
                req = urllib.request.Request(provider + path, data=body, headers=headers, method='POST')
                try:
                    response = urllib.request.urlopen(req, timeout=min(self.settings.timeout + 5, remaining))
                except urllib.error.HTTPError as exc:
                    response = exc
                with response:
                    status = response.status
                    content_type = response.headers.get('Content-Type', 'application/json')
                    data = response.read()
            except (OSError, TimeoutError, urllib.error.URLError, http.client.HTTPException) as exc:
                status = 502
                error = f'{type(exc).__name__}: {exc}'
                data = json.dumps({'error': {'type': 'api_error', 'message': error}}).encode()
            upstream_status = status
            protocol_error = None
            if is_generation and 200 <= status < 300:
                protocol_error = completion_error(data)
                if protocol_error:
                    status, error = 502, f'invalid upstream Anthropic response: {protocol_error}'
            succeeded = 200 <= status < 300
            self._append('provider_responses.jsonl', {
                **record, 'attempt': attempt, 'started_at': started_at, 'ended_at': utc_now(),
                'duration_seconds': round(time.monotonic() - started, 6), 'http_status': status,
                'upstream_http_status': upstream_status,
                'error': error, 'response': data.decode('utf-8', errors='replace')})
            if protocol_error:
                # Entire response is buffered here: no content/tool call has
                # reached the CLI. Keep original bytes above and use only the
                # existing bounded pre-delivery retry policy.
                content_type = 'application/json'
                data = json.dumps({'error': {'type': 'upstream_error',
                                            'message': error}}).encode()
            if succeeded:
                if is_generation:
                    with self.runtime._lock:
                        record['generation'] = self.budget.commit(record)
                        self.generations += 1
                return status, content_type, data
            failure, retryable = provider_failure(status, data)
            record['failure_type'] = failure
            with self.runtime._lock:
                self.upstream_errors += int(failure == 'upstream_error')
            # This optional endpoint has a stock CLI fallback; retain its real
            # error without terminating the task before the CLI can handle it.
            if path.split('?', 1)[0] == '/v1/messages/count_tokens' and status == 404:
                return status, content_type, data
            if not retryable or attempt == self.request_attempts:
                break
            # The canonical mllm_adapter uses these exact delays for 4 attempts.
            delay = (self.settings.agent_retry_delay if self.settings.agent_retry_delay is not None else
                     (2, 4, 8, 16, 30, 60, 90)[min(attempt - 1, 6)])
            if self.cancelled.wait(min(delay, max(0, self.deadline - time.monotonic()))):
                break
        self.stop_reason = self.stop_reason or record.get('failure_type', 'upstream_error')
        return status, content_type, data

    def record_native_read(self, image_id):
        if image_id in self._native_reads:
            return
        self._native_reads.add(image_id)
        self.runtime.record_native_read(image_id)

    def diagnostics(self):
        return {'agent_generations': self.generations, 'max_agent_generations': self.settings.max_agent_turns,
                'http_requests': self.http_requests, 'retry_count': self.retry_count,
                'upstream_errors': self.upstream_errors,
                'max_output_tokens': self.settings.max_output_tokens, 'request_attempts': self.request_attempts,
                'agent_retry_delay': self.settings.agent_retry_delay,
                'stop_reason': self.stop_reason, 'wire_requests': self.requests}
