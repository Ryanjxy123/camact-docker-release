"""Bounded Unix sockets across a network-isolated Claude sandbox.

The agent can reach only its Adapter and the existing model bridge, never the
host business-service ports. No business services or agent loop live here.
"""
from __future__ import annotations

import http.server
import json
import socketserver
import socket
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from .tool_profiles import check_registration


class UnixServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = getattr(socket, 'AF_UNIX', -1)
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        owner = self.server.owner
        status, content_type = 200, 'application/json'
        try:
            if self.server.kind == 'adapter':
                if self.path != '/command':
                    raise ValueError('route denied')
                document = owner.runtime.command(json.loads(body))
                data = json.dumps(document).encode()
                status = 200 if document.get('ok') else 400
            else:
                route = self.path.split('?', 1)[0]
                if route not in {'/v1/messages', '/v1/messages/count_tokens'}:
                    raise ValueError('provider route denied')
                document = json.loads(body)
                names = sorted(t['name'] for t in document.get('tools', []))
                # Utility requests with no tools are allowed. Every agent request
                # must have the complete exact inventory before provider access.
                if names:
                    if not owner.ready.wait(15) or not owner.registration.get('passed'):
                        raise ValueError('Claude startup registration not accepted')
                    passed = names == owner.expected
                    owner.registrations.append({'tools': names, 'passed': passed})
                    if not passed:
                        raise ValueError('actual provider tool inventory differs from profile')
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() in {'content-type', 'anthropic-version', 'anthropic-beta', 'x-api-key'}}
                policy = getattr(owner.runtime, 'prompt_policy', None)
                if policy is not None:
                    document, metadata = policy.apply(document, 'anthropic-messages')
                    owner.prompt_applications.append(metadata)
                    body = json.dumps(document, ensure_ascii=False).encode()
                if owner.limits is not None:
                    status, content_type, data = owner.limits.generate(owner.provider, self.path, document, headers)
                else:
                    req = urllib.request.Request(owner.provider + self.path, data=body, headers=headers, method='POST')
                    try:
                        response = urllib.request.urlopen(req, timeout=owner.timeout)
                    except urllib.error.HTTPError as exc:
                        response = exc
                    with response:
                        status = response.status
                        content_type = response.headers.get('Content-Type', 'application/json')
                        data = response.read()
        except Exception as exc:
            status = 403
            data = json.dumps({'error': {'type': 'permission_error', 'message': str(exc)}}).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class SandboxTransport:
    def __init__(self, runtime, provider: str, expected: list[str], timeout: float, limits=None):
        self.runtime, self.provider = runtime, provider.rstrip('/')
        self.expected, self.timeout = sorted(expected), timeout
        self.registrations = []
        self.prompt_applications = []
        self.registration = {}
        self.ready = threading.Event()
        self.servers = []
        self.limits = limits

    def accept_init(self, event):
        self.registration = check_registration(event, self.expected, self.runtime.tool_profile)
        self.ready.set()

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='camact-transport-')
        self.path = Path(self.temporary.name)
        for kind in ('adapter', 'provider'):
            server = UnixServer(str(self.path / f'{kind}.sock'), Handler)
            server.owner, server.kind = self, kind
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.servers.append((server, thread))
        return self

    def __exit__(self, *_args):
        log_dir = getattr(self.limits, 'log_dir', None)
        if log_dir is not None:
            from .core import write_json
            write_json(Path(log_dir) / 'system_prompt_policy.json', {
                'schema_version': 'camact.system_prompt_policy.v1',
                'source': 'canonical_baseline_composer', 'applications': self.prompt_applications})
        if self.limits:
            self.limits.cancelled.set()
        for server, thread in self.servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.temporary.cleanup()
