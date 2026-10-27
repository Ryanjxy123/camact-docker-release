"""Dependency-free MCP stdio transport for existing task-local CamAct tools.

Copied into the public workspace. No benchmark imports or model inference.
"""
import http.client
import json
import pathlib
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/transport/adapter.sock')


class GatewayTransportError(RuntimeError):
    """Retryable local transport failure, not a benchmark service decision."""


def _send(endpoint, body):
    if endpoint.get('transport') != 'unix':
        request = urllib.request.Request(endpoint['url'], data=body,
            headers={'Content-Type': 'application/json', 'X-CamAct-Token': endpoint['token']}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=endpoint.get('timeout', 120)) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as error:
            if error.code in {408, 429, 500, 502, 503, 504}:
                raise GatewayTransportError(f'Gateway HTTP {error.code}') from None
            text = error.read().decode('utf-8', errors='replace')
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {'ok': False, 'error': text or f'Gateway HTTP {error.code}'}
    conn = UnixConnection('localhost', timeout=endpoint.get('timeout', 120))
    try:
        conn.request('POST', '/command', body, {'Content-Type': 'application/json'})
        response = conn.getresponse()
        data = response.read()
        if response.status in {408, 429, 500, 502, 503, 504}:
            raise GatewayTransportError(f'Gateway HTTP {response.status}')
        return json.loads(data)
    finally:
        conn.close()


def command(payload):
    """One logical invocation gets one ID shared by its transport attempts.

    Calling this function again creates a distinct request even with identical
    business arguments. A caller explicitly forwarding an existing request ID
    retains that ID. MCP JSON-RPC IDs are intentionally not used here: they can
    be reused by a client after a prior call has completed.
    """
    endpoint = json.loads(pathlib.Path(__file__).with_name('endpoint.json').read_text())
    request = dict(payload)
    if 'request_id' not in request:
        request['request_id'] = uuid.uuid4().hex
    body = json.dumps(request, ensure_ascii=False, allow_nan=False).encode('utf-8')
    for attempt in range(3):
        try:
            return _send(endpoint, body)
        except (OSError, http.client.HTTPException, json.JSONDecodeError, GatewayTransportError):
            if attempt == 2:
                raise
            time.sleep(0.1 * (attempt + 1))


def tool_result(response):
    content = [{"type": "text", "text": json.dumps(
        {k: v for k, v in response.items() if k != 'content'}, ensure_ascii=False)}]
    for item in response.get('content', []):
        if item.get('type') == 'text':
            content.append(item)
        elif item.get('type') == 'image_url':
            url = item['image_url']['url']
            header, data = url.split(',', 1)
            if not header.startswith('data:image/') or not header.endswith(';base64'):
                raise ValueError('Only real inline image observations are supported')
            content.append({'type': 'image', 'mimeType': header[5:-7], 'data': data})
    return {'content': content, 'isError': not response.get('ok', False)}


def main():
    # Authoritative schemas come from the server; editing public files cannot
    # expand capabilities. The provider gate independently checks registration.
    for line in sys.stdin:
        request = json.loads(line)
        if 'id' not in request:
            continue
        method = request.get('method')
        try:
            if method == 'initialize':
                result = {'protocolVersion': request['params']['protocolVersion'],
                          'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'camact', 'version': '1.0.0'}}
            elif method == 'ping':
                result = {}
            elif method == 'tools/list':
                response = command({'op': 'domain_tools'})
                result = {'tools': response.get('tools', [])}
            elif method == 'tools/call':
                params = request['params']
                result = tool_result(command({'op': 'domain', 'tool': params['name'],
                                              'arguments': params.get('arguments', {})}))
            else:
                raise ValueError(f'Unsupported MCP method: {method}')
            reply = {'jsonrpc': '2.0', 'id': request['id'], 'result': result}
        except Exception as exc:
            reply = {'jsonrpc': '2.0', 'id': request['id'],
                     'error': {'code': -32603, 'message': str(exc)}}
        print(json.dumps(reply, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
