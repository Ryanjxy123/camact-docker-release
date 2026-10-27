"""Inside the sandbox: expose only the bounded model Unix relay to Claude."""
import http.client
import http.server
import os
import socket
import subprocess
import sys
import threading


class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/transport/provider.sock')


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        conn = Connection('localhost', timeout=3600)
        try:
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            conn.request('POST', self.path, body, dict(self.headers))
            response = conn.getresponse()
            data = response.read()
            self.send_response(response.status)
            self.send_header('Content-Type', response.getheader('Content-Type'))
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            conn.close()


if __name__ == '__main__':
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ, ANTHROPIC_BASE_URL=f'http://127.0.0.1:{server.server_port}',
               ANTHROPIC_API_KEY='camact-local-protocol-bridge')
    try:
        raise SystemExit(subprocess.call(sys.argv[1:], env=env))
    finally:
        server.shutdown()
