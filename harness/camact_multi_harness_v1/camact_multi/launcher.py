"""Inside a network namespace: expose the host's bounded provider Unix socket."""
import http.client
import http.server
import socket
import subprocess
import sys
import threading

class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/transport/provider.sock")

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def relay(self):
        conn = Connection("localhost", timeout=660)
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            conn.request(self.command, self.path, body, dict(self.headers))
            response = conn.getresponse()
            self.send_response(response.status)
            for key in ("Content-Type", "Content-Encoding"):
                value = response.getheader(key)
                if value:
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        finally:
            conn.close()
        self.close_connection = True

    do_POST = do_GET = do_DELETE = relay

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 18780), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        raise SystemExit(subprocess.call(sys.argv[1:]))
    finally:
        server.shutdown()
