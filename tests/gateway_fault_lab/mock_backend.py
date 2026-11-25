"""Disposable upstream. No Django, database, real credentials or login logic."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.respond()

    def respond(self):
        print(f"FAULT_LAB_BACKEND {self.command} {self.path}", flush=True)
        body = b"FAULT LAB isolated upstream\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Fault-Lab-Upstream", "reached")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
