from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs

import pytest

from apex.local_lab import LocalLabWebAgent, assert_loopback_target


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        cookie = self.headers.get('Cookie', '')
        if self.path == '/':
            if 'session=ok' in cookie:
                body = '<title>Dashboard</title><a href="/orders?id=1">order</a><a href="/logout">Logout</a>'
            else:
                body = ('<title>Login</title><form method="post" action="/">'
                        '<input name="username"><input name="password" type="password">'
                        '<button name="submit">Login</button></form>')
        elif self.path.startswith('/orders?id=') and 'session=ok' in cookie:
            q = parse_qs(self.path.split('?', 1)[1])
            oid = q['id'][0]
            if oid == '2':
                body = 'Order 2 owner=other FLAG{local-idor-proof}'
            else:
                body = f'Order {oid} owner=self'
        else:
            self.send_response(404); self.end_headers(); return
        raw = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def do_POST(self):
        n = int(self.headers.get('Content-Length', '0'))
        data = parse_qs(self.rfile.read(n).decode())
        if data.get('username') == ['admin'] and data.get('password') == ['admin']:
            body = b'<title>Dashboard</title><a href="/orders?id=1">order</a>'
            self.send_response(200)
            self.send_header('Set-Cookie', 'session=ok; Path=/')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        body = b'<title>Login</title><form method="post"><input name="username"><input name="password" type="password"></form>'
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)


def serve():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    return server


def test_refuses_non_loopback():
    with pytest.raises(PermissionError):
        assert_loopback_target('https://example.com/')


def test_solves_local_default_credential_then_idor():
    server = serve()
    try:
        target = f'http://127.0.0.1:{server.server_port}/'
        result = LocalLabWebAgent(target, max_requests=60).solve()
        assert result.authenticated
        assert result.credential_username == 'admin'
        assert result.solved
        assert 'FLAG{' in result.flag
        assert result.id_mutations >= 1
        assert result.requests < 60
        assert result.evidence
    finally:
        server.shutdown(); server.server_close()
