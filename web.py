#!/usr/bin/env python3
"""Small local web UI for the P2P transfer engine."""
import html
import io
import os
import tempfile
import threading
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from p2p import DEFAULT_PORT, receive_file, send_file

MAX_UPLOAD = 10 * 1024 * 1024 * 1024

PAGE = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>P2P File Share</title><style>*{box-sizing:border-box}body{margin:0;background:#080b12;color:#e8eef8;font:15px system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:880px;margin:50px auto;padding:20px}.hero{padding:30px 4px 22px}h1{font-size:42px;margin:0 0 8px;letter-spacing:-2px}p{color:#9ba8bb}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:700px){.grid{grid-template-columns:1fr}}.card{background:#111722;border:1px solid #263144;border-radius:18px;padding:24px;box-shadow:0 12px 35px #0005}h2{margin-top:0}.accent{color:#65e6d2}label{display:block;margin:14px 0 7px;color:#aebbd0}input,button{width:100%;padding:12px;border-radius:10px;border:1px solid #344157;background:#0a0f18;color:#fff}button{margin-top:18px;background:#65e6d2;color:#07100f;border:0;font-weight:800;cursor:pointer}.note{font-size:13px}.status{margin-top:20px;padding:15px;border-radius:12px;background:#0d131e}.ok{color:#72efad}.error{color:#ff7b8b}</style></head><body><main><section class="hero"><h1>P2P <span class="accent">File Share</span></h1><p>Direct peer-to-peer transfer • AES-256-GCM • SHA-256 verification</p></section><div class="grid"><section class="card"><h2>↗ Send</h2><form method="post" action="/send" enctype="multipart/form-data"><label>Receiver IP</label><input name="host" placeholder="192.168.1.25" required><label>Port</label><input name="port" value="5000" type="number" min="1" max="65535"><label>File</label><input name="file" type="file" required><label>Encryption password</label><input name="password" type="password" minlength="8" required><button>Send securely</button></form></section><section class="card"><h2>↙ Receive</h2><form method="post" action="/receive"><label>Listen port</label><input name="port" value="5000" type="number" min="1" max="65535"><label>Save folder</label><input name="output" value="received"><label>Encryption password</label><input name="password" type="password" minlength="8" required><button>Start receiving</button></form><p class="note">The web UI binds to localhost by default. Keep it there unless you deliberately want another device to control this computer.</p></section></div>{status}</main></body></html>"""


def render(status=""):
    return PAGE.format(status=f'<div class="status">{status}</div>' if status else "")


def field(data, name, default=""):
    return data.get(name, [default])[0]


def parse_multipart(body, content_type):
    if not content_type.lower().startswith("multipart/form-data"):
        raise ValueError("Expected multipart/form-data upload.")
    raw = b"Content-Type: " + content_type.encode("utf-8", "strict") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    message = BytesParser(policy=policy.default).parsebytes(raw)
    if not message.is_multipart():
        raise ValueError("Malformed multipart upload.")
    fields, files = {}, {}
    for part in message.iter_parts():
        disposition = part.get("Content-Disposition", "")
        if not disposition.lower().startswith("form-data"):
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename is not None:
            files[name] = (filename, io.BytesIO(payload))
        else:
            charset = part.get_content_charset() or "utf-8"
            fields[name] = payload.decode(charset, "replace")
    return fields, files


class Handler(BaseHTTPRequestHandler):
    def _reply(self, body, code=200):
        encoded = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path != "/":
            self._reply(render('<span class="error">✗ Not found.</span>'), 404)
            return
        self._reply(render())

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_UPLOAD:
                raise ValueError("Upload is limited to 10 GiB.")
            body = self.rfile.read(length)

            if self.path == "/receive":
                data = parse_qs(body.decode("utf-8", "strict"), keep_blank_values=True)
                port = int(field(data, "port", DEFAULT_PORT))
                output = Path(field(data, "output", "received"))
                password = field(data, "password")
                if len(password) < 8:
                    raise ValueError("Password must contain at least 8 characters.")
                threading.Thread(target=self._receive_worker, args=(port, output, password), daemon=True).start()
                self._reply(render(f'<span class="ok">● Receiver started on TCP {port}.</span><br>Keep this page open and send from the other peer.'))
                return

            if self.path == "/send":
                fields, files = parse_multipart(body, self.headers.get("Content-Type", ""))
                host = fields.get("host", "").strip()
                port = int(fields.get("port", str(DEFAULT_PORT)))
                password = fields.get("password", "")
                item = files.get("file")
                if not host:
                    raise ValueError("Receiver IP is required.")
                if not len(password) >= 8:
                    raise ValueError("Password must contain at least 8 characters.")
                if item is None:
                    raise ValueError("Choose a file first.")
                filename, stream = item
                safe_name = Path(filename).name
                if not safe_name or safe_name in {".", ".."}:
                    raise ValueError("Invalid filename.")
                fd, temp = tempfile.mkstemp(prefix="p2p_", suffix=Path(safe_name).suffix)
                os.close(fd)
                temp_path = Path(temp)
                try:
                    with temp_path.open("wb") as out:
                        while True:
                            chunk = stream.read(1024 * 1024)
                            if not chunk:
                                break
                            out.write(chunk)
                    digest = send_file(host, port, temp_path, password)
                finally:
                    temp_path.unlink(missing_ok=True)
                self._reply(render(f'<span class="ok">✓ Sent securely.</span><br>SHA-256: <code>{html.escape(digest)}</code>'))
                return

            self._reply(render('<span class="error">✗ Unknown action.</span>'), 404)
        except Exception as exc:
            self._reply(render(f'<span class="error">✗ {html.escape(str(exc))}</span>'), 400)

    @staticmethod
    def _receive_worker(port, output, password):
        try:
            receive_file("0.0.0.0", port, output, password)
        except Exception as exc:
            print(f"[web receiver] {exc}")

    def log_message(self, fmt, *args):
        print(f"[web] {self.address_string()} - {fmt % args}")


def run_web(host="127.0.0.1", port=8080):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Web UI: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run_web()
