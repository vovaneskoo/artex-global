#!/usr/bin/env python3
"""Minimal OAST (out-of-band application security testing) receiver.

Accepts any HTTP request on any path and records it as a JSONL hit so agents
can poll /hits for out-of-band callbacks (SSRF, RCE beacons, XXE, blind SQLi).
/health is used by the tunnel orchestrator for end-to-end verification.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get('OAST_PORT', '18080'))
LOG = os.environ.get('OAST_LOG', '/data/hits.jsonl')
MAX_BODY = 4096
MAX_HITS_IN_MEMORY = 500
lock = threading.Lock()


def record(hit):
    line = json.dumps(hit, ensure_ascii=False)
    directory = os.path.dirname(LOG)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with lock:
        with open(LOG, 'a') as stream:
            stream.write(line + '\n')


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args): pass

    def _serve(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(min(length, MAX_BODY)).decode('utf-8', 'replace') if length else ''
        if self.path == '/health':
            payload, status, ctype = b'ok', 200, 'text/plain'
        elif self.path == '/hits':
            hits = []
            try:
                with lock, open(LOG) as stream:
                    hits = [json.loads(line) for line in stream.read().splitlines() if line]
            except (OSError, ValueError):
                pass
            payload, status, ctype = (json.dumps(hits[-MAX_HITS_IN_MEMORY:]).encode(), 200, 'application/json')
        else:
            payload, status, ctype = b'ok', 200, 'text/plain'
        try:
            record({'ts': round(time.time(), 3), 'client': self.client_address[0],
                    'method': self.command, 'path': self.path,
                    'headers': dict(self.headers), 'body': body[:MAX_BODY]})
        except OSError:
            pass
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _serve


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
