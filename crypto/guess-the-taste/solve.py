#!/usr/bin/env python3
"""Solve guess-the-taste: recover the NTRU plaintext via c mod p.

The server forgets to reduce the ciphertext mod q. Encryption is
    c = p * r * h + m
so c mod p == m mod p directly leaks the ternary message.
"""
import ast
import re
import socket
import ssl
import sys

# m -> char mapping observed on a leaked round.
MP = {0: "C", 1: "B", 2: "A"}


def connect(host: str, port: int):
    raw = socket.create_connection((host, port))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=host)


def recv_until(sock, marker: bytes, timeout: float = 20.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def main() -> None:
    host, port = sys.argv[1], int(sys.argv[2])
    sock = connect(host, port)

    banner = recv_until(sock, b"Give me the message:").decode(errors="replace")
    c = ast.literal_eval(re.search(r"c=\s*(\[[^\]]*\])", banner).group(1))

    guess = "".join(MP[v % 3] for v in c)
    print(f"sending {len(guess)}-char guess: {guess[:64]}...", file=sys.stderr)
    sock.sendall(guess.encode() + b"\n")

    # Drain whatever the server says next (flag on success, "nope" + truth on failure).
    sock.settimeout(15)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass

    text = out.decode(errors="replace").strip()
    print(text)
    for line in text.splitlines():
        if "GPNCTF" in line:
            print(line)
            return


if __name__ == "__main__":
    main()
