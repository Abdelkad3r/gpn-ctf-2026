#!/usr/bin/env python3
"""Solve com-petition: open every commitment to the move that beats the server."""
import socket, ssl, sys
from hashlib import sha256

HOST, PORT = sys.argv[1], int(sys.argv[2])

BEAT = {"rock": "paper", "paper": "scissors", "scissors": "rock"}
SLICES = {
    # message -> (r1, r2) such that r1 + message + r2 == b"rockpaperscissors"
    "rock":     (b"",          b"paperscissors"),
    "paper":    (b"rock",      b"scissors"),
    "scissors": (b"rockpaper", b""),
}


def connect():
    raw = socket.create_connection((HOST, PORT))
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=HOST)
    return sock.makefile("rwb")


def expect(io, needle: bytes) -> bytes:
    buf = b""
    while needle not in buf:
        ch = io.read(1)
        if not ch:
            sys.exit(f"EOF before {needle!r}: tail={buf[-200:]!r}")
        buf += ch
    return buf


def main() -> None:
    io = connect()
    expect(io, b"I want to play a game...\n")
    for round_idx in range(100):
        # Fresh preimage per round to dodge the already_seen replay check.
        preimage = str(round_idx).encode() + b"rockpaperscissors"
        com = sha256(preimage).digest()

        expect(io, b"Commitment (hex): ")
        io.write(com.hex().encode() + b"\n"); io.flush()

        # Server reveals.
        buf = expect(io, b"I choose ")
        # Read up to '.'.
        choice = b""
        while True:
            ch = io.read(1)
            if not ch or ch == b".":
                break
            choice += ch
        server = choice.decode()
        we_play = BEAT[server]

        expect(io, b"What did you choose? ")
        io.write(we_play.encode() + b"\n"); io.flush()

        r1, r2 = SLICES[we_play]
        # The numeric prefix sits in r1, before the move name.
        r1_full = str(round_idx).encode() + r1
        proof = f"{r1_full.hex()} {r2.hex()}\n".encode()
        expect(io, b"Proof (hex): ")
        io.write(proof); io.flush()

        print(f"Round {round_idx:>3}: server={server} we={we_play} ✓", file=sys.stderr)

    # Final line carries the flag.
    rest = b""
    while True:
        ch = io.read(1)
        if not ch: break
        rest += ch
    text = rest.decode(errors="replace")
    sys.stderr.write(text)
    for line in text.splitlines():
        if "GPNCTF" in line or "flag" in line.lower():
            print(line)


if __name__ == "__main__":
    main()
