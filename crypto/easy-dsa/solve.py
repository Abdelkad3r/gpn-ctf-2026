#!/usr/bin/env python3
"""Solver for `easy-dsa` — ECDSA nonce reuse via uuid3/MD5 collision."""
import os, socket, ssl, sys
from hashlib import sha256, md5
from secrets import randbelow

from Crypto.PublicKey import ECC

HOST = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "msg1.bin"), "rb") as f: M1 = f.read()
with open(os.path.join(HERE, "msg2.bin"), "rb") as f: M2 = f.read()
NS = b"kitchenexplosion"
assert M1 != M2 and md5(NS + M1).digest() == md5(NS + M2).digest()


def connect(host, port):
    sock = ssl.create_default_context().wrap_socket(
        socket.create_connection((host, port)), server_hostname=host)
    return sock.makefile("rwb")


def expect(io, needle: bytes) -> bytes:
    buf = b""
    while needle not in buf:
        ch = io.read(1)
        if not ch:
            sys.stderr.write(f"\n[EOF] last 200 bytes: {buf[-200:]!r}\n")
            sys.exit(1)
        buf += ch
    sys.stderr.write(buf.decode(errors="replace"))
    return buf


def send(io, line: str):
    io.write((line + "\n").encode()); io.flush()
    sys.stderr.write(f"\033[33m> {line[:60]}{'…' if len(line) > 60 else ''}\033[0m\n")


def grab(io, label: bytes) -> int:
    expect(io, label)
    val = b""
    while True:
        ch = io.read(1)
        if ch in (b"\n", b"\r"): break
        val += ch
    sys.stderr.write(val.decode() + "\n")
    return int(val, 16)


def grab_dec(io, label: bytes) -> int:
    expect(io, label)
    val = b""
    while True:
        ch = io.read(1)
        if ch in (b"\n", b"\r"): break
        val += ch
    sys.stderr.write(val.decode() + "\n")
    return int(val)


def main():
    io = connect(HOST, PORT)
    expect(io, b"> ")  # banner + first prompt

    # 1. Sign M1 and M2 (which collide under uuid3 → same k → same r).
    send(io, f"sign {M1.hex()}")
    s1_a = grab(io, b"s1: ")
    s2_a = grab(io, b"s2: ")
    expect(io, b"> ")

    send(io, f"sign {M2.hex()}")
    s1_b = grab(io, b"s1: ")
    s2_b = grab(io, b"s2: ")
    expect(io, b"> ")

    assert s1_a == s1_b, f"nonce-reuse FAIL: r={hex(s1_a)} vs {hex(s1_b)}"
    r = s1_a
    sa, sb = s2_a, s2_b
    sys.stderr.write(f"\n*** nonce reuse confirmed: r matches ***\n\n")

    # 2. Recover the private scalar.
    z1 = int.from_bytes(sha256(M1).digest())
    z2 = int.from_bytes(sha256(M2).digest())
    n = int(ECC._curves["p521"].order)
    k = (z1 - z2) * pow(sa - sb, -1, n) % n
    d = (sa * k - z1) * pow(r, -1, n) % n

    # 3. Cross-check against the public key.
    send(io, "get pkey")
    px = grab_dec(io, b"x: ")
    py = grab_dec(io, b"y: ")
    expect(io, b"> ")

    pk = ECC.construct(curve="p521", point_x=px, point_y=py)
    G = pk._curve.G
    Q = d * G
    if int(Q.x) != int(pk.pointQ.x):
        d = (-d) % n
        Q = d * G
    assert int(Q.x) == int(pk.pointQ.x), "private key recovery failed"
    sys.stderr.write("d matches the published public key ✓\n\n")

    # 4. Forge a signature on a fresh recipe.
    recipe = b"forged-recipe"
    assert recipe != M1 and recipe != M2
    kk = randbelow(n - 1) + 1
    P = kk * G
    rr = int(P.x) % n
    z = int.from_bytes(sha256(recipe).digest())
    ss = pow(kk, -1, n) * (z + rr * d) % n

    # 5. Hand it over.
    send(io, "flag please")
    expect(io, b"recipe (hex): ")
    send(io, recipe.hex())
    expect(io, b"s1 (hex): ")
    send(io, hex(rr))
    expect(io, b"s2 (hex): ")
    send(io, hex(ss))

    # 6. Read the verdict.
    rest = b""
    while True:
        ch = io.read(1)
        if not ch: break
        rest += ch
        if rest.endswith(b"\n"):
            sys.stderr.write(rest.decode(errors="replace"))
            rest = b""
            if b"flag" in rest.lower() or b"No flag" in rest:
                break


if __name__ == "__main__":
    main()
