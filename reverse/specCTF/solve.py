#!/usr/bin/env python3
"""
Solver for the `specCTF` reverse-engineering challenge.

The binary's Spectre cache-side-channel is real but mostly theatrical:
the actual constraint enforced by `specEnvTime` is

    ENC[i] == hash(input_qword_i)

where `hash` is an invertible splitmix-style finalizer. We extract ENC
from `.data`, invert `hash`, and dump the resulting little-endian
qwords as bytes.
"""

MASK64 = (1 << 64) - 1

# Constants encoded as `movabs ..., -<imm>` in the binary:
#   hash multiplier:    -0xbae5068a2ead353   == 0xf451af975d152cad
#   hash xor constant:  -0x3d315521e5cae3dd  == 0xc2ceaade1a351c23
MUL = 0xF451AF975D152CAD
XOR = 0xC2CEAADE1A351C23

# 56 bytes from .data @ 0x70c0 (`ENC`, 7 little-endian qwords;
# the trailing zero qword is unused — main only iterates strlen/8 times).
ENC_BYTES = bytes.fromhex(
    "e57571e9ec9075ee"
    "9a6e36f356ac93b9"
    "ed5e66134a845a4a"
    "a1ebae5b56a4bdcd"
    "415a6201729e5c52"
    "1f0887d83e7e05bb"
    "0000000000000000"
)


def hash64(x: int) -> int:
    """Forward hash, matching the binary's `_ZL5hashym`."""
    x &= MASK64
    x ^= x >> 33
    x = (x * MUL) & MASK64
    x ^= x >> 33
    x ^= XOR
    x ^= x >> 33
    return x


def inv_xs33(y: int) -> int:
    # x ^= x >> 33 is self-inverse because the shift exceeds half the
    # word width (33 > 64/2): the top 31 bits are untouched, and the
    # bottom 33 bits can be recovered by xor-ing the top bits back in.
    return (y ^ (y >> 33)) & MASK64


def inv_hash(y: int) -> int:
    mul_inv = pow(MUL, -1, 1 << 64)  # MUL is odd → invertible mod 2^64
    y = inv_xs33(y)
    y ^= XOR
    y = inv_xs33(y)
    y = (y * mul_inv) & MASK64
    y = inv_xs33(y)
    return y


def solve() -> bytes:
    flag = b""
    # Only the first 6 qwords are meaningful (ENC[6] == 0 is just padding).
    for i in range(6):
        qw = int.from_bytes(ENC_BYTES[i * 8 : (i + 1) * 8], "little")
        flag += inv_hash(qw).to_bytes(8, "little")
    return flag


if __name__ == "__main__":
    # Self-check: round-trip a few values through hash/inv_hash.
    for v in (0, 1, 0xDEADBEEFCAFEBABE, 0x4748505152535455):
        assert inv_hash(hash64(v)) == v

    flag = solve()
    print(f"Flag: {flag.decode()}")

    # Verify against the binary's ENC.
    for i in range(6):
        chunk = int.from_bytes(flag[i * 8 : (i + 1) * 8], "little")
        enc_i = int.from_bytes(ENC_BYTES[i * 8 : (i + 1) * 8], "little")
        assert hash64(chunk) == enc_i, f"chunk {i} mismatch"
    print("Verified: hash(flag chunks) matches ENC[0..5].")
