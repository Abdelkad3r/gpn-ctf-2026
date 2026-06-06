#!/usr/bin/env python3
"""Solve organized: recover an LSB-first UART stream from a ternary
amplitude-modulated bit-density carrier.

The ~7.3 MB `data` file is 612 amplitude-modulated blocks of 12,500 bytes
each. Block popcount means cluster around 0.8 / 1.6 / 4.0 bits-per-byte,
which we read as ternary symbols 0 / 1 / 2.

The mid-level symbol `1` is the inter-frame idle marker, and only ever
appears as the two trits framing each 10-trit payload. After dropping a
24-trit preamble, 49 frames remain. Inside each frame, trits 2-9 are 8
data bits of one ASCII byte, **LSB-first**, with trit 1 / trit 10 as
start / stop bits and `0`/`2` mapping to bit 0/1. Reassemble → flag.
"""
import sys

import numpy as np


BLOCK = 12_500
PREAMBLE = 24
SYM = {1: "0", 2: "1", 5: "2"}  # round(popcount_mean / 0.8) → ternary symbol


def solve(path: str) -> str:
    d = np.frombuffer(open(path, "rb").read(), dtype=np.uint8)
    per_block = np.unpackbits(d).reshape(-1, 8).sum(1).reshape(-1, BLOCK).mean(1)
    syms = "".join(SYM[x] for x in np.round(per_block / 0.8).astype(int))

    frames = syms[PREAMBLE:]
    out = []
    for i in range(0, len(frames), 12):
        f = frames[i:i + 12]
        assert f[0] == "1" and f[11] == "1", f"bad frame at {i}: {f!r}"
        # trits 2..9 = 8 data bits LSB-first, 0→0, 2→1
        bits_lsb = "".join("1" if c == "2" else "0" for c in f[2:10])
        out.append(chr(int(bits_lsb[::-1], 2)))
    return "".join(out)


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "data"))
