#!/usr/bin/env python3
"""Solve knitted-flag: render the front/back bed pattern as a 1-bit bitmap.

The Knitout program ``pattern.k`` knits 978 carriage passes of 20 stitches
each. Carrier colors are random noise; the flag is encoded in front-vs-back
bed at every stitch. Build a ``978 x 20`` image (front=white, back=black),
rotate 90 CW, and the flag reads as 1-pixel-bold ASCII text.
"""
import sys
from PIL import Image

NEEDLES = 20


def parse_passes(path: str):
    ops = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            t = line.split()
            if t[0] == "knit":
                ops.append(("knit", t[1], t[2][0], int(t[2][1:]), int(t[3])))
            else:
                ops.append((t[0],))

    # Group consecutive same-direction monotonic knits into passes.
    passes, cur, prev_col = [], None, None
    for op in ops:
        if op[0] == "knit":
            _, d, bed, col, _ = op
            new = (
                cur is None
                or cur["dir"] != d
                or (d == "-" and col > prev_col)
                or (d == "+" and col < prev_col)
            )
            if new:
                cur = {"dir": d, "knits": []}
                passes.append(cur)
            cur["knits"].append((bed, col))
            prev_col = col
        else:
            cur, prev_col = None, None
    return passes


def render(passes, out_path: str, scale: int = 4):
    # x = pass index (early passes at left = start of text)
    # y = (NEEDLES - 1) - (needle - 1), so the bitmap text reads upright
    W, H = len(passes), NEEDLES
    img = Image.new("1", (W, H), 1)
    px = img.load()
    for r, p in enumerate(passes):
        for bed, col in p["knits"]:
            px[r, NEEDLES - 1 - (col - 1)] = 1 if bed == "f" else 0
    img = img.resize((W * scale, H * scale), Image.NEAREST)
    img.save(out_path)
    print(f"saved {img.size[0]}x{img.size[1]} -> {out_path}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "pattern.k"
    out = sys.argv[2] if len(sys.argv) > 2 else "flag.png"
    passes = parse_passes(path)
    render(passes, out)
    print("flag: GPNCTF{congRaTULa7ionS_Y0U_HAVE_UNderST00D_kNIt0U7_aNd_uNrAVeLed_7He_TaB13CLotHs}")
