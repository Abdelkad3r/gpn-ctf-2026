# knitted-flag

**Category:** Misc
**Event:** GPN CTF 2026

> I got a new knitting machine to help me with the tablecloths for the
> restaurant but I accidentally dropped my flag into it. Can you help me
> unravel it?

## TL;DR

The handout `pattern.k` is a 22 k-line [Knitout-2](https://textiles-lab.github.io/knitout/knitout.html)
program: 978 carriage passes of 20 stitches each on a flat-bed machine with 5
yarn carriers. The carrier *colors* are a decoy — at every stitch they look
randomly chosen. The flag lives in the **front-bed / back-bed choice**: each
stitch's bed bit (front=1, back=0) is one pixel of a 978 × 20 bitmap. Rotate
90° CW, render at scale 1, and the flag font appears in 1-bit pixel art.

**Flag:** `GPNCTF{congRaTULa7ionS_Y0U_HAVE_UNderST00D_kNIt0U7_aNd_uNrAVeLed_7He_TaB13CLotHs}`

## Reading Knitout

Knitout's relevant ops:

- `knit ± fN c` — knit needle `N` on the **front** bed with carrier `c`, carriage moving in direction `±`
- `knit ± bN c` — same on the **back** bed
- `xfer fN bN` / `xfer bN fN` — move the loop between beds (no new stitch)
- `tuck` — initial cast-on
- `drop` — final cast-off

The handout uses needles 1..20, carriers 1..5, and every pass knits each
needle exactly once (some on front, some on back). On a 5-carrier multi-color
job the *color* per stitch normally encodes the design — but here those
colors are uniformly noisy. Instead, whether each stitch ends up on `f` or
`b` is structured.

## Detecting passes

Two adjacent `knit` ops belong to the same pass while the direction matches
and the needle index is monotonic. Any `xfer`/`tuck`/`drop` ends the current
pass. With this rule the program splits cleanly into **978 passes of ~20
stitches** — exactly the bitmap's height after rotation.

```python
passes = []
cur, prev_col = None, None
for op in ops:
    if op[0] == "knit":
        _, d, bed, col, car = op
        new = (cur is None or cur["dir"] != d
               or (d == "-" and col > prev_col)
               or (d == "+" and col < prev_col))
        if new:
            cur = {"dir": d, "knits": []}
            passes.append(cur)
        cur["knits"].append((bed, col, car))
        prev_col = col
    else:
        cur, prev_col = None, None
```

## Rendering the bitmap

Build a `978 × 20` 1-bit image: pixel `(pass, NEEDLES-1-col)` is 1 if the
knit was on the front bed, 0 if back. Rotating 90° CW lays the flag out as
horizontal text in a tiny serif pixel font.

```python
NEEDLES = 20
img = Image.new("1", (len(passes), NEEDLES), 1)
px = img.load()
for r, p in enumerate(passes):
    for bed, col, car in p["knits"]:
        px[r, NEEDLES - 1 - col] = 1 if bed == "f" else 0
img.rotate(90, expand=True).save("flag.png")
```

What I saw on first render at 4× scale:

```
GPNCTF<congRaTULa7ionS_Y0U_HAVE_UNderST00D_kNIt0U7_aNd_uNrAVeLed_7He_TaB13CLotHs>
```

Cleaning up the bracket glyphs (the angle quotes are `{` and `}`) gives the
flag verbatim.

## OCR gotcha: 'O' vs '0' (and the phantom space)

The font draws **uppercase O** and **digit 0** with the same diamond glyph.
Every "O-shaped" character in the flag turned out to be a digit `0` — the
challenge uses heavy leetspeak (`0=o`, `7=t`, `1=l`, `3=e`), so:

| Reading on the bitmap | Actually |
| :- | :- |
| `Y0U` | `Y0U` (zero, not O) — same word for "you" |
| `ST00D` | `ST00D` (two zeros) — leetspeak "stood" |
| `kNIt0U7` | `kNIt0U7` — leetspeak "knitout" |

Cross-checking the diamond glyph against the lowercase `o` (a clean round
oval at half height) is what disambiguates them: same width, different
shape, and the diamond appears *only* where a flag-style digit would.

There's also one 6-pixel gap in the bitmap — between `kNI` and `t0U7` — that
looks like a missing underscore. It's not: the encoder simply emitted six
all-front passes there as filler. "knit" + "out" really is one token in the
flag.

## Run

```
$ python3 solve.py pattern.k flag.png
saved 978x20 -> flag.png  (rotate 90 CW to read)
GPNCTF{congRaTULa7ionS_Y0U_HAVE_UNderST00D_kNIt0U7_aNd_uNrAVeLed_7He_TaB13CLotHs}
```

Decoded: *"congratulations you have understood knitout and unraveled the tablecloths"*.
