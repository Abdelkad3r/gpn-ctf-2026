# organized

**Category:** Misc
**Event:** GPN CTF 2026

> Wait, isn't this just a file of random data?
> Well, maybe you just don't appreciate the organization in your life...

## TL;DR

`data` is a 7,650,000-byte file that looks like noise — every bit position
is 1 with probability ≈ 0.287, and `file(1)` calls it `data`. The
"organization" is hidden in the **bit-density of windows**, not in the
bytes themselves:

1. Slice the file into **612 blocks of 12,500 bytes**.
2. Each block's mean popcount-per-byte falls into one of *three* sharp
   levels (~0.80 / ~1.60 / ~4.00), giving a 612-trit string.
3. The mid-level symbol is an idle marker. After a 24-trit preamble,
   the rest is 49 UART-style frames of 12 trits each — start bit, 8 LSB-
   first data bits, stop bit, framed by idle. Decode each frame to ASCII.

```
GPNCTF{tHaNK_YOU_tO_entropia_FoR_Or64niZ1N6_GPN!}
```

The flag thanks Entropia e.V. for *organizing* GPN — fitting payoff for a
challenge whose entire trick is recognising the carrier's organization.

## Recon

```
$ wc -c data
 7650000 data
$ file data
data: data
```

7,650,000 = 2⁴ · 3² · 5⁵ · 17 — no clean image dimensions. Byte-value
frequencies are *very* uneven though:

```
popcount=0  (byte 0x00):           1,573,858   ← way over uniform (29,883)
popcount=1  (8 single-bit bytes):  ~214,900 each
popcount=2  (28 two-bit bytes):    ~42,400 each
popcount=8  (byte 0xFF):           12,681       ← way under uniform
```

The 8 bit positions are each set with density ≈ 0.287, but the 0x00
byte is over-represented 3×. So the bits are *positively correlated* —
when one bit in a byte is 0, others tend to be 0 too. That's the
smoking gun: the file has slowly-varying bit-density across positions.

## Spotting the carrier

Renders of `data` as a 1-bpp bitmap at every plausible width are all
covered in horizontal stripes — the row-to-row popcount oscillates. So
look at popcount averaged in fixed windows:

```python
import numpy as np
d   = np.frombuffer(open("data","rb").read(), dtype=np.uint8)
pop = np.unpackbits(d).reshape(-1, 8).sum(1)
avg = pop.reshape(-1, 100).mean(1)               # 76,500 windows of 100 bytes
classes = (avg > 2).astype(int)
```

Run-length the binary class signal — every run is a multiple of **125
windows = 12,500 bytes**:

```
len  125: 188 runs
len  250:  45
len  375:  48
len  500:  25
len  625:  12
len  750:   1
len  875:   3
```

So the carrier has a fixed block size of **12,500 bytes / symbol**, and
`7,650,000 / 12,500 = 612` blocks total.

## Three levels, not two

Recomputing the popcount means per 12,500-byte block at full precision:

| level | mean popcount/byte | density | count |
| -: | -: | -: | -: |
| `0` | 0.795 ± 0.01 | 0.099 | 252 |
| `1` | 1.60  ± 0.02 | 0.200 |  98 |
| `2` | 4.00  ± 0.02 | 0.500 | 262 |

Three sharp peaks, nothing else — confirmed by a 200-bin histogram. The
file is amplitude-modulated in three steps. Map by rounding the mean to
the nearest multiple of 0.8 (`{1, 2, 5} → {0, 1, 2}`) and you get a
612-character ternary string.

## Reading the ternary stream

First 80 trits:

```
000222000222002020002200 102220002021100000202021100222002021102200002021
└───── preamble ───────┘ └─ frame ──┘└─ frame ──┘└─ frame ──┘└─ frame ──┘
```

Past the 24-trit preamble, slice in widths of 12. Every single 12-trit
slice satisfies:

- trit `0` and trit `11` are `1` (mid-level idle markers)
- trits `1..10` are only `0` or `2`

That's 49 frames after a header. The mid-level `1` appears exactly
**98** times in the whole file — 49 frames × 2 boundary markers — and
**nowhere** else. So the carrier is using its mid amplitude as an
inter-frame idle / break signal.

Within a frame, the natural reading is **UART**: start bit, 8 data bits
LSB-first, stop bit, framed by idle. Mapping `0 → bit 0`, `2 → bit 1`,
trits `2..9` are the byte (LSB-first):

```
frame "1 0 2 2 2 0 0 0 2 0 2 1"  →  data trits "2 2 2 0 0 0 2 0"
                                  →  bits LSB→MSB  1 1 1 0 0 0 1 0
                                  →  byte 0x47  =  'G'
```

That's the 'G' of `GPNCTF{`. Repeat for all 49 frames and the flag falls
out:

```
GPNCTF{tHaNK_YOU_tO_entropia_FoR_Or64niZ1N6_GPN!}
```

## Solver

```python
import numpy as np

d = np.frombuffer(open("data","rb").read(), dtype=np.uint8)
pop = np.unpackbits(d).reshape(-1, 8).sum(1)
per_block = pop.reshape(-1, 12_500).mean(1)
syms = "".join({1:"0", 2:"1", 5:"2"}[x]
               for x in np.round(per_block / 0.8).astype(int))

frames = syms[24:]                                   # drop 24-trit preamble
flag = "".join(
    chr(int("".join("1" if c=="2" else "0" for c in frames[i+2:i+10])[::-1], 2))
    for i in range(0, len(frames), 12)
)
print(flag)
```

```
$ python3 solve.py data
GPNCTF{tHaNK_YOU_tO_entropia_FoR_Or64niZ1N6_GPN!}
```

## What the preamble is

The 24-trit preamble (`000222000222002020002200`) sits before the first
frame and is not framed by `1` idle markers. As bits it spells the three
bytes `1c 72 8c` — not text. It's most likely a synchronisation
pre-roll: enough alternation between the low and high amplitudes for a
receiver to lock onto the symbol rate before the framed UART stream
starts. The decoder doesn't need it; you just skip 24 trits.
