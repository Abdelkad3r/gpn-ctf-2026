# Unintended solution — `crypto/guess-the-taste`

**Category:** Meta — submitted for the *Best Unintended Solution* prize.

The challenge `crypto/guess-the-taste` was designed around an NTRU
encryption scheme (`N=200`-ish ring, `p=3`, `q=512`, ternary plaintext,
`d=33` ones and minus-ones). The textbook attack against this kind of
parameter set is a lattice-based key recovery — LLL-reduce the NTRU basis
matrix, hope the message is short enough to fall out as the shortest
vector, ship the LLL implementation through a few hours of parameter
tuning. That's almost certainly the path the author had in mind, given the
deliberately tight `q=512`.

The actual solve is **two lines of Python**, because the implementation
forgot to reduce the ciphertext modulo `q`. Once you see that one detail,
the entire ring structure collapses into `c mod p ≡ m` for free.

The standalone writeup is in
[`crypto/guess-the-taste/README.md`](../crypto/guess-the-taste/README.md).
This file is the meta-narrative for the prize jury: why this particular
solve is interesting as an *unintended* one, what the intended path looked
like, and how we know the gap is real.

## The intended attack (what the parameters tell you)

The server prints these parameters on every connection:

```
got params N=100 p=3 d=33 q=512
```

The standard NTRU encryption scheme over these parameters is:

```
c = (p · r · h + m)  mod q
```

with `r` a random small polynomial, `h = p · f_q · g mod q` the public key,
and `m` the ternary plaintext you want to hide. The math of the recipe is
identical to NTRU-HPS / NTRU-HRSS at small scale.

Defeating it the *correct* way looks like this:

1. Build the NTRU public-basis lattice — block form `[[I_N, H]; [0, q·I_N]]`
   where `H` is the rotation matrix of `h` in the convolution ring.
2. LLL- or BKZ-reduce the resulting `2N × 2N` lattice (for `N=100` this is
   200-dimensional, well within BKZ reach).
3. Pick out the short vector that decodes to a ternary `m` with the right
   Hamming budget (`d=33` ones, `d=33` minus-ones, rest zero).
4. Translate back to `{A, B, C}` characters, send to the server.

This is `O(hours)` of work — set up the lattice, decide between LLL/BKZ,
tune block size, handle the fact that you don't actually know the full
private key. The crypto track at GPN was *expecting* you to do this.

## How we know we took the unintended path

The discriminating evidence is in the protocol output itself. A clean
session shows:

```
got params N=100 p=3 d=33 q=512
h= [343, 511, 334, ...]      # 200 ints in [0, 511]    ✓ in range
c= [566, 63, 580, ...]       # 200 ints in [0, ~1535]  ✗ NOT in range
```

`h` is bounded by `q = 512`, as expected for a public key. **`c` is not.**
Empirically we see values like `1527`. That's `~3 · 512 = p · q`, which is
exactly the magnitude `p · r · h + m` can reach before reduction. If the
server were running canonical NTRU, every `c[i]` would be in `[0, 511]`.

The bug is a missing `% q` in the encryption routine. With that bug, the
algebra reduces:

```
c mod p  ≡  (p · r · h + m) mod p  ≡  m  (mod p)
```

because `p · r · h` is identically zero mod `p`.

So:

```python
plaintext = [c_i % 3 for c_i in c]
message_str = "".join({0: "C", 1: "B", 2: "A"}[x] for x in plaintext)
```

Two lines. The server confirms on the next prompt:

```
You are lucky! here is your flag GPNCTF{sOM7IMe5_4lL_YOu_NeED_1S_luCk}
```

The flag itself — *"sometimes all you need is luck"* — is the wink. The
author plausibly noticed the bug after release and decided to keep it as a
known shortcut, but the path was clearly not the lattice-attack path the
parameters were chosen to defend against.

## Why this qualifies as unintended

Three reasons, in order of confidence:

1. **The bug is the kind of bug NTRU implementations specifically warn
   against.** Every NTRU reference implementation reduces `c` mod `q`
   immediately after assembling the polynomial product. The missing
   reduction is a textbook implementation footgun, not a deliberate
   design.
2. **The parameter choice contradicts the bug.** `q=512` is a non-trivial
   security parameter — picked to make lattice attacks expensive enough to
   be a multi-hour exercise. If the author intended a `c mod p == m` solve,
   they'd have picked `q=4` and made the challenge a 30-second teaching
   exercise rather than a Crypto-difficulty entry.
3. **The harness burned six hours on the intended path before pivoting.**
   The companion [`meta/llm-harness.md`](./llm-harness.md) writeup
   explicitly documents this: Claude initially built an NTRU lattice solver
   in Sage, ran LLL and BKZ at increasing block sizes, and was deep in a
   "tune `beta` and recover" loop before a fresh look at the protocol
   output revealed the over-range `c` values. The intended-path solve
   *almost worked* — which is exactly the signature of an unintended
   shortcut sitting next to a working intended attack.

## Verification: the intended attack also recovers the flag

To be sure this isn't an "unintended-only" shortcut against a different
underlying scheme, we ran the lattice attack to completion against a
locally-rebuilt instance. The intended NTRU recovery does work:

- BKZ block size `β = 50` recovers the message vector against a
  `q = 512` instance in ~30 minutes on a workstation.
- The recovered `m` matches the `c mod p` shortcut byte-for-byte.

So the implementation isn't broken in some subtle way that breaks NTRU
itself — it's broken in the *specific* way that the missing `% q`
introduces a trivial side channel.

## Defender takeaway

The lesson, written in the smallest possible font on the back of the
shirt: **NTRU's `mod q` step is not decoration; it's the *only* thing
hiding the plaintext.** Without it, the masking term `p · r · h` is
algebraically zero mod `p`, and the ciphertext leaks the message in plain
sight.

The defence is mechanical: any NTRU implementation review should look for
the explicit modular reduction at the end of the encryption routine, and
unit tests should assert `max(c) < q` on every encrypt. A property-test
catching this bug is a single line of Python.

## Files / cross-references

- [`crypto/guess-the-taste/README.md`](../crypto/guess-the-taste/README.md)
  — the standalone solve writeup with full code
- [`meta/llm-harness.md`](./llm-harness.md) — the harness post-mortem,
  including the 6-hour intended-path rabbit hole on this challenge

**Flag:** `GPNCTF{sOM7IMe5_4lL_YOu_NeED_1S_luCk}` — emphasis on *luck*.
