# guess-the-taste

**Category:** Crypto
**Event:** GPN CTF 2026

> You come into a restaurant but what is that, no menu? Your server tells you
> to just guess the taste...

## TL;DR

The server sets up a tiny NTRU instance with `p=3, q=512`, ternary plaintext
`m` (mapped `A=2, B=1, C=0`), and asks us to recover `m` from `(h, c)`. The
**ciphertext is never reduced mod q** — we see `c[i]` going up to ~`p·q`
instead of `< q`. Since the encryption is `c = p·r·h + m`, taking `c mod p`
gives `m` directly:

```
c[i] mod 3  ≡  (3 · r · h + m)[i] mod 3  ≡  m[i] mod 3
```

Map `0 → C, 1 → B, 2 → A`, send the 200-char string back, get the flag.

**Flag:** `GPNCTF{sOM7IMe5_4lL_YOu_NeED_1S_luCk}`

## Protocol

A single connection looks like:

```
got params N=100 p=3 d=33 q=512
h= [343, 511, 334, ...]      # 200 ints in [0, 511]
c= [566, 63, 580, ...]       # 200 ints in [0, ~1535]
Give me the message:_
```

We send back a 200-char string over `{A, B, C}`. On a wrong guess the server
replies `nope\n<actual message>` and disconnects; on a correct guess it sends
`You are lucky! here is your flag GPNCTF{...}`.

A few oddities to call out:

- The banner says `N=100` but the vectors are 200 long. Whatever the internal
  ring is, the message poly is length **200** with exactly `d=33` ones,
  `d=33` minus-ones, and `200 - 2d = 134` zeros (matches the `A=33, B=33,
  C=134` counts we see in a leaked ground-truth message).
- `q=512` would normally cap `c[i]` at `511`, but we see values like `1527`.
  That's the bug.

## The bug

Standard NTRU encryption is

```
c = (p · r · h + m) mod q
```

The `mod q` is what hides `r` (and therefore `m`) from anyone without the
private key — without it, `c mod p` is identically the message, because
`p · r · h ≡ 0 (mod p)`.

This server forgot the `mod q`. The ciphertext is just `p·r·h + m` as
integers in some larger range (looks like `mod p·q = 1536`, but it doesn't
matter — any modulus that's a multiple of `p` preserves the leak).

## Verifying the leak from a known message

The server helpfully prints the true `m` after a wrong guess. Capture one
round and check:

```python
mp = {0: 'C', 1: 'B', 2: 'A'}
recovered = ''.join(mp[v % 3] for v in c)
assert recovered == leaked_message    # ✓
```

Exact match for all 200 positions on the first try.

## Run

```
$ python3 solve.py steamed-truffle-crusted-with-shaved-noodles-dzkq.gpn24.ctf.kitctf.de 443
sending 200-char guess: ACBBCCCCCCCCBCCCACCCCACBCACCBACCBCABBCCBCCCCCBCCCCCCCACAAACCBCCCC...
You are lucky!
here is your flag GPNCTF{sOM7IMe5_4lL_YOu_NeED_1S_luCk}
```

## Patch

Reduce `c` mod `q` before sending it:

```python
c = [(3 * rh_i + m_i) % q for rh_i, m_i in zip(r_times_h, m)]
```

That puts `r · h` and `m` back behind the `mod q` veil and forces the
attacker to actually break NTRU.
