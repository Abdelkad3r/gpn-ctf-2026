# easy-dsa

**Category:** Crypto
**Event:** GPN CTF 2026

> Welcome to the Mongolian barbecue. Use `sign [hex recipe]` to get your recipe
> signed by us.

## TL;DR

The server signs arbitrary recipes with ECDSA on P-521. The "secure" nonce is
`int(sha256(uuid3(ns, sk_pem).bytes + uuid3(ns, message).bytes)) mod (n-1) + 1`.
`uuid3` is **MD5** under the hood, so two messages that collide under
`MD5("kitchenexplosion" ‖ ·)` produce the **same nonce**. Sign both, recover
the private key from the nonce-reuse equations, then forge a fresh-recipe
signature to claim the flag.

**Flag:** `GPNCTF{m4yb3_w3_sh0uld_us3_RFC_6979_n3xt_t1m3}`

## Where the security falls over

```python
secure_namespace = UUID(bytes=b"kitchenexplosion")

def secure_random(sk, message):
    key_id = uuid3(secure_namespace, sk.export_key(format="PEM")).bytes
    msg_id = uuid3(secure_namespace, message).bytes
    return sha256(key_id + msg_id).digest()[...] % (n - 1) + 1
```

`uuid3(ns, name)` is just `MD5(ns.bytes ‖ name.encode())`, lightly tagged for
RFC 4122. So `msg_id = MD5("kitchenexplosion" ‖ message)` (modulo a few fixed
bits). If we find `M1 ≠ M2` with
`MD5("kitchenexplosion" ‖ M1) = MD5("kitchenexplosion" ‖ M2)`, then `msg_id`
matches for both, the SHA-256 input matches, and the ECDSA nonce `k` is reused
across the two signatures.

## Building the collision

Use Marc Stevens' `fastcoll` for an identical-prefix MD5 collision, feeding
the namespace bytes as the prefix:

```
$ fastcoll -p prefix.bin -o m1.bin m2.bin       # prefix = "kitchenexplosion"
$ tail -c +17 m1.bin > msg1.bin                  # strip prefix
$ tail -c +17 m2.bin > msg2.bin
$ python -c "from hashlib import md5; \
    a=open('msg1.bin','rb').read(); b=open('msg2.bin','rb').read(); \
    print(md5(b'kitchenexplosion'+a).hexdigest() == md5(b'kitchenexplosion'+b).hexdigest())"
True
```

`msg1.bin` and `msg2.bin` differ in their interior bytes (fastcoll picks two
near-collision blocks) but both produce the same `msg_id`.

## Recovering the private key

ECDSA with reused nonce `k`:

```
s1 = k^-1 · (z1 + r·d)   mod n
s2 = k^-1 · (z2 + r·d)   mod n
```

Subtract → `k = (z1 - z2) · (s1 - s2)^-1 mod n`, then `d = (s1·k - z1) · r^-1 mod n`.

`z_i` is `sha256(M_i)` (since `n` has 521 bits the masking `& ~(1 << 521)` is
a no-op here). After computing `d`, check it against the published public key
by multiplying with the generator and comparing `Q.x`. If it doesn't match,
flip the sign — the symmetric solution `(-k, -d)` corresponds to the negated
nonce.

## Forging

Pick any recipe the server hasn't already signed (e.g. `b"forged-recipe"`),
choose a fresh random `kk`, compute the standard ECDSA signature with the
recovered `d`, and hand `(rr, ss)` to the `flag please` flow.

## Run

```
$ python3 solve.py <host> <port>
> sign 1755...
s1: 0x...
s2: 0x...
> sign 2cd9...
s1: 0x...                 ← same r as previous: nonce reuse confirmed
s2: 0x...
*** nonce reuse confirmed: r matches ***
d matches the published public key ✓
Congratulations. Here is your flag: GPNCTF{m4yb3_w3_sh0uld_us3_RFC_6979_n3xt_t1m3}
```
