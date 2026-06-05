# leftover-leftovers

**Category:** Reverse Engineering
**Event:** GPN CTF 2026

> You caught me, I was a bit cheeky with the last one! To make up for it,
> you can now supply me with some delicious, edible, eatable and
> completely safe food. I hear you had something cooking the other day?
> It's probably still good!
>
> PS: Sorting my leftovers first sounds like a good idea :)

## TL;DR

A follow-up to [`leftovers`](../leftovers). The challenge bolts an extra
upload-and-validate stage on the front:

* **Stage 1** is `OuterServer` — a Javalin app whose class data lives
  entirely in `outer-cache.aot` (the `de/kitctf/gpn24/leftovers2/`
  directory is **empty** in the JAR). It serves `GET /cache`
  (returns the original `cache.aot`), `POST /init` (multipart upload of a
  candidate `cache.aot`), runs `verifyStuff(uploaded)` on it, and if the
  result matches the original it writes `/tmp/cache.aot` for Stage 2 and
  exits.
* **Stage 2** is the leftovers `Server` running against the just-written
  `/tmp/cache.aot`.

The bundled `cache.aot` has `Server.lambda$main$15` reduced to **5 bytes**:

```
03 b8 11 00 b0    iconst_0; invokestatic Boolean.valueOf; areturn
```

i.e. password validation is hard-wired to return `Boolean.FALSE`, and the
live server rejects every password with **`Password login is currently
disabled`**.

The exploit is a **one-byte patch**: flip `iconst_0` (`0x03`) to
`iconst_1` (`0x04`) at file offset `0x1F05A88`. `verifyStuff` doesn't
include method bytecode bytes in its hash, so the patched cache survives
the upload check. Stage 2 then accepts any password, and the standard
leftovers exploitation reads `/flag`.

**Flag:** `GPNCTF{I_HoPE_thE_c4cHE_i5_nevER_Pr0vided_8y_1Ibr4RI35}`

## Recon

```
$ ls -la
Dockerfile     leftovers2.jar   my-jdk/
exec.sh        cache.aot        outer-cache.aot
README.md
```

`exec.sh` reveals the two-stage layout:

```bash
"$JAVA" ... -XX:AOTCache="$OUTER_CACHE_FILE" \
        -cp "$JAR" de.kitctf.gpn24.leftovers2.OuterServer serve \
            "/tmp/cache.aot" "$CACHE_FILE"
"$JAVA" ... -XX:AOTCache="/tmp/cache.aot" -jar "$JAR"
```

The JAR's `de/kitctf/gpn24/leftovers2/` directory has **no** `.class`
files — only `pom.xml` and `pom.properties`. So `OuterServer` is loaded
out of `outer-cache.aot` exclusively. (`leftovers-padding.bin` is 122 KB
of zero padding, probably for cache-alignment reasons during recording.)

## Mapping out OuterServer

OuterServer's class metadata is in the outer cache. Following the same
Symbol-pointer trick as in [`leftovers`](../leftovers) (in-memory base
`0x800000000`), the class CP shows:

| Symbol                                                          | Meaning                |
|-----------------------------------------------------------------|------------------------|
| `Usage: OuterServer <serve> <aot target file> <expected hash>`  | CLI usage              |
| `/init`                                                         | upload endpoint        |
| `/cache`                                                        | download endpoint      |
| `cache.aot`                                                     | multipart field name   |
| `No cache.aot file uploaded`                                    | 400 body if no file    |
| `Invalid cache file`                                            | 400 body on hash miss  |
| `verifyStuff`                                                   | the validator method   |
| `(L…/AotCache;)Ljava/lang/String;`                              | signature of validator |
| `(L…/InstanceKlassView;)Ljava/lang/String;`                     | per-class hash lambda  |
| `(L…/MethodView;)Ljava/lang/Long;`                              | per-method hash lambda |

…plus parsers `ArchiveReader`, `ArchiveHeaderView`, `PointerResolver`,
`CompactHashtableReader`, `SerializedRootsReader`, `InstanceKlassView`,
`ConstantPoolView`, `ConstantPoolView$ConstantPoolEntryView`,
`MethodView`, `ConstMethodView`, `RunTimeClassInfoView`, `ArchiveRegionView`.
The author wrote a small CDS-format parser and a hash of selected
metadata.

The hint **"sorting my leftovers first sounds like a good idea"** matters
here: `verifyStuff` iterates a `Map<String, InstanceKlassView>`. Without
sorting the keys, two semantically-equivalent caches whose Klass entries
land in different bucket order produce different hashes. To stay
deterministic we mustn't add, remove, or relocate any class — patches
have to be done in place.

## The cheeky cache

Looking up `lambda$main$15`'s Symbol in `cache.aot` (file offset
`0x1467086`) and following the same pointer-table trick to the
ConstMethod (file offset `0x1F05A50`), the body is just five bytes:

```
[01F05A88]  03 b8 11 00 b0
            ^^ iconst_0  (push 0/false)
               ^^^^^^^^ invokestatic Boolean.valueOf
                        ^^ areturn
```

`return Boolean.FALSE;` — full stop. The corresponding "Invalid password"
string has also been swapped out: the cache contains
`Password login is currently disabled` as the Javalin validator error
message, which is what the live server returned during recon.

A patched version of this challenge actually presents a *new* lesson — the
previous leftovers ROT13 puzzle was just there to make you find the
substituted method; here the substituted method is intentionally trivial
to neutralise. The interesting half is bypassing `verifyStuff`.

## The one-byte patch

```python
with open("cache_patched.aot", "r+b") as f:
    f.seek(0x1F05A88)
    f.write(bytes([0x04]))   # iconst_0 (0x03) → iconst_1 (0x04)
```

Now the body is `04 b8 11 00 b0` = `return Boolean.TRUE`. Same length,
same offsets, every other byte of the 51 MB cache is unchanged. The 64
bytes around the ConstMethod (header + body + padding) are committed as
[`cheeky_lambda_main_15.bin`](./cheeky_lambda_main_15.bin) for
inspectability without needing the full cache.

## Why `verifyStuff` doesn't notice

`verifyStuff` apparently combines a per-Klass hash that depends only on
its `ConstantPoolView` and per-method `(name, signature)` — *not* the
bytecode bytes inside `ConstMethodView`. (You can verify this empirically
by uploading the patched cache: it's accepted, and Stage 2 boots with
our modified body live.) If the hash *did* include the body, we'd be
forced to find a five-byte sequence that (a) returns `true` and (b)
collides under whatever per-method `Long` the lambda produces. The
"sorting" hint is what keeps the Klass iteration order canonical between
the original recording and our upload, but as long as we don't disturb
that, in-place body edits are free.

## Exploitation

```
$ python3 solve.py cache.aot https://<instance>.gpn24.ctf.kitctf.de
Patched cache → /tmp/cache_patched.aot  (1 byte at 0x1F05A88: 03 → 04)
Uploading to .../init … (this takes ~90s; Stage 1 closes the connection
after the handoff)
Exploiting Stage 2 …
Flag: GPNCTF{I_HoPE_thE_c4cHE_i5_nevER_Pr0vided_8y_1Ibr4RI35}
```

The exploitation half of Stage 2 is the same as the original leftovers
challenge: with `lambda$main$15` returning `true`, `POST /set-image-dir`
accepts any password (we sent `"anything"`) and we can re-point
`folderPath` to `/`. `PUT /products/flag` registers a Product, and
`GET /images/flag` reads `/flag` directly.

## Reflection

The flag spells it out: **"I hope the cache is never provided by
libraries"**. The two leftovers challenges together teach the same
lesson from two angles:

1. **Leftovers I** — the bundled AOT cache replaced a 41-byte method
   body with a 321-byte ROT13/XOR puzzle. Static analysis of the JAR's
   `lambda$main$15` showed `equals("supersecret")`, but the *live*
   method was something else entirely.
2. **Leftovers II** — the bundled AOT cache reduces the same method to
   five bytes (`return Boolean.FALSE;`) **and** wraps the whole loader
   in a validation stage that hash-checks any replacement cache. The
   author tries to convince you that you can't tamper with the cache,
   but the validator hashes class structure, not bytecode — so a single
   byte still flips the world.

The `-Wno-discarded-qualifiers` flag in the original Dockerfile is the
breadcrumb in both challenges: the JDK was patched to allow writing into
normally-`const` regions of the CDS archive, which is how the substitute
method bodies were stitched in without invalidating the cache header.

## Files

- [`leftovers2.jar`](./leftovers2.jar) (9.2 MB) — application JAR.
- [`exec.sh`](./exec.sh) — two-stage launcher.
- [`CHALLENGE_README.md`](./CHALLENGE_README.md) — original challenge
  README from the handout.
- [`cheeky_lambda_main_15.bin`](./cheeky_lambda_main_15.bin) — the
  64-byte ConstMethod region extracted from `cache.aot` at file offset
  `0x1F05A50`, so the cheeky 5-byte body is reproducible without the
  51 MB cache.
- [`solve.py`](./solve.py) — patches `cache.aot`, uploads it to
  `POST /init`, then runs the Stage 2 exploit.

`cache.aot` (51 MB), `outer-cache.aot` (38 MB) and the custom JDK
(`my-jdk/`) are not committed — see `exec.sh` for the JDK build
instructions.
