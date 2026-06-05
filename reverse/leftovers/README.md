# leftovers

**Category:** Reverse Engineering
**Event:** GPN CTF 2026

> We ship a JDK, a JAR, and a recorded AOT cache. The flag is at `/flag`.
> Have fun :)

## TL;DR

The JAR contains an honest-looking Javalin fridge tracker whose
`Server.lambda$main$15` checks the admin password against the literal
`"supersecret"`. Sending `"supersecret"` to the deployed server returns
**`Invalid password`**. The cache.aot has surreptitiously **replaced**
the method's bytecode at archive-time: instead of `Arrays.equals` against
`"supersecret"`, the live method runs a four-stage transform on the user
input (ROT13 → reverse → XOR with a hardcoded array → compare to another
hardcoded array). Inverting that transform yields the real password
`algomaster99`. Once authenticated we re-point the image folder to `/`,
register a Product named `flag`, and read it back through
`GET /images/flag`.

**Flag:** `GPNCTF{L3FT_0r_R1GHt_code_CaCHe_VA1ID4tiOn_5Ays_gOOd_NigHt}`

## The application

`leftovers.jar` is a small Kotlin/Javalin server with four routes:

| Method | Path                | Behaviour                                            |
|--------|---------------------|------------------------------------------------------|
| GET    | `/`                 | List products as HTML.                               |
| PUT    | `/products/{name}`  | Add a Product, then HTTP-download its image to `folderPath/sanitize(name)`. |
| GET    | `/images/{name}`    | Look up Product by name, return the file at `folderPath/sanitize(name)`. |
| POST   | `/set-image-dir`    | Reset `folderPath` after a password + path check.    |

`sanitize(name) = name.replaceAll("[^a-zA-Z0-9_-]", "_")`, so path traversal
via the product name is dead. The only way to read `/flag` is to convince
`/set-image-dir` to set `folderPath = "/"` and then GET `/images/flag`.

`/set-image-dir` chains three Javalin validators on a
`record SetImageDir(String password, Path newPath)`:

1. `password != null` — *"Password must be present"*
2. `Arrays.equals("supersecret".toCharArray(), password.toCharArray())`
   && `'s' == 115` — *"Invalid password"*
3. `Files.exists(newPath) && Files.isDirectory(newPath)` — *"Path must exist…"*

The third validator passes for `newPath="/"`. The second is what stands
between us and the flag.

## The setup

The Dockerfile is the punchline:

```
FROM eclipse-temurin:26 AS challenge
EXPOSE 1337
COPY my-jdk /my-jdk
COPY leftovers.jar cache.aot /app/
WORKDIR /app/
ENTRYPOINT /my-jdk/bin/java -XX:AOTCache=cache.aot -jar leftovers.jar
```

A custom JDK (built from a specific OpenJDK commit with
`--with-extra-cflags="-Wno-discarded-qualifiers"` — keep that flag in mind)
runs the JAR with a 51 MB AOT cache hand-recorded by the challenge author.
*Something* in that cache is doing the lifting.

## The dead end

The JAR's bytecode for `lambda$main$15` is exactly the cute thing it looks
like:

```
 0: ldc           #134                // String supersecret
 2: invokevirtual #136                // String.toCharArray
 5: astore_1
 6: aload_1; iconst_0; caload; istore_2     // var2 = chars1[0]
10: aload_1
11: aload_0; getfield #140                  // password
15: invokevirtual #136                      // toCharArray
18: invokestatic  #144                      // Arrays.equals
21: istore_3
22: iload_3; ifeq 36
26: iload_2; bipush 115; if_icmpne 36
32: iconst_1; goto 37
36: iconst_0
37: invokestatic #128                       // Boolean.valueOf
40: areturn
```

So sending `{"password": "supersecret", "newPath": "/tmp"}` *should* pass.
It doesn't:

```
$ curl … /set-image-dir -d '{"password":"supersecret","newPath":"/tmp"}'
{"REQUEST_BODY":[{"message":"Invalid password",…}]}
```

`"supersecret"` also appears as expected in the cache:

- a `Symbol` (interned UTF-8) at file offset `0x146ca10`,
- an archived `String`'s `byte[]` at file offset `0x32994d4`,

both with the literal 11 bytes `73 75 70 65 72 73 65 63 72 65 74`. So the
constant pool is unchanged. The lie has to be somewhere else.

## Proving the method body has been swapped

The original `lambda$main$15` body contains the unique 5-byte sequence
`4c 2b 03 34 3d` (`astore_1; aload_1; iconst_0; caload; istore_2`) — those
instructions don't change under CDS rewriting because they have no CP
operands. Yet:

```python
>>> sum(1 for _ in re.finditer(b'\x4c\x2b\x03\x34\x3d', open('cache.aot','rb').read()))
0
```

Zero matches. The cache has scrubbed the original method body. Time to
find what it was replaced with.

## Finding the substitute method

CDS deduplicates UTF-8 strings into a Symbol table. The Symbol for
`"lambda$main$15"` lives at file offset `0x146d086`:

```
$ grep -aob 'lambda$main$15' cache.aot
0x146d086
```

The `Symbol*` itself starts a few bytes earlier. Critically, the file is
**mapped** at base `0x800000000` (the standard Application CDS base on
this JDK build), so the in-memory pointer is `0x80146d080`. Searching the
file for that pointer as a little-endian 64-bit value finds three
references:

```python
>>> [hex(m.start()) for m in re.finditer(struct.pack('<Q', 0x80146d080), data)]
['0x884938', '0x1f075c0', '0x29453f0']
```

The hit at `0x884938` sits **inside** a 112-byte `Method` struct that
starts at `0x884900`. The very first 8 bytes of every `Method` are its
`ConstMethod*`:

```
[00884900] 80 c6 f0 01 08 00 00 00  …   ; ConstMethod* = 0x801f0c680
…
[00884938] 80 d0 46 01 08 00 00 00  …   ; name Symbol* = 0x80146d080
…
[00884970] 00 c8 f0 01 08 00 00 00  …   ; next method's ConstMethod*
```

So `lambda$main$15`'s real body lives at file offset `0x1f0c680`, and the
next method starts at `0x1f0c800`, giving us a 384-byte ConstMethod blob
to decode. (That blob is shipped here as
[`lambda_main_15_constmethod.bin`](./lambda_main_15_constmethod.bin) so
you can reproduce without the 51 MB cache.)

## Decoding the bytecode

The first ~56 bytes of the ConstMethod are header fields; the actual
bytecode runs from offset `0x38` through end. The opcodes are CDS-
rewritten, which means a couple of non-standard one-byters are mixed
with the usual JVM set:

- `0xed XX` — `_fast_iload` (a one-byte-index variant of `iload`)
- `0xec XX YY` — `_fast_aaccess_0` (combined `aload_0; getfield CP[XXYY]`)
- `0xee XX YY` — `_fast_invokevfinal` (resolved `invokevirtual`)

(Everything else is stock.)

The method, transliterated back to Java:

```java
char[] arr1 = { 233, 202, 85, 61, 72, 144, 198, 179, 218, 190, 240, 59 };
char[] arr = input.password.toCharArray();

// 1. ROT13 every char that isn't a digit.
for (int i = 0; i < arr.length; i++) {
    int c = arr[i];
    if (c >= '0' && c <= '9') continue;
    arr[i] = (char) (((c - 'a' + 13) % 26) + 'a');   // i2b then i2c afterwards
}

// 2. Reverse the array in place.
for (int i = 0; i < arr.length / 2; i++) {
    char tmp = arr[arr.length - 1 - i];
    arr[arr.length - 1 - i] = arr[i];
    arr[i] = tmp;
}

// 3. XOR with arr1.
for (int i = 0; i < arr.length; i++) {
    arr[i] = (char) (arr[i] ^ arr1[i % arr1.length]);
}

// 4. Compare to arr2.
char[] arr2 = { 208, 243, 48, 79, 47, 246, 168, 201, 184, 202, 137, 85 };
return Boolean.valueOf(Arrays.equals(arr2, arr));
```

The two static arrays are right there in plaintext — they're materialised
by a long run of `dup; iconst/bipush <index>; bipush/sipush <value>; castore`
instructions. The transform itself is built out of standard arithmetic
opcodes (`isub`, `iadd`, `irem`), and the conspicuous `bipush '0'` /
`bipush '9'` / `bipush 'a'` / `bipush 26` constants make the ROT13 hard to
miss once you find the method.

## Inverting

Each of the four steps is invertible, so we just run the pipeline
backwards:

```
target          = STATIC_ARR_2                              # [208, 243, 48, 79, 47, 246, 168, 201, 184, 202, 137, 85]
after_reverse   = [target[i] ^ STATIC_ARR_1[i] for i …]      # "99ergfnzbtyn"
after_rot13     = reversed(after_reverse)                    # "nytbznfgre99"
original        = [rot13(c) for c in after_rot13]            # "algomaster99"
```

ROT13 is its own inverse for letters; digits drop through untouched. The
twelve-char password is **`algomaster99`** — a nod to a well-known coding
YouTuber, which is the "leftover" the challenge name is winking at.

## Exploitation

```
$ curl -X POST $BASE/set-image-dir \
       -H 'Content-Type: application/json' \
       -d '{"password":"algomaster99","newPath":"/"}'
# HTTP 200 (folderPath = "/" now)

$ curl -X PUT $BASE/products/flag \
       -H 'Content-Type: application/json' \
       -d '{"product":{"name":"flag","quantity":1,
                       "bestBefore":"2030-01-01T00:00:00",
                       "notAfter":"2030-01-01T00:00:00"},
            "imageUrl":"http://example.invalid/x.png"}'
# HTTP 500 — but State.addProduct adds the Product *before* the
# httpClient.send() call, so the Product is registered before the failure.

$ curl $BASE/images/flag
GPNCTF{L3FT_0r_R1GHt_code_CaCHe_VA1ID4tiOn_5Ays_gOOd_NigHt}
```

`solve.py` automates all of the above and verifies the password derivation
by running the forward transform and checking the result equals
`STATIC_ARR_2`.

## Lessons

The point of the challenge is that the AOT cache (the OpenJDK 26 successor
to AppCDS, the prototype that ships with Project Leyden) is part of your
application's trusted code base. The cache can ship arbitrary substitute
Method bodies whose ConstMethod entries override what's in the JAR —
even Symbols and Strings the JAR's constant pool resolves through can be
replaced. Static analysis of the JAR alone tells you nothing about what
the JVM will actually execute.

The flag spells it out:
"**L3FT or R1GHt code CaCHe VA1ID4tiOn 5Ays gOOd NigHt**" — i.e., if your
build pipeline doesn't validate the code cache on either side, the
attacker's bytecode wins.

The `-Wno-discarded-qualifiers` hint in the Dockerfile is the breadcrumb:
the custom JDK was patched to allow writing into normally-`const` regions
of CDS metadata, which is how the swap was performed without
invalidating the cache header.

## Files

- [`leftovers.jar`](./leftovers.jar) — application JAR (9.2 MB).
- [`Dockerfile`](./Dockerfile) — original challenge Dockerfile.
- [`lambda_main_15_constmethod.bin`](./lambda_main_15_constmethod.bin) —
  the 384 bytes of the substituted ConstMethod, extracted from `cache.aot`
  at file offset `0x1f0c680` (so the bytecode analysis is reproducible
  without the 51 MB cache file).
- [`solve.py`](./solve.py) — derives the password, verifies the forward
  transform, then runs the three-step exploit against an instance URL.

The original `cache.aot` (51 MB) and the custom JDK (`my-jdk/`) are not
committed — see the Dockerfile for how to rebuild the JDK from openjdk/jdk
commit `35b0de3d4d4e8212227af5462fafbd464103f058`.
