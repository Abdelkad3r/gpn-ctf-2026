# specCTF

**Category:** Reverse Engineering
**Event:** GPN CTF 2026

> A 43 KB C++ Spectre-v1 contraption. Pass it the right input on the command
> line and it prints `CORRECT`.

## TL;DR

The binary looks like a Spectre side-channel duel, but the cache-timing rig is
mostly theatre. The actual check enforced by the speculative gadget is

```
ENC[i] == splitmix_hash(input_qword_i)
```

`hash` is invertible mod 2⁶⁴, so we just invert it on each of the six
non-zero `ENC` qwords and concatenate the result in little-endian byte order.

**Flag:** `GPNCTF{tHIS_Meal_I5_5PeCulaTively_De1ic1ouS!!!!}`

## Recon

```
$ file specCTF
specCTF: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
         interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

Not stripped — handy. The symbols immediately advertise a Spectre PoC:

```
specte_byte   readMemoryByte   carrierFunc   spec_func
specEnvTime   get_from_array   init_attack   train
distTrue      distFalse        hash          pin_core
```

…plus globals `ENC`, `arr1`, `arr2`, `results`, `true_res`, `false_res`,
`ATTACK_PATTERN`, `IS_ATTACK`, `CACHE_HIT_THRESHOLD`, `ACCEPTABLE_DIST`,
`PQ`. Standard Spectre v1 vocabulary: train a branch predictor, mistrain a
bounds check, leak through `arr2[secret * 512]` cache footprints.

## The decoy main()

```c
for (outer = 0; outer <= 0x2a; outer++) {        // 43 rounds
    pin_core();
    init_attack();
    train();

    char *input = argv[1];
    size_t n = strlen(input);
    if (n & 7) { puts("NOPE"); exit(0x539); }    // must be a multiple of 8

    int counter = 0;
    for (i = 0; i < n / 8; i++) {
        r15 = ((uint64_t *)ENC)[i];              // <-- loaded but
        r14 = ((uint64_t *)input)[i];            // <-- never passed!
        counter += specte_byte(0x1337, 0x1337);  // hardcoded args
    }
    if (counter == n / 8) correct++; else correct--;
    if (correct > 2) { puts("CORRECT"); exit(0); }
}
```

The constant `0x1337` arguments are a giant red flag: how does any of this
depend on the input? The trick is `r14` / `r15`. They're loaded with
`input[i]` and `ENC[i]` right before the call, and System V x86-64 marks them
as **callee-saved** — so they survive `specte_byte` unchanged. Somewhere
deeper in the call graph, a function reads them directly.

## The real comparison — specEnvTime

```c
int specEnvTime(unsigned long /*unused*/, int /*unused*/) {
    if (r15 == 0 && r14 == 0)              return arr2[0x2800];   // train "match"
    if (hash(r14) == r15)                  return arr2[0x2800];   // real match
                                           return arr2[0xa200];   // mismatch
}
```

(In source, this is presumably a `register uint64_t … asm("r14")` global, a
GCC extension. In the disassembly it just shows up as bare `mov rax, r14`
inside an otherwise normal-looking function.)

`arr2[0x2800]` and `arr2[0xa200]` are two different cache lines. `specte_byte`
then runs the Flush+Reload classifier on those lines, comparing the timing
fingerprint against the `true_res` / `false_res` distributions that `train`
built earlier. So the entire 200+ line Spectre rig collapses to a one-line
hash equality check: **`hash(input_qword) == ENC[i]`**.

### train() ↔ specEnvTime

`train()` runs 40 rounds, alternating:

- **Even rounds**: set `r14 = r15 = 0` → `specEnvTime` hits `arr2[0x2800]` →
  accumulated into `true_res`.
- **Odd rounds**: set `r14`, `r15` to independent `rand()` values (and bump
  `r14` if they happen to collide) → `hash(r14) != r15` almost always →
  hits `arr2[0xa200]` → accumulated into `false_res`.

So `true_res` is the cache pattern when `hash(r14) == r15` and `false_res`
when not. `specte_byte` picks whichever distribution is closer.

## The hash

```c
static uint64_t hash(uint64_t x) {
    x ^= x >> 33;
    x *= 0xf451af975d152cad;   // movabs ... -0xbae5068a2ead353
    x ^= x >> 33;
    x ^= 0xc2ceaade1a351c23;   // movabs ... -0x3d315521e5cae3dd
    x ^= x >> 33;
    return x;
}
```

A splitmix64-style finalizer (one multiply, three xor-shifts, one xor). Every
step is invertible:

| Step              | Inverse |
|-------------------|---------|
| `x ^= x >> 33`    | Self-inverse. The shift is > half the word width, so the top 31 bits pass through untouched, and applying it again recovers the bottom 33 bits. |
| `x *= MUL`        | `MUL` is odd, so it has a modular inverse mod 2⁶⁴ (`pow(MUL, -1, 1 << 64)`). |
| `x ^= CONST`      | Self-inverse. |

So `inv_hash(y)` is just the same steps in reverse:

```python
def inv_hash(y):
    y = inv_xs33(y)
    y ^= 0xc2ceaade1a351c23
    y = inv_xs33(y)
    y = (y * pow(MUL, -1, 1 << 64)) & ((1<<64) - 1)
    y = inv_xs33(y)
    return y
```

## Extracting ENC and solving

```
$ objdump -s -j .data --start-address=0x70c0 --stop-address=0x70f8 specCTF
 70c0 e57571e9 ec9075ee 9a6e36f3 56ac93b9
 70d0 ed5e6613 4a845a4a a1ebae5b 56a4bdcd
 70e0 415a6201 729e5c52 1f0887d8 3e7e05bb
 70f0 00000000 00000000
```

Six meaningful little-endian qwords. The seventh zero qword in `ENC[6]` is
unused — `main` iterates `strlen / 8` times and the flag has `strlen == 48`.

```
$ python3 solve.py
Flag: GPNCTF{tHIS_Meal_I5_5PeCulaTively_De1ic1ouS!!!!}
Verified: hash(flag chunks) matches ENC[0..5].
```

## Why the misdirection works

The interesting design choice is making `r14` / `r15` implicit. A reader
following the C++ ABI sees `specte_byte(0x1337, 0x1337)` and concludes the
input is unused — the compare must be elsewhere, perhaps via shared state.
Tracing into `specEnvTime` reveals the hidden register-coupling, and from
there the rest of the Spectre machinery becomes obvious noise: the speculative
load, the 256 cache lines in `arr2`, the priority-queue of measured times,
the Euclidean-distance classifier — all of it just amplifies one bit
(`hash(r14) == r15`) into a side-channel signal that the rest of the program
re-reads as a normal return value.

For an attacker reverse-engineering the binary, none of that matters. The
hash is pure math and pure math is invertible.

## Files

- [`specCTF`](./specCTF) — original 43 KB binary
- [`solve.py`](./solve.py) — hash inverter + round-trip verification
