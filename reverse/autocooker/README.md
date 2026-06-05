# autocooker

**Category:** Reverse Engineering
**Event:** GPN CTF 2026

> Welcome to the auto cooker. We'll cook any recipe for you under one condition: It must actually taste good.

## TL;DR

A 16 KB dynamically-linked ELF takes our flag as a "recipe", runs it through
four invertible transformations (`salt → fry → trim → mix`), and `memcmp`s the
result against a 64-byte constant `DELICIOUS`. Every step is invertible, so we
extract the constants and run the pipeline backwards.

**Flag:** `GPNCTF{1_fE3L_l1k3_Y0u_ARE_rEAdY_FOR_oUr_haRDesT_dIsH3S_N0w}`

## Recon

```
$ file autocooker
autocooker: ELF 64-bit LSB executable, x86-64, dynamically linked,
            interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

Not stripped — the symbol table hands us the call graph for free:

```
check_recipe_length   explain_current_food
salt   fry   trim   mix   taste
```

…plus globals named `RECIPE`, `FOOD`, `TARGET_LENGTH`, `GRAIN_OF_SALT`,
`HEADER`, `WELCOME`, `DELICIOUS`. The whole challenge is laid out for us; we
just need to read each function and find the constants.

## main()

```c
fgets(RECIPE, 64, stdin);
check_recipe_length();
memcpy(FOOD, RECIPE, 64);

explain_current_food(verbose);
salt();   explain_current_food(verbose);
fry();    explain_current_food(verbose);
trim();   explain_current_food(verbose);
mix();    explain_current_food(verbose);
taste();
puts("Congratulations, you \"cooked\" a delicious plate of food!");
```

`FOOD` is the working buffer; `RECIPE` is the raw input. Both live in `.bss`,
zero-initialised, so anything past the user's input is `0x00`.

## The kitchen constants

The values we need live in `.data`:

```
404060  3d 00 00 00 aa 00 00 00   TARGET_LENGTH=0x3d, GRAIN_OF_SALT=0xaa
404080  0a 0a 0a 0a 7d dd a9 4e   ┐
404088  5f 9f 99 2e 9d 3e ec 5f   │
...                               │  DELICIOUS[64]
4040b8  9e 4e af de               ┘
```

So `TARGET_LENGTH = 61` and `GRAIN_OF_SALT = 0xAA`.

## check_recipe_length

```c
if (RECIPE[TARGET_LENGTH]     != 0) goto bad;  // must be terminated by 61
if (RECIPE[TARGET_LENGTH - 1] == 0) goto bad;  // index 60 must be non-zero
```

`fgets` keeps the `\n` and appends a `\0`. So with input of length `N`:

- `RECIPE[N]   = '\n'`
- `RECIPE[N+1] = '\0'`

The checks force `N + 1 == 61`, i.e. **the flag is exactly 60 bytes long**, and
`RECIPE[60]` is the `'\n'` from `fgets`.

## The four pipeline steps

Each step iterates over all 64 bytes of `FOOD`. Distilled C:

```c
void salt(void) { for (i=0; i<64; i++) FOOD[i] ^= GRAIN_OF_SALT; }      // 0xAA

void fry(void)  { for (i=0; i<64; i++)
                      FOOD[i] = (FOOD[i] << 4) | (FOOD[i] >> 4); }      // nibble swap

void trim(void) { for (i=TARGET_LENGTH; i<64; i++) FOOD[i] &= 0x0F; }   // i ∈ [61, 63]

void mix(void)  { uint8_t tmp[64] = FOOD;
                  for (i=0; i<64; i++) FOOD[i] = tmp[63 - i]; }         // reverse
```

`taste` is just `memcmp(FOOD, DELICIOUS, 64)`; any mismatch prints `YUCK!` and
exits.

## Inverting the pipeline

Every step is invertible:

| Step  | Operation                | Inverse                |
|-------|--------------------------|------------------------|
| salt  | XOR 0xAA                 | XOR 0xAA (self-inverse) |
| fry   | nibble swap              | nibble swap (self-inverse) |
| trim  | mask high nibble (i≥61)  | unrecoverable for i ∈ [61, 63] |
| mix   | reverse                  | reverse (self-inverse) |

`trim` looks like it loses information — but only at indices 61, 62, 63, which
are exactly the bytes we *don't* control (they come from the zero padding after
`fgets`). For the 60 flag bytes (indices 0–59), `trim` is a no-op.

### Sanity-check the tail (indices 61–63)

The pipeline state at indices 61–63 is determined entirely by the zero padding:

```
RECIPE[61..63] = 0x00
         salt → 0x00 ^ 0xAA = 0xAA
         fry  → swap(0xAA) = 0xAA
         trim → 0xAA & 0x0F = 0x0A
         mix  → ends up at FOOD[0..2]
```

`DELICIOUS[0..2] = 0x0A 0x0A 0x0A` ✓. And `RECIPE[60] = '\n' = 0x0A`, which
salts/fries to `0x0A` and lands at `DELICIOUS[3] = 0x0A` ✓.

The constraints are self-consistent — confirmation we've understood the
pipeline correctly.

### Solving for the flag

For `i ∈ [0, 59]`, the flag byte at position `i` ends up at `DELICIOUS[63 - i]`
after the pipeline. Inverting:

```
flag[i] = nibble_swap(DELICIOUS[63 - i]) ^ 0xAA
```

That's the whole solver — see `solve.py`:

```python
flag = bytes(nibble_swap(DELICIOUS[63 - i]) ^ 0xAA for i in range(60))
```

```
$ python3 solve.py
Flag: GPNCTF{1_fE3L_l1k3_Y0u_ARE_rEAdY_FOR_oUr_haRDesT_dIsH3S_N0w}
Verified against DELICIOUS.
```

## Reflection

The whole challenge is a worked example of *don't invent your own crypto*: XOR
with a fixed byte, a nibble swap, and a reversal are all involutions; chaining
involutions and one near-no-op (`trim`) keeps the composition invertible. The
not-stripped symbols make the structure trivial to recover, but even stripped,
the four "operate on 64 bytes" loops are unmistakable in the disassembly.

## Files

- [`autocooker`](./autocooker) — original 16 KB binary
- [`solve.py`](./solve.py) — solver + forward-verification
