# stupidcontract

**Category:** Reverse Engineering
**Event:** GPN CTF 2026

> I recently learned that Solana contracts are just eBPF bytecode and
> thought: "Why do I need a Solana VM for that if my kernel can just
> execute it?"
> So, after some tinkering, I let my kernel do what it does best:
> execute user provided code to enable gambling (and make me rich).

**Flag:** `GPNCTF{W417, n0! WHo STo1e mY S3CurITy???}`

## TL;DR

The handout ships a QEMU-launched kernel image (`patched.bzImage`) plus
the original `unpatched.bzImage`. Diffing the two shows the only patch is
the **removal of BPF-verifier bounds-check error messages** —
`R%d unbounded memory access`, `math between %s pointer and register with
unbounded min value is not allowed`, `value %lld makes %s pointer be out
of bounds`. The verifier was castrated.

The userspace `stupidcontract` binary embeds a Rust-aya eBPF object with
two programs:

* `try_get_reservation(idx: i64)` — runs a 20% RNG check, writes the
  resulting `0`/`1` byte into a 101-byte `.bss` map at offset
  `idx + 1`. The bound check is the **signed** comparison
  `if r7 s> 0x63 goto error`, so any *negative* index sails through.
* `validate_reservations()` — walks `bss[1..100]`; if every byte's low
  bit is set, writes `bss[0] = 1`. `bss[0]` is the `SUCCESS` flag the
  binary reads at the end to decide whether to print the flag.

`try_get_reservation(-1)` makes the program write the RNG bit to
`bss[-1 + 1] = bss[0]` directly. On the unpatched verifier this load
would die with one of those very error messages; on the patched kernel
the program loads and runs.

The bit is `1` with probability `0x33333333 / 0x1_0000_0000 ≈ 20 %`, so
**the last call's RNG result determines `SUCCESS[0]`**. The trick is:
spam `-1` until the server prints `Your reservation succeeded`, then
switch to `-200` for the remaining iterations so that subsequent writes
land far outside the `bss[0..100]` window. After the 300-iteration loop
runs `validate_reservations` (which on failure doesn't clear `bss[0]`),
the binary reads `SUCCESS[0]`, sees `1`, and prints the flag.

## Files

```
Dockerfile           # socat → run-qemu.sh
compose.yml          # binds ./flag → /flag-data/flag in the guest
flag                 # placeholder GPNCTF{this_is_a_local_dummy_flag}
run-qemu.sh          # qemu-system-x86_64 -kernel patched.bzImage -drive rootfs.ext2 …
images/
  patched.bzImage    # vulnerable kernel
  unpatched.bzImage  # reference kernel (red herring for diffing)
rootfs.ext2          # buildroot rootfs with /usr/bin/stupidcontract
```

`/etc/inittab` runs `/usr/bin/stupidcontract` after mounting the
`/flag-data` 9p share — that's the only path users reach over the socat
proxy.

## Step 1 — what's "patched"?

The bzImage payload is a gzip stream starting at offset `0x42c4`:

```python
data = open('patched.bzImage','rb').read()
i = data.find(b'\x1f\x8b\x08')   # 0x42c4
open('comp.gz','wb').write(data[i:])
```

After `gunzip`, both vmlinux ELFs are ~23 MB and 99 % of bytes differ
(layout shifted because of an added section). String-diffing strips the
noise:

```
$ strings vmlinux-patched | sort -u > p.s
$ strings vmlinux-unpatched | sort -u > u.s
$ diff p.s u.s | awk 'length > 30'
< 6.19.5-patched SMP preempt mod_unload
> 6.19.5 SMP preempt mod_unload
> R%d max value is outside of the allowed memory range
> R%d min value is outside of the allowed memory range
> R%d unbounded memory access, make sure to bounds check any such access
> math between %s pointer and register with unbounded min value is not allowed
> value %lld makes %s pointer be out of bounds
```

The unpatched kernel *has* the verifier's bounds-check messages; the
patched one does not. So the patch is "delete the OOB-pointer error
paths in `check_reg_arithmetic` / `check_helper_mem_access`" — i.e. the
verifier still loads programs but no longer rejects unbounded pointer
arithmetic against map-value pointers.

Conclusion: any eBPF code with **deliberately unverifiable pointer math**
is now loadable, and its runtime accesses are unchecked. We need to find
a program that takes advantage of that.

## Step 2 — the userspace binary

`rootfs.ext2` mounts cleanly as ext2 (`7z x`). The Rust binary
`/usr/bin/stupidcontract` is a Rust/aya application:

```
$ strings -n 20 usr/bin/stupidcontract | grep -i 'reservation\|flag\|map'
For which restaurant do you want a reservation? Please enter the index …
Your reservation succeeded, we look forward to seeing you!
Well, better luck next time...
Sorry, I cannot give you a flag. You did not get reservations to all restaurants
Thank you! You successfully got reservations to every restaurant
As a thank you, here's your flag:
/tmp/flag-data/flag
try_get_reservation
validate_reservations
SUCCESS map not found
.bss
```

100 "restaurants" exist. Each round the user types an index; the program
loads `try_get_reservation`, runs it via `BPF_PROG_TEST_RUN` with the
user's `i64` as ctx_in, prints either *succeeded* or *better luck next
time* depending on the program's return value. After **300** rounds it
runs `validate_reservations`, looks up `SUCCESS[0]` in a BPF
`Array<u8>`, and conditionally prints the flag.

The embedded BPF ELF (machine = `EM_BPF` = `0xf7`) is at file offset
`0x2aa20` (three identical copies are baked in for relocation purposes);
extract it by walking the ELF header and dumping `e_shoff + e_shnum *
e_shentsize` bytes. The result is included here as
[`contract.bpf.o`](./contract.bpf.o).

## Step 3 — `try_get_reservation` in eBPF

```
0000000000000000 <try_get_reservation>:
   0:  r0 = 0xffffffff ll                      ; default retval = -1
   2:  if r1 == 0x0  goto +0x16c               ; null ctx → return -1
   3:  r7 = *(u64 *)(r1 + 0x0)                 ; r7 = user-supplied i64 index
   4:  if r7 s> 0x63 goto +0xd                 ; SIGNED check: idx > 99 → log path
   5:  call 0x7                                ; bpf_get_prandom_u32
   6:  r1 = r0
   7:  r1 <<= 0x20
   8:  r1 >>= 0x20                             ; r1 = random_u32, zero-extended
   9:  r0 = 0x1                                ; tentative win
  10:  r2 = 0x33333333
  11:  if r2 > r1  goto +0x1                   ; if random < 0x33333333 keep r0 = 1
  12:  r0 = 0x0                                ; else r0 = 0
  13:  r1 = .bss                               ; map_value pointer (relocation)
  15:  r1 += r7                                ; r1 += idx       ← UNBOUNDED ADD
  16:  *(u8 *)(r1 + 0x1) = w0                  ; bss[idx + 1] = r0
  17:  goto +0x15d                             ; → exit (returns r0 = 0 or 1)
```

`validate_reservations` is straight-line: it walks `i = 1..100`, checks
`bss[i] & 1 != 0` for every `i`, sets `bss[0] = 1` on all-pass, and on
any failure exits via `r0 = 0; exit` **without touching `bss[0]`**.

### The bug

Two cooperating mistakes:

1. **Signed compare on an unsigned offset.** `r7 s> 0x63` returns false
   for any value with bit 63 set — i.e. any negative `i64`. So a user
   input of `-1` (or `-200`, or `0xFFFFFFFFFFFFFFFF` in the unsigned
   sense) skips the "index too large" branch.
2. **Unbounded map-value arithmetic.** `r1 += r7` after `r1 = .bss` is
   exactly the pattern the deleted verifier messages warn about. On
   stock 6.19.5 the program would be rejected at load time. On
   `patched.bzImage` it loads, and at runtime the kernel just does the
   addition.

Passing `r7 = -1` makes the store target `bss + (-1) + 1 = bss[0]` —
which is `SUCCESS[0]`, the literal flag gate.

(`r7 = -200` makes the target `bss[-199]`, well below the start of the
map's value region — that's fine on the patched kernel as long as the
written page isn't unmapped. Empirically the BPF program just runs and
returns; it never SIGSEGVs the host.)

## Step 4 — exploiting the 20% gate

`try_get_reservation` always **writes** `r0` to the target byte, win or
lose. So consecutive `-1` calls keep overwriting `SUCCESS[0]` with fresh
RNG bits. The final state is the last call's result — a 20%/80%
coinflip even if we made 300 attempts.

What we actually want:

* Send `-1` until `SUCCESS[0]` becomes `1`. The server prints
  *Your reservation succeeded* on the same iteration, so we know when
  this happens by parsing the output.
* Immediately switch to a "neutral" index whose write target is outside
  `bss[0..100]`. `-200` writes `bss[-199]` and changes nothing the
  binary cares about. `validate_reservations` still fails (because
  `bss[1..100]` were never set), but it doesn't *clear* `bss[0]` either.
* Burn the remaining iterations on `-200`. The 300-round loop ends,
  `validate_reservations` runs, `bss[0]` is still `1` from our earlier
  successful `-1` call, the binary's `SUCCESS[0]` lookup returns `1`,
  and the flag-printing branch fires.

The "we won" detection is straightforward: each round the server prints
either `Your reservation succeeded` or `Well, better luck next time`
between prompts.

## Solver

[`solve.py`](./solve.py) is stdlib only:

```python
PROMPT = b"index ("           # last bytes of the per-round prompt
ssock.sendall(b"-1\n" if not won else b"-200\n")
read_until(PROMPT)
if b"reservation succeeded" in buf and not won:
    won = True
```

End-to-end run (excerpt):

```
…
266/300 …  -1
[INFO  stupidcontract::interaction] Your reservation succeeded, …

*** [iter 266] SUCCESS — switching to neutral index ***

267/300 …  -200
[INFO  stupidcontract::interaction] Well, better luck next time...
…
300/300 …  -200
[INFO  stupidcontract::interaction] Well, better luck next time...
[INFO  stupidcontract] Thank you! You successfully got reservations to every restaurant
    I really hope the restaurants don't screw up and all our dinners go over without a problem.
[INFO  stupidcontract] As a thank you, here's your flag: GPNCTF{W417, n0! WHo STo1e mY S3CurITy???}
ACPI: PM: Preparing to enter system sleep state S5
reboot: Power down
```

## Notes

* The "*Thank you! You successfully got reservations to every
  restaurant*" message is printed by the binary's *flag* path
  unconditionally on the win-side branch — it's not produced by
  `validate_reservations` actually succeeding. `validate_reservations`
  returns `r0 = 0` (failure) in our run; the binary's check is purely
  `aya::Array::<u8>::get(&0)` on the BSS map, and we forged the byte
  directly.
* The eBPF `bss` "map" in aya is a `BPF_MAP_TYPE_ARRAY` with one element
  whose value is the concatenated `.bss` section. The kernel does
  *not* runtime-check offsets within map values — that is exactly the
  verifier's job, which is why removing the verifier checks is sufficient
  for this exploit. No kernel R/W primitive or escape is required; the
  whole thing stays inside the legitimate map-value page.
* The author included the unpatched bzImage as a courtesy: it's the
  intended way to identify "what changed." Without it you could still
  catch the signed-compare bug by reading the eBPF disassembly and
  asking why the program loads at all — `clang -O2` definitely wouldn't
  emit `r1 += r7` against a map value on a stock kernel.
