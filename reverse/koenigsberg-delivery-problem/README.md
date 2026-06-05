# Königsberg Delivery Problem

**Category:** Reverse Engineering
**Event:** GPN CTF 2026

> The cartographer needs to deliver a parcel to every address in the city —
> exactly once. Hand it a route and it will tell you whether you've done it
> right.

## TL;DR

`cartographer` is a 140 KB binary that reads 250 signed bytes, walks them
through a hand-built 250-state finite state machine, and only opens `/flag`
if every state was visited at least once. With exactly 250 input bytes that
forces a **Hamiltonian path** on the state graph. The name is the joke —
Königsberg is famous for the Euler*ian* bridge problem (no walk visits every
edge once), but here the delivery driver has to visit every *vertex*, which
is Hamilton's territory. Despite the misdirection, the graph is very dense
(out-degree ≈ 100 / state), so DFS with Warnsdorff's heuristic finds a path
in milliseconds.

**Flag:** `GPNCTF{s4y_EU1eR_7h3_oWl_0Wl5_iN_könI6SBeRG_10_7IMEs_F457!}`

## Recon

```
$ file cartographer
cartographer: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
              interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

Only three symbols matter: `main`, `cfg`, `check_instance`. `main` is huge but
boring — it issues 250 calls to `scanf("%hhd;", &buf[i])` into a 250-byte
buffer on the stack, then calls `cfg(buf)`:

```
$ strings cartographer | grep -c '%hhd'
250
```

## The FSM

`cfg()` opens with a zeroed 256-byte stack region (the visit-counter array)
and an indirect jump into state 0. Every state has the same skeleton:

```asm
1210: inc  byte ptr [rsp + N]            ; counter[N]++
1213: movzx edx, byte ptr [rdi + rcx]    ; sym = input[rcx]
1217: cmp  rdx, MAX_SYM_N                ; bounds check
121b: ja   0x40d4                        ; out of range → tail (= check_instance)
1221: inc  rcx
1224: movsxd rdx, dword ptr [JT_BASE + 4*rdx]
1228: add  rdx, JT_BASE                  ; (rip-relative offset to absolute)
122b: jmp  rdx                           ; dispatch to next state
```

So the binary encodes a directed graph as 250 jump tables packed back-to-back
in `.rodata`. Each entry is a 32-bit offset added to its table's base; the
result is either the entry address of another state, or the OOB tail block at
`0x40d4`.

The OOB tail is the *only* exit from `cfg()`:

```asm
40d4: mov  rdi, rsp
40d7: mov  esi, 0xfa            ; 250
40dc: call check_instance
40e1: add  rsp, 0x108
40e8: ret
```

## The win condition

`check_instance(buf, 250)` is a single linear scan:

```c
bool any_zero = false;
for (i = 0; i < 250; i++)
    if (buf[i] == 0) any_zero = true;
if (!any_zero) {
    int fd = open("/flag", O_RDONLY);
    char b[100]; read(fd, b, 100);
    printf("Congratulations! Here is your flag: %s", b);
}
else puts("Not quite, try again!");
```

So `/flag` is printed iff **every visit counter is non-zero** — every state
was visited at least once. The state entry counters are bytes at `rsp[0..249]`
and the entry-by-entry `inc` is the only thing that touches them, so a state
*not* visited keeps its zero counter.

## Why Hamiltonian (not Eulerian)

The challenge name evokes Königsberg's seven bridges — Euler's 1735 proof
that no walk crosses every bridge exactly once because four vertices have
odd degree. That's an *edge*-cover problem.

This challenge inverts it: the win condition counts *vertex* visits, not
edge usage, and the input is just barely long enough to do it once each:

- Initial state (state 0) is entered automatically, counting as 1 visit.
- Each subsequent input byte triggers exactly one transition = one new visit.
- 250 input bytes ⇒ 251 state entries total, except the last byte has to be
  an OOB symbol to fire `check_instance`, so it doesn't enter a state — the
  arithmetic works out to **exactly 250 state entries**, one per counter.

So the input is forced to encode a Hamiltonian path of length 250 starting
at state 0, followed by one terminating OOB byte. Euler is a red herring
baked into the flag, not the algorithm.

## Solving

The clean version of the pipeline lives in [`solve.py`](./solve.py); the
sketch:

1. **Disassemble** via `objdump -d -M intel`.
2. **Parse `cfg`**: every state is the unique `inc byte ptr [rsp + N]`
   instruction followed within ~10 instructions by `cmp rdx, MAX` and either
   an explicit `lea rsi, [rip + …]` (for the jump-table base) or, for state 0
   only, the `rax` value set right at the top of `cfg`. 250 such patterns
   appear in order — `idx` matches source order, with maxima between
   `0x59` and `0x6e`.
3. **Read the jump tables** out of `.rodata` (`objdump -s -j .rodata`). Each
   entry is a `<i` signed dword; resolve `JT_BASE + offset` against the
   state-address table to get the successor state (or detect `0x40d4` as
   OOB).
4. **Build the directed graph** and search for a Hamiltonian path from
   state 0. Out-degrees are 68–121 (average ≈ 100), so the graph is dense
   enough that DFS with Warnsdorff's rule — extend toward the unvisited
   successor with the fewest unvisited successors — finds a path with
   essentially no backtracking. ~70 ms on my laptop.
5. **Emit the input**: for each path edge `s → t`, pick any symbol that
   `transitions[s]` maps to `t`; append a final OOB symbol from the last
   state. All chosen symbols fall in `0..127`, so they round-trip through
   `%hhd` as plain non-negative decimals.

```
$ python3 solve.py
Hamiltonian path found over 250 states.
Wrote 735 bytes of input to .../input.txt

$ cat input.txt | ncat --ssl <host> 443
Congratulations! Here is your flag: GPNCTF{s4y_EU1eR_7h3_oWl_0Wl5_iN_könI6SBeRG_10_7IMEs_F457!}
```

The found path isn't unique — any Hamiltonian path on this graph works,
and there are presumably astronomically many — but the deterministic
Warnsdorff ordering makes `solve.py` reproducible.

## Reflection

This is what makes the binary fun: there's no encryption, no hidden constants,
no anti-debug tricks. The whole challenge is a single legible CS problem
expressed in 4500 lines of straight-line dispatch. The work is reading
enough of those lines to *recognise* the pattern, then trusting the textbook
algorithm to finish the job. The misdirection in the name — Königsberg —
nudges you toward an Eulerian formulation that won't fit the win condition;
the flag text rubs it in by name-checking Euler one more time.

## Files

- [`cartographer`](./cartographer) — original 140 KB binary
- [`solve.py`](./solve.py) — FSM extractor + Warnsdorff Hamiltonian DFS
- [`input.txt`](./input.txt) — pre-computed 250-byte input that opens `/flag`
