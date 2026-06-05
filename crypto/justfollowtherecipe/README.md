# justfollowtherecipe

**Category:** Crypto
**Event:** GPN CTF 2026

> Cooking is easy they say. Just follow the recipe they say. If you follow the
> recipe nothing can go wrong. And still, I end up with chemical weapons
> instead of dinner and they complain. But it's not my fault that my kitchen
> is shit. But they dont want to hear that excuse. The binary is there for a
> reason, LOOK at it.

**Flag:** `GPNCTF{coMP1L3rS_aRe_Y0UR_fr1End_7HEY_w0ULd_never}`

The flag spells out the lesson: the source code is fine, the **compiler
miscompiled** the AVX2 hot path.

## TL;DR

SIS-style hash `flag_hash = A · secret mod q` with `A ∈ Z_q^{N×M}` random,
`secret ∈ {0..9}^M`, `N=64, M=164, q=12289`. An oracle hashes arbitrary
vectors, so we leak `A` column-by-column via `multi_hash`, then attack the
q-ary kernel lattice `Λ_q^⊥(A)` with a Kannan embedding. BKZ on the resulting
165-dim lattice — with fplll's `default.json` preprocessing+pruning strategies
— finds the short target around `β = 50..60` in ~45 s.

The Linux binary's `mat_mul` (the AVX2 inner-product routine) is
**miscompiled** under `gcc -O3 -mavx2 -funroll-loops`. In each 4-way
unrolled output block the compiler swaps **lanes 1 and 2**, so result
positions `4k+1` and `4k+2` come out swapped for every full block — but the
final scalar tail (the last `MM mod 4` entries) is correct. `mat_mul_naive`
(used only for `flag_hash` at startup) is scalar and unaffected, so the
target side of the SIS equation is fine — only the *queries* we use to leak
`A` are corrupted, and they're corrupted **in the batch axis** for
`multi_hash`. Undoing the per-batch swap (and not over-swapping the tail
block) restores `A` exactly and BKZ recovers `secret`.

## Protocol

```
0) Check your work       — submit a guess of secret, win if exact, else leak + exit
1) Hash a single vector  — read v, print A·v mod q   (or v = secret if you say "y")
2) Hash multiple vectors — same, up to 100 vectors per call
3) Exit
```

Option 0 has the obvious "hint": on a wrong guess the server prints the real
`secret_vec` before `exit(0)`. Useless across connections (each session
re-randomises `A`, `secret`, `flag_hash`) but priceless for ground-truth
debugging against a locally-rebuilt binary.

## The compiler bug

`mat_mul` is a textbook 4-wide unrolled dot product:

```c
for (blk = 0; blk < (int)MM - 4; blk += 4) {
    for (int i = 0; i < NN; i++) {
        result[blk + 0] += src[i] * (uint64_t)BB[i*MM + blk + 0];
        result[blk + 1] += src[i] * (uint64_t)BB[i*MM + blk + 1];
        result[blk + 2] += src[i] * (uint64_t)BB[i*MM + blk + 2];
        result[blk + 3] += src[i] * (uint64_t)BB[i*MM + blk + 3];
    }
}
for (; blk < MM; blk++) for (int i = 0; i < NN; i++)
    result[blk] += src[i] * BB[i*MM + blk];
```

`gcc -O3 -funroll-loops -mavx2 -flra-remat -fsched-spec …` (the exact
Dockerfile recipe) vectorises the outer loop with `vpmuludq` over four
64-bit lanes packed into `ymm0..15`, then stores back four 64-bit results
per outer iteration. Reading the disassembly (`mat_mul @ 0x404830`):

- The 64-bit accumulator `ymm8` is laid out with lane `i` corresponding to
  result position `blk + i`.
- In the broadcast/permute step `vpermd ymm6, ymm13, ymm7` plus the
  high/low load pattern via `vinserti128`, the compiler ends up reading
  `BB[blk + 0], BB[blk + 2], BB[blk + 1], BB[blk + 3]` into lanes 0..3.
  Equivalently, lane 1 and lane 2 are interchanged.
- The `vmovdqu ymmword ptr [r8 - 0x20], ymm8` store dumps the lanes back
  into `result[blk+0..3]` in lane order — so `result[blk+1]` is written
  with what should have been `result[blk+2]` and vice versa.

The scalar tail loop (the `for (; blk < MM; blk++)` portion) is left
untouched, so positions `blk = MM - (MM mod 4) .. MM - 1` are correct. For
`MM = 64` the bug therefore swaps result indices `(1, 2), (5, 6), …,
(57, 58)` and leaves `(60, 61, 62, 63)` alone.

`mat_mul_naive` is a straight scalar loop and is **not** miscompiled, so
the `flag_hash = A · secret_vec` line in `setup_challenge` is correct —
the server has the real `A` and the real `flag_hash`. Only what we *read
back* from `hash_single` / `multi_hash` is permuted.

## Effects on the two query paths

| call | mat_mul result axis | what the bug does to *us* |
| :- | :- | :- |
| `hash_single`: `mat_mul(res, A, v)` | result is the **rows** of `A` (length 64) | each returned 64-vector has its entries (1,2),(5,6),…,(57,58) swapped |
| `multi_hash`: `mat_mul(acc, B_t, a_col)` | result is the **batch index** (length `n`) | for `n = 64` the returned `hashes[1]` and `hashes[2]` (and 5/6, …) are swapped — i.e. we get `A · msgs[2]` where we asked for `A · msgs[1]` |

We attack `multi_hash` because the corruption is in the **batch index**,
not the entry index, so each returned 64-vector is still a full untouched
column of `A` — we just need to relabel which column it is.

## Recovering A correctly

1. Use `multi_hash` with **n = 64 exactly** (pad the last partial batch
   with zero vectors). For `n < 64` `results[i]` is *truncated* (the
   `mat_get_col` reads only `MatRows(res_mat) = n` entries), and for
   `n > 64` it *wraps* into `msgs[i+1]`. `n = 64` is the only clean value.
2. After each batch, swap back the AVX2 lane interchange: swap
   `hashes[4k+1]` ↔ `hashes[4k+2]` for `k = 0 .. (n-1)//4 - 1`
   (i.e. all blocks **except** the tail block, which is computed by the
   scalar loop without the lane swap).
3. With `n = 64`, that's swaps `(1,2), (5,6), …, (57,58)` — 15 pairs per
   batch — and three batches reconstruct `A` exactly.

`mat_mul_naive` was never used for queries (only at startup), so once `A`
is correct the lattice attack proceeds against the real `flag_hash`.

## Lattice setup

Standard primal uSVP on the q-ary kernel lattice plus a Kannan embedding:

1. Split `A = [A1 | A2]`, `A1 ∈ Z_q^{N×N}` (invertible w.o.p.).
2. Particular solution `s0 = [A1^{-1} t' | 0]` where `t' = flag_hash − 5·A·1`.
3. Kernel basis (M × M) rows: `(−A1^{-1}·A2_j, e_j)` and `(q·e_j, 0)`.
4. Centre to `t = secret − 5·1` so `t ∈ [−5, 4]^M` with `‖t‖² ≈ M · 8.5`.
5. Kannan: extend to `(M+1) × (M+1)` with last row `(s0_centered, K=1)`.

| quantity | value |
| :- | :- |
| dimension `d` | 165 |
| determinant | `q^N = 12289^64` |
| `det^{1/d}` | `≈ 38.7` |
| `GH(L')` | `≈ 120` |
| target `‖(t, K)‖` | `≈ 37` |
| target / GH | `≈ 0.31` |

Textbook uSVP — but stock fpylll BKZ-40 without strategies grinds for
minutes and lands at norm ~310. Loading fplll's `default.json`
preprocessing+pruning is the difference between "infeasible" and "45 s".
Homebrew installs it at
`/usr/local/Cellar/fplll/<ver>/share/fplll/strategies/default.json`.

A 20 s heartbeat thread keeps the kitctf SSL proxy from idling us out
during BKZ.

## Solver run

```
$ python3 solve.py braised-crab-marinated-in-braised-noodles-kwb4.gpn24.ctf.kitctf.de 443
[ 17.4s] flag_hash[:5] = [504, 10242, 12264, 8305, 8985]
[ 17.4s] Querying A...
[ 17.8s]   batch 0..63: got 64 hashes (real=64)
[ 18.1s]   batch 64..127: got 64 hashes (real=64)
[ 18.4s]   batch 128..163: got 64 hashes (real=36)
[ 18.4s] A recovered shape=(64, 164)
[ 22.4s] LLL done; Budget remaining: 172.6s
[ 22.4s] BKZ-30 ml=2 …  0.9s
[ 23.3s] BKZ-40 ml=2 …  1.5s
[ 24.8s] BKZ-50 ml=2 …  8.7s
[ 33.5s] BKZ-55 ml=2 …  22.2s
[ 55.7s] BKZ-58 ml=2 …  35.4s
[ 91.1s] BKZ-58 found!
[ 91.1s] verify: True; s[:10]=[0, 5, 1, 8, 8, 4, 7, 2, 0, 0]
Impossible the recipe was a lie.
GPNCTF{coMP1L3rS_aRe_Y0UR_fr1End_7HEY_w0ULd_never}
```
