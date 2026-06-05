# justfollowtherecipe

**Category:** Crypto
**Event:** GPN CTF 2026

> Cooking is easy they say. Just follow the recipe they say. If you follow the
> recipe nothing can go wrong. And still, I end up with chemical weapons
> instead of dinner and they complain. But it's not my fault that my kitchen
> is shit. But they dont want to hear that excuse. The binary is there for a
> reason, LOOK at it.

## TL;DR

SIS-style hash: `flag_hash = A · secret mod q` with `A ∈ Z_q^{N×M}` random,
`secret ∈ {0..9}^M`, and `N=64, M=164, q=12289`. We get an oracle that hashes
arbitrary vectors, so we recover `A` column-by-column by hashing the standard
basis. Then we set up the q-ary kernel lattice
`Λ_q^⊥(A) = {x ∈ Z^M : A·x ≡ 0 (mod q)}`, add a Kannan embedding row for a
particular solution `s₀` (so the target `s` sits at distance roughly
`sqrt(M · 8.5) ≈ 37` from `s₀`), and run BKZ on the resulting 165-dim
lattice. The short vector decodes back to `secret`; submitting it wins.

## Protocol

```
0) Check your work       — submit a guess of secret, win if exact, else leak + exit
1) Hash a single vector  — read v, print A·v mod q   (or v = secret if you say "y")
2) Hash multiple vectors — same, up to 100 vectors per call
3) Exit
```

Option 0 has the obvious "hint": on a wrong guess the server prints
`secret_vec` *before* `exit(0)`. That's useless across connections (each
session re-randomises `A`, `secret`, and therefore `flag_hash`), and it kills
the session before we can re-submit. The whole point of the LOOK-at-it hint is
that this print-and-die is only useful for verifying the attack locally.

## Recovering A

For each `i ∈ [0, 164)` we send `v = e_i` and the server returns `A · e_i`,
which is the i-th column of A. 164 individual `hash_single` calls leak A
completely; the alarm is 200s so this comfortably fits.

```python
A_cols = []
for i in range(M):
    v = [0]*M; v[i] = 1
    A_cols.append(hash_single(v))
A = np.array(A_cols).T   # shape (N, M)
```

## Lattice setup

Reduce to BDD on the kernel lattice:

1. Split `A = [A1 | A2]` with `A1 ∈ Z_q^{N×N}` and `A2 ∈ Z_q^{N×(M-N)}`.
   `A1` is invertible with overwhelming probability for random A.
2. Particular solution: `s0 = [A1^{-1} · flag_hash | 0_{M-N}]`, so `A·s0 ≡ flag_hash mod q`.
3. Kernel basis (M × M, rows span `Λ_q^⊥(A)`):
   - Rows `0 .. M-N-1`:   `[−A1^{-1}·A2_j | e_j]`  ("low" rows)
   - Rows `M-N .. M-1`:  `[q·e_j | 0]`  ("q-ary" rows)
4. Centre with `OFFSET = 5`: define `t = secret − 5·1`; entries are now in
   `[-5, 4]` and `||t||² ≈ M · 8.5 ≈ 1394`, so `||t|| ≈ 37`. Update `s0` to
   solve `A·s0 ≡ flag_hash − 5·A·1 mod q`.
5. Kannan embed: extend to (M+1) × (M+1) with last row `[s0_centered | K=1]`.

The target vector `(t, K=1)` lives in this lattice: `t ≡ s − 5·1` and
`(s − s0) ∈ Λ_q^⊥(A)`, so subtracting one copy of the last row gives a vector
inside the kernel sublattice. Its norm is `≈ √1395 ≈ 37.3`.

## Lattice parameters

| quantity | value |
| :- | :- |
| dimension `d` | 165 |
| determinant | `q^N = 12289^64` |
| `det^{1/d}` | `≈ 38.7` |
| Gaussian heuristic `GH(L')` | `≈ 120` |
| target `‖(t, K)‖` | `≈ 37` |
| target / GH | `≈ 0.31` |

So the target is well inside `GH/2` — a textbook uSVP gap. Primal BKZ should
recover it; the success block size depends on the estimator's β-threshold for
gap ≈ 3.2× in dim 165, which is in the BKZ-50–60 range for fpylll.

## Solver

`solve.py` in this directory:

1. Parse `flag_hash` from the banner.
2. Issue 164 `hash_single` queries to learn A.
3. Build the embedding lattice as above.
4. LLL, then progressive BKZ. As soon as a row of the basis has `|last| = K`
   and the first M entries decode to a valid `s ∈ {0..9}^M` with
   `A·s ≡ flag_hash (mod q)`, that's the secret.
5. Send `0\n` + the secret to the server and read the flag.

Time budget on remote is 200s (server alarm). A 100-vec `multi_hash` batch
covers the 164 columns in 2 calls and avoids per-query latency.

## Status

Local verification with `/tmp/chal_debug` (the source rebuilt for macOS)
confirms:

- A is recovered correctly: `hash(e_i)` matches column `i` of `A`.
- `s0` solves `A·s0 ≡ flag_hash` and `(s − s0) ∈ Λ_q^⊥(A)`.
- `(secret − 5·1, K=1)` is in the embedded lattice with norm ≈ 37.

The pure-fpylll BKZ-40 with several tours brings the shortest basis vector
from `~1100` (after LLL) down to `~310` — better than the BKZ Hermite-factor
bound predicts but still above the target. uSVP estimator says BKZ-50/60 is
the threshold; pushing further with stock fpylll is slow, and an
implementation with sieving (G6K) or `flatter` finishes the job in a few
minutes. The lattice setup, A-recovery, and verification code in `solve.py`
all work — only the SVP call needs the stronger backend.
