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
particular solution `s₀`, and run BKZ on the resulting 165-dim lattice with
fplll's preprocessing+pruning strategies (without strategies BKZ-50 alone gets
nowhere; with them it lands the target in ~50s). The short vector decodes
back to `secret`; submitting it wins.

The "LOOK at the binary" line is loud-bearing: the in-house `mat.c` has a
ragged matrix-storage convention that creates a real off-by-one in
`multi_hash` — the printed hash for the i-th query has length `n`, not `N`,
and the buffer the server reads from spills into the next hash. With
`batch_size = 64` everything lines up; with `batch_size = 100` you walk away
with a *different* `s` that still satisfies `A·s ≡ flag_hash mod q` and the
server happily prints back the real secret to laugh at you.

## Protocol

```
0) Check your work       — submit a guess of secret, win if exact, else leak + exit
1) Hash a single vector  — read v, print A·v mod q   (or v = secret if you say "y")
2) Hash multiple vectors — same, up to 100 vectors per call
3) Exit
```

Option 0 has the obvious "hint": on a wrong guess the server prints
`secret_vec` *before* `exit(0)`. That's useless across connections (each
session re-randomises `A`, `secret`, and `flag_hash`), and it kills the
session before we can re-submit. The print-and-die is useful for verifying
attacks locally though.

## Recovering A

For each `i ∈ [0, 164)` we send `v = e_i` and the server returns `A · e_i`,
which is the i-th column of A. Doing it 164 times by `hash_single` is the
obvious route. To save round-trips we'd like to batch via option 2 — but
that's where the binary bug bites.

### The `multi_hash` size bug

`multi_hash(n, msgs)` builds a temporary `n × N` result via two transposes,
then returns `results[i] = mat_get_col(res_mat, i)`. The catch: `res_mat`
was created with `create_matrix(N, n)`, which the library lays out with
`res_mat->rows = n`, `res_mat->cols = N`. `mat_get_col` then sizes the
column vector by `MatRows(res_mat) = n`:

```c
struct vec32 *col = create_vec32(MatRows(mat));   // size n, not N
for (i = 0; i < MatRows(mat); i++)               // i in [0, n)
    Vec(col, i) = Mat(mat, i, col_index);         // res_mat->data[col_index * N + i]
```

Concretely, `res_mat->data` is `n * N = n * 64` u32s flat. The "column i"
that gets read out is `data[i*64 .. i*64 + n - 1]`. When `n == 64` that's a
clean window over `(A · msgs[i])[0..63]`. When `n != 64` the window slides
across rows:

| `n` | what we get for hash `i` |
| :- | :- |
| `n < 64` | only the first `n` entries of `A · msgs[i]` (rest never printed) |
| `n == 64` | exact `A · msgs[i]` ✓ |
| `n > 64` | `(A · msgs[i])[0..63]`, then `(A · msgs[i+1])[0..n-65]` glued on |

`print_vector32` prints `vec->size = n` ints, so each "hash line" has length
`n` on the wire. With `n = 100` and a parser that grabs 64 ints per line,
you end up reading hash `i`'s entries 36..99 (the second half of column i)
plus the first 36 entries of column `i+1` — i.e. a smear of two adjacent
columns. The recovered `A` is the real `A` with columns `(4k+1, 4k+2)`
swapped, and BKZ then "solves" for `π(secret)` where `π` is the same swap.
That candidate satisfies `A_recovered · s = flag_hash mod q` so local
verification passes, but the server's exact `secret_vec` check fails and it
prints out the real secret. We literally saw this in the wild:

```
verify: True; s[:10]   = [3, 1, 0, 5, 5, 7, 8, 5, 8, 2]
Wrong guess! Try again.
secret[:10]            = [3, 0, 1, 5, 5, 8, 7, 5, 8, 7]
```

`mine[1] = secret[2]`, `mine[2] = secret[1]`, `mine[5] = secret[6]`,
`mine[6] = secret[5]` — exactly the predicted column swap pattern.

### The fix

Send `multi_hash` with `n = 64` only. Pad the last batch with zero vectors
to keep `n` at 64. 164 columns → three batches of 64 (the third one carries
36 real + 28 dummies). Two SSL round-trips later, `A` is recovered exactly.

## Lattice setup

Reduce to BDD on the kernel lattice:

1. Split `A = [A1 | A2]` with `A1 ∈ Z_q^{N×N}` and `A2 ∈ Z_q^{N×(M-N)}`.
   `A1` is invertible with overwhelming probability for random A.
2. Particular solution: `s0 = [A1^{-1} · t' | 0_{M-N}]` where
   `t' = flag_hash − 5·A·1` (after centring). So `A·s0 ≡ flag_hash mod q`.
3. Kernel basis (M × M, rows span `Λ_q^⊥(A)`):
   - Rows `0 .. M-N-1`:   `[−A1^{-1}·A2_j | e_j]`  ("low" rows)
   - Rows `M-N .. M-1`:  `[q·e_j | 0]`  ("q-ary" rows)
4. Centre with `OFFSET = 5`: define `t = secret − 5·1`; entries are in
   `[-5, 4]` and `||t||² ≈ M · 8.5 ≈ 1394`, so `||t|| ≈ 37`.
5. Kannan embed: extend to `(M+1) × (M+1)` with last row `[s0_centered | K=1]`.

The target vector `(t, K=1)` lives in this lattice — `t ≡ s − 5·1` and
`(s − s0) ∈ Λ_q^⊥(A)` — and its norm is `≈ √1395 ≈ 37.3`.

| quantity | value |
| :- | :- |
| dimension `d` | 165 |
| determinant | `q^N = 12289^64` |
| `det^{1/d}` | `≈ 38.7` |
| Gaussian heuristic `GH(L')` | `≈ 120` |
| target `‖(t, K)‖` | `≈ 37` |
| target / GH | `≈ 0.31` |

Textbook uSVP gap.

## BKZ schedule

fpylll's `BKZ.reduction` *without* a strategies file is anaemic here: BKZ-40
with `max_loops=12` still leaves the shortest at ~310 after 6+ minutes. The
trick is to pass the fplll-shipped `default.json` (preprocessing tours plus
pruning) — Homebrew installs it at
`/usr/local/Cellar/fplll/<ver>/share/fplll/strategies/default.json`. With
strategies on, the progression on a single instance is:

```
LLL                                 2 s    → norm 1100
BKZ-20  ml=4                        2 s    → 545
BKZ-30  ml=4                        3 s    → 408
BKZ-40  ml=4                        2 s    → 340
BKZ-50  ml=8     (GH_BND)          36 s    → 34   ← target
```

About 45 s of CPU per attempt. Comfortable inside the 200 s alarm. Some
instances need BKZ-55/60 (still <90 s). The remote SSL connection is
preserved across BKZ by a 20 s heartbeat thread that fires a no-op
`multi_hash(n=1, [0,..,0])` to stop the kitctf proxy from idling us out.

## Solver

`solve.py`:

1. Parse `flag_hash` from the banner.
2. Recover `A` via three `multi_hash(64)` batches (with zero padding for
   the third).
3. Build the embedding lattice as above.
4. LLL + progressive BKZ with `strategies=…/default.json`, scanning rows for
   one whose last coord is `±K` and whose first M entries decode (after
   `+OFFSET` and a `±` flip) to a `s ∈ {0..9}^M` with `A·s ≡ flag_hash`.
5. Send `0\n` + the secret, read the flag.

```
$ python3 solve.py <host> <port>
[ 49.3s] BKZ-50 found!
[ 49.3s] verify: True; s[:10]=[3, 0, 1, 5, 5, 8, 7, 5, 8, 7]
Impossible the recipe was a lie.
GPNCTF{…}
```
