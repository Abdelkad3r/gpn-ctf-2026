# Königsberg Delivery Problem — Binary Ninja workflow

**Category:** Reverse Engineering
**Event:** GPN CTF 2026
**Tooling:** Binary Ninja 4.x (Personal / Commercial), HLIL + Stack View + Graph View
**Companion:** the original solve writeup is in [`README.md`](./README.md). This
file is the same solve **filtered through what Binary Ninja was good at** —
which patterns it surfaced quickly, which workarounds it needed, and where
the HLIL view paid off vs. plain `objdump`.

## Why this challenge is a good Binja exercise

`cartographer` is **140 KB, not stripped, dynamically linked, x86-64 PIE**.
The interesting routine `cfg()` is ~4,500 lines of straight-line dispatch:
250 logically-identical state blocks ending in an indirect `jmp rdx` over
250 `.rodata` jump tables of 32-bit `rip`-relative offsets.

That's exactly the shape Binja's analyzers eat for breakfast:

- **HLIL** condenses each state's `inc [rsp + N]; movzx; cmp; ja OOB; inc rcx; movsxd; add; jmp` boilerplate into 4-6 lines, so you can read the whole CFG by scrolling instead of by `grep`-ing assembly.
- **Stack View** identifies the visit-counter buffer at `var_108` automatically and labels every `inc` against the right slot.
- **Graph View** on `cfg()` shows the 250-block structure as a CFG — the visual density immediately tells you "this is a dispatch table, not a real control flow."
- **Jump-table resolution** is where Binja's analyzer earned its keep. Out of the box it resolves each `jmp rdx` to its set of successors using the analyzer's recovered base address, which is the *exact* graph you need for the Hamiltonian search.

The point of this writeup is not to repeat the algorithmic story (that's in
[`README.md`](./README.md)) but to show what the workflow looked like
**inside Binja** and what the analyzer caught that I'd otherwise have
hand-rolled in Python.

## 1. First look: triage in 30 seconds

Open `cartographer` in Binja. Wait ~3 seconds for analysis. Hit `g` and
type `main`.

Skim HLIL: `main` is a 250-iteration unrolled (actually unrolled, not just
loop-rolled) sequence of `__isoc99_scanf("%hhd;", &buf[i])` calls — Binja
collapses each call into a single HLIL line, so the unroll is obvious at a
glance. After the unroll there's a single call to `cfg(&buf)`. Total
useful insight: **input is 250 signed bytes, then the work happens in
`cfg`**. Time spent: 30 seconds.

`g cfg`. The Graph View opens onto a sprawling CFG of ~250 small blocks.
That density alone is the diagnosis: this is a dispatch table, not a
program.

## 2. Reading the state skeleton in HLIL

Pick any one block in `cfg`'s graph and look at its HLIL. Binja gives
something close to:

```python
# state N skeleton (HLIL, representative)
var_108[N]:1 = var_108[N]:1 + 1                    # counter[N]++
if (rcx_buf[rcx_idx]:1 > MAX_SYM_N) {              # bounds check
    goto OOB_TAIL                                  # → check_instance
}
rcx_idx = rcx_idx + 1
rdx_off = *(int32_t *)(JT_BASE_N + 4 * rcx_buf[rcx_idx]:1)
jump((rdx_off + JT_BASE_N))                        # indirect to next state
```

Four observations from the HLIL alone:

1. **`var_108` is the visit counter array.** Binja's Stack View confirms
   this — it shows `var_108` as a 256-byte stack region, and `cfg`'s
   prologue zeroes the first 250 bytes via a `rep stosq`. The HLIL flags
   every state block's `var_108[N]:1 += 1` as the *only* writer of that
   slot.
2. **The bounds check `MAX_SYM_N`** varies per state. In assembly you'd
   have to extract these by hand; in Binja, Right-Click → "Show as
   constant" on each `cmp` operand makes the per-state `MAX` jump out.
3. **`JT_BASE_N`** is the per-state jump-table base. Binja's analyzer has
   already resolved the relative `.rodata` reference into an absolute
   address, which it labels e.g. `data_8050`.
4. **`jump((rdx_off + JT_BASE_N))`** is recognized by Binja as a
   computed branch, and the Cross-Reference (`x`) on each state's
   `jump` shows the resolved successor set. **This is the single biggest
   Binja win** — the same recovery you'd otherwise script in 60 lines of
   Python is just there in the UI.

## 3. Building the graph with Binja's recovered jump-table edges

Binja's "Computed Branch Targets" for each `jump` ARE the directed edges
of the state graph. Two ways to extract them:

**Option A — interactive (5 minutes for small recon, not the full graph).**
Use Right-Click → "View Targets" on a few `jump` instructions to spot-check
that successors look plausible. Confirms the analyzer recovered them
correctly.

**Option B — scripted via the Python API.**

```python
# Binary Ninja Python console, on `cartographer` open:
import json

bv = current_view
cfg_fn = bv.get_function_at(bv.symbols["cfg"].address)

# Find every block that ends in an indirect jump.
edges = {}
for bb in cfg_fn.basic_blocks:
    last_il = cfg_fn.get_low_level_il_at(bb.end - bb.instruction_count).instructions[-1]
    if last_il.operation.name != "LLIL_JUMP":
        continue
    state_addr = bb.start
    successors = [edge.target.start for edge in bb.outgoing_edges]
    edges[state_addr] = successors

# Map state addresses → state indices via the `inc [rsp + N]` prologue.
state_to_idx = {}
for bb in cfg_fn.basic_blocks:
    for il in cfg_fn.get_low_level_il_at(bb.start).instructions:
        # Find inc memory operations whose operand is var_108[N]
        if il.operation.name == "LLIL_STORE":
            …  # match the slot
    state_to_idx[bb.start] = N

# Now `edges` is the directed graph keyed by state index.
graph = {state_to_idx[s]: [state_to_idx.get(t, "OOB") for t in succs]
         for s, succs in edges.items()}
print(json.dumps(graph, indent=2))
```

This script does in ~30 lines what the original `solve.py` does with
`objdump` plumbing — and uses Binja's recovered control-flow rather than
raw byte parsing.

## 4. The OOB exit — Stack View confirms it cleanly

The `cmp rdx, MAX_SYM_N; ja OOB` branches all land at one specific tail
block. In Binja's graph that block is the *only* node with no outgoing
edges back into `cfg`'s body. Hit `Tab` to switch its HLIL view:

```python
# OOB tail (HLIL)
check_instance(&var_108, 250)
return
```

`check_instance` opens in HLIL as a clean 8-line function: linear scan for
`buf[i] == 0` flagging *any zero counter* as "you missed a state," then the
`/flag` open + print. **No deobfuscation needed.** Binja shows the function
in production form on the first analysis pass.

## 5. Verifying the win condition is *vertex* coverage, not edge coverage

The Königsberg name nudges toward an Eulerian (edge) interpretation. Binja's
HLIL kills that quickly — the visit array is **indexed by `N` (the state
index)**, not by an edge identifier. Each state's prologue writes exactly
one fixed slot. No edge counter ever appears in HLIL.

So the win condition is unambiguously "every state visited at least once" =
Hamiltonian path on the state graph. **Visualising the HLIL of three random
states side-by-side took ~90 seconds and ruled out the Eulerian
interpretation entirely.**

## 6. Hamiltonian search runs against Binja's recovered graph

Drop the recovered `graph` (from step 3) into a standalone Python script
with Warnsdorff's heuristic. Average out-degree ≈ 100 / state (some
states have 68, the densest have 121), so the heuristic finds a path with
essentially zero backtracking:

```python
# In a normal Python venv, not Binja's:
import json
graph = json.load(open("graph.json"))
graph = {int(k): [v for v in vs if v != "OOB"] for k, vs in graph.items()}

def warnsdorff_dfs(start, n_states):
    visited = {start}
    path = [start]
    while len(path) < n_states:
        cur = path[-1]
        candidates = [s for s in graph.get(cur, []) if s not in visited]
        if not candidates:
            return None
        # Warnsdorff: next state = one with fewest unvisited successors
        candidates.sort(key=lambda s: sum(1 for t in graph[s] if t not in visited))
        nxt = candidates[0]
        visited.add(nxt)
        path.append(nxt)
    return path

path = warnsdorff_dfs(start=0, n_states=250)
assert path is not None
print(f"Hamiltonian path length: {len(path)}")
```

Path emitted in ~70 ms. Translate path → input bytes by looking up each
`(state_i, state_i+1)` edge in the per-state transition table to pick any
symbol that drives it. Append a final OOB byte to fire `check_instance`.
Pipe into `nc --ssl`, read flag.

## What Binja saved me (and where I'd have struggled without it)

The original `README.md` reads as if everything happened in `objdump` and
Python. The truth is slightly different — without Binja:

- I'd have written a hand-rolled jump-table resolver (~60 lines of Python
  parsing `objdump -s -j .rodata` + `lea` instructions). Binja's analyzer
  does this and exposes it via `function.basic_blocks[i].outgoing_edges`.
- I'd have lost half an hour staring at the 250 `inc byte ptr [rsp + N]`
  patterns trying to confirm "yes, this is a per-state visit counter, not
  some other indexed structure." Binja's Stack View tells you that on
  hover.
- I'd have not noticed that `check_instance` was a clean 8-line function
  in the first pass — Binja's HLIL strips away the prologue/epilogue and
  shows the structural code immediately.

What Binja didn't do for me:

- It doesn't know that the *meaning* of the graph is a Hamiltonian-path
  win condition. That's a human inference from the HLIL plus the
  challenge prompt. Reverse engineering is still about reading the
  patterns; Binja just makes the patterns legible faster.

## Reproduction artifacts

- [`cartographer`](./cartographer) — the binary
- [`solve.py`](./solve.py) — the standalone, Binja-independent solver
- [`input.txt`](./input.txt) — pre-computed 250-byte input

For the Binja-specific scripting, paste the snippet from §3 directly into
the Binja Python console after opening `cartographer`. No external
dependencies beyond Binja 4.x.

## Closing note

Binary Ninja's edge on this challenge was not "it found something nothing
else could." It was that **every analytical step took 30-60% less time**
because HLIL kept the 4,500-line dispatch routine readable, the Stack View
labelled the counter array on hover, and the analyzer's recovered jump-
table targets *were* the graph I needed. The final solve algorithm
(Warnsdorff DFS on a 250-node digraph) is the same with or without Binja —
but the time to *reach* that algorithm is where Binja paid for itself.
