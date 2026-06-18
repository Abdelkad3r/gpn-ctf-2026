# The LLM harness behind these writeups

**Category:** Meta — submitted for the *Best LLM harness writeup* prize.

This isn't about *one* challenge. It's about the workflow that produced the
other 19 writeups in this repo — what the harness around Claude actually
looked like during a 24-hour CTF, what it was good at, where it
embarrassed me, and which design choices I'd keep.

## TL;DR

Claude Code (Opus 4.x, 1M-context build) driving a small Bash/Python tool
sandbox, with **parallel sub-agents** for independent exploration and a
**single human in the loop** as referee. The harness was load-bearing for
five of the six categories — but it was wrong in load-bearing ways too,
including ~6 hours sunk into the wrong solve direction on `guess-the-taste`
before the human stopped it.

The thing worth writing about is **when the harness was wrong**, not when
it was right.

## The setup

```
┌───────────────────────────────────────────────────────────────────┐
│  human (me)  ──orchestrates──▶  Claude Code (Opus 4.x, 1M ctx)    │
│                                            │                      │
│                                            ├─ Bash sandbox        │
│                                            ├─ Read / Edit / Write │
│                                            ├─ Explore sub-agent   │
│                                            └─ general-purpose     │
│                                               sub-agents          │
└───────────────────────────────────────────────────────────────────┘
```

A few non-obvious choices that mattered:

- **Sub-agents are the unit of parallelism, not threads.** When I needed to
  scan a 23 MB `vmlinux` for what changed (`stupidcontract`), I'd kick off
  three sub-agents in one message: one running `strings | sort | diff`, one
  running `nm -D`, one running `bindiff`-style section sizing. Each spends
  its own context window so the main conversation never has to see the
  4 MB of `strings` output.
- **Scratch dirs are part of the harness.** `~/gpn/<challenge>/work/` is
  where Sage scripts, intermediate hex dumps, partially-tested exploits
  live. The harness treats them as cache: when a sub-agent comes back
  saying *"I implemented `multi_coppersmith.sage`, here's a 12-line
  summary"*, I can read the file later instead of asking again.
- **No agentic shopping list.** I never gave Claude a high-level
  *"solve every challenge"* prompt. Each challenge starts with a fresh
  conversation, the handout files, and a one-sentence framing. Long-context
  agents start hallucinating a coherent narrative across challenges if you
  don't.
- **Memory file pinned in CLAUDE.md, not in the chat.** Repeated patterns
  (`use lowercase hex offsets, never `cd` inside Bash commands, prefer
  reading specific file ranges over slurping`) live in a
  `~/.claude/CLAUDE.md` so each new session starts with the same posture.

## What the harness was great at

### Reading a lot of code fast

`reverse/koenigsberg-delivery-problem` is 4500 lines of repetitive
state-machine dispatch. The path the harness took:

1. Ask for **structure first**: *"objdump -d cartographer | head -200,
   then describe the per-state pattern in one paragraph."*
2. Validate the pattern by **grep-counting** the same instruction across
   the whole disassembly (`250 states ⇒ 250 inc byte ptr [rsp+N]`). One
   sub-agent does this, returns a one-line confirmation, doesn't dump
   the matches into the main context.
3. Now I trust the pattern; ask Claude to write a parser. The parser is
   wrong on the first try (it misses state 0 because state 0 uses `rax`
   instead of `lea`). The fix is a single follow-up message.

Total wall-clock: ~25 minutes. The actual reading happened in sub-agent
context windows that I never saw.

The same shape worked for `reverse/autocooker` (16 KB binary, four
involution pipelines), `reverse/specCTF` (43 KB, recognizing splitmix64
from three xor-shifts and a multiply), and `crypto/justfollowtherecipe`
(reading the AVX2 inner-product loop and noticing it permutes lanes).

### Cheap statistical recon

`misc/organized` is a 7.65 MB file that looks like noise. The trick is
that bit-density per 12,500-byte window is *trinary*, not binary. The
harness got there in three steps:

1. *"Is this image data?"* — Claude renders 25 candidate widths at 1 bpp
   in a sub-agent, eyeballs them, reports "all show horizontal stripes."
2. *"What's the smallest periodic structure in popcount?"* — sub-agent
   computes per-window popcount means and run-lengths, comes back with
   "every run is a multiple of 125 windows = 12,500 bytes."
3. *"Three peaks or two?"* — 200-bin histogram of per-block popcount.

That's the whole reverse-engineering of the carrier. The human's job is
picking the *next* question, not running the analysis.

### Parallel hypothesis testing

`web/pharry`'s PHP source admits two attack surfaces (`md5_file` /
`file_get_contents`) and three failure modes (PHP 7.4 PHAR remote
restrictions, `data://` nesting, `phar://https://`). I dispatched three
sub-agents in one message — *"verify that `phar://data://` works in PHP
7.4"*, *"verify `phar://https://` works"*, *"check what `md5_file` does
on an HTTP URL when the response is empty"* — and got three independent
answers in parallel. Two were dead ends, one was the kill chain. Without
parallelism that's three serial round-trips, each lasting a few minutes
because the sub-agent has to actually run PHP.

## What the harness was bad at

### Committing to the wrong direction

`crypto/guess-the-taste` had two versions floating around in my workspace.
One was an MIHNP-style "modular inverse hidden number problem" with a
1000-bit prime, 570 low bits zeroed in the inverse samples. The other was
the actual GPN challenge: an NTRU instance where the ciphertext is just
never reduced mod q, so `c mod p == m` directly.

I gave the harness the MIHNP script. Claude leapt at it, recognised the
Xu-Hu-Sarkar lattice attack, started building it, and over the next ~6
hours produced this:

```
~/gpn/taste/work/
  bench.sage  best.sage  bivar_attack.sage  bivar_large_m.sage
  brute_short.sage  double_poly.sage  dp_sim.sage  elim.sage
  elim_simple.sage  explore_threshold.sage  fast_eim.sage
  fast_scan.sage  five_sub.sage  focus.sage  four_sample.sage
  full5.sage  lc_scan.sage  m3_scan.sage  m45_scan.sage
  m4_scan.sage  multi_coppersmith.sage  multi_full.sage
  multi_g.sage  multi_prefix.sage  multi_short.sage
  …
  xhs_attack.sage  xhs_full.sage  xhs_proper.sage  xhs_v2.sage
  xhs_v3.sage
```

70+ unique Sage scripts. Five "xhs" iterations (Xu-Hu-Sarkar) that never
recovered the secret. The harness *can't tell from inside* that it's
attacking the wrong challenge — it sees a paper that promises the attack
should work, a script that doesn't, and infers *"more parameters."* Each
sub-agent reports modest progress; the human sees "still iterating." Six
hours of compute and one human cup of coffee later, the actual challenge
turned out to be a one-line `mod p` away from the flag.

**The corrective move that should have happened sooner:** when a single
sub-agent has rebuilt the same attack five different ways without
recovering the secret, stop and re-read the challenge handout. The
harness does not naturally generate this "step back" reflex. The human
has to.

### Confident wrong code

In `crypto/easy-dsa`, Claude wrote the first ECDSA-nonce-reuse solver and
recovered a `d` that *didn't match the public key*. Confident commentary:
*"Sign of the recovered private key may be flipped, try negating."*
Negating worked. But Claude wrote the entire solver before noticing the
sign ambiguity, when the canonical write-up of nonce reuse mentions it in
the third sentence. Treating Claude's first-pass code as a draft rather
than a finished solver caught this in two minutes; treating it as
finished would have lost an hour.

### Hallucinated APIs in less-common ecosystems

The `web/restaurant-builder` exploit hangs on a specific behavior of
Pydantic v2: `create_model("X", x="some_string")` treats `"some_string"`
as a `ForwardRef` that gets `eval`-ed when `model_json_schema()` is
called. Claude knew the general shape but mis-named two helpers
(`pydantic.create_model_from_typeddict`, which doesn't exist in v2; and
`get_type_hints(..., include_extras=True)` not being the path the v2
schema builder takes). I caught both by `grep`-ing the installed package.
Less popular libraries: trust nothing without `grep`-confirmation.

### Anything graphical without a screenshot

`misc/knitted-flag` ends with a 978×20 bitmap rendered to a PNG that, by
eye, reads `GPNCTF<...>`. Reading **`{` vs `<`** and **`O` vs `0`** is a
font-disambiguation task Claude cannot do without literally seeing the
image. I had to take the PNG, open it, decide by eye that the angle
quotes were braces and the diamond glyphs were zeros, and feed that back.
The harness loop is still useful — it built the parser, picked the
rotation, produced the PNG — but the final "is this a 0 or an O" step is
pure carbon.

## When to kill a research direction

The MIHNP debacle taught one rule the rest of the CTF respected:

> If a sub-agent has produced **N independent re-implementations of the
> same attack** without progress, the bug is upstream of the attack
> code.

For `crypto/justfollowtherecipe` we hit this early. fpylll BKZ-40 with
defaults landed at norm ~310 — way above the GH bound, no flag.
Iteration N+1 would have been "try BKZ-50, then 60, then change pruning."
The right move was to step back and ask: *"is the input `A` actually the
real `A`?"* — which led to the AVX2 lane-swap discovery and a 45 s solve.

For `reverse/stupidcontract` it took the form of: *"the verifier rejects
my program at load time. Have I read every patched-vs-unpatched diff?"*
The answer was a five-string deletion that the harness almost missed
because the gunzipped vmlinuxes differed in 99% of bytes (section layout
shift) and the obvious `diff -q` returned uninformative.

For `web/tinyweb` it was: *"every obvious XSS angle is blocked. Is there
a non-XSS sink in this response?"* — which led to the `Link: rel=stylesheet`
CSS-injection / attribute-selector path.

The shape is always the same: the harness will happily refine a wrong
plan forever. The human's only essential job is to *kill plans*.

## Specific harness configurations that paid for themselves

These are concrete configurations I'd port to any future CTF harness.

### Read-budget discipline

Bash output that exceeds ~50 KB blows the main context's coherence by
the end of the day. The harness saves output to files and reads
**byte ranges** instead:

```
sub-agent: tshark -r kitchen_log.pcap … > /tmp/syslog.txt
sub-agent: head -n 20 /tmp/syslog.txt | summarize structure
main:     [reads only the summary, never the 12k lines]
```

For `misc/double-fried` (115 syslog packets) the main thread saw maybe
600 bytes of pcap output the entire time.

### Sub-agent reports under 200 words

Every sub-agent prompt ends with *"report in under 200 words."* This
isn't aesthetic — it's a forcing function for the sub-agent to extract
*conclusions* instead of dumping raw data into the main context. The
sub-agent can write any amount to disk; what comes back into the
parent's context is a paragraph.

### Plans, not chat

Non-trivial work goes through an explicit Plan (the harness has an
`ExitPlanMode` ritual). The plan is two paragraphs: what we're doing
and what we're not. Reading the plan back to myself before approving
catches half the wrong directions. The MIHNP plan said *"recover
`a` from MIHNP samples"* — and *should* have said *"verify the handout
matches the server before recovering anything."* That one missing line
is six hours.

### Per-challenge memory, not per-session

`/Users/apple/.claude/projects/-Users-apple-gpn/memory/` holds short
notes between sessions — what was tried, what worked, what the
challenge was actually about once we figured it out. The memory **does
not** contain the writeups themselves; those live in this repo. The
split is: memory = "next-time-you-look-here, you'll need to know X";
repo = "next-time-anyone-reads-this, here's the full solve."

## Numbers, for what they're worth

| Challenge                       | Wall-clock (rough) | Sub-agents | Notes                                              |
|--------------------------------|--------------------:|------------:|----------------------------------------------------|
| `crypto/com-petition`          |             45 min |           2 | Sub-agent ran 100 rounds; main wrote the proof     |
| `crypto/easy-dsa`              |          2.5 hours |           4 | Sign ambiguity caught on first verify              |
| `crypto/guess-the-taste`       |           6 hours… |          9+ | …of MIHNP scratch, then 8 min on the real NTRU bug |
| `crypto/justfollowtherecipe`   |          3.5 hours |           5 | 45 s of BKZ; the rest was finding the lane swap    |
| `misc/customer-service`        |          1.5 hours |           3 | holpy reading is human-on-LLM                      |
| `misc/double-fried`            |             40 min |           2 | tshark sub-agent; the R/F split is obvious once seen|
| `misc/knitted-flag`            |          1.5 hours |           3 | Final `{`-vs-`<` disambiguation is human-eye       |
| `misc/organized`               |          2.5 hours |           4 | Three-peak histogram was the key sub-agent output  |
| `misc/supercat`                |             20 min |           1 | Race window large; first try landed                |
| `pwn/recipe-for-disaster`      |             15 min |           1 | `gets()` is `gets()`                               |
| `reverse/autocooker`           |             40 min |           2 | Four involutions; sub-agent confirmed each is self-inverse |
| `reverse/koenigsberg-…`        |           2 hours  |           3 | Warnsdorff DFS suggestion came from sub-agent      |
| `reverse/leftovers`            |          3.5 hours |           6 | CDS file format is the cost; bytecode decode was fast |
| `reverse/leftover-leftovers`   |             45 min |           2 | One-byte patch once the parent challenge was solved |
| `reverse/specCTF`              |          1.5 hours |           3 | r14/r15 ABI trick was a "wait, what?" moment       |
| `reverse/stupidcontract`       |           4 hours  |           5 | bzImage unpacking was 70% of the time              |
| `web/pharry`                   |           2 hours  |           5 | Parallel hypothesis-testing on PHP behavior        |
| `web/restaurant-builder`       |          1.5 hours |           4 | Pydantic v2 hallucination caught early             |
| `web/tinyweb`                  |          2.5 hours |           3 | CSS exfil rate-limited by 30s `await sleep`        |

Sub-agent counts are upper bounds — I lost track during long sessions.

## What I'd change next time

1. **Force a "is this the right challenge?" gate.** Before any
   solve-direction commitment, the harness should verify that the
   handout file matches what the live service produces. The MIHNP/NTRU
   split was preventable by a single `nc host port | head` ran against
   the script's expected I/O shape.

2. **Better cross-session memory hygiene.** I had memory files from a
   prior CTF still loaded by default; some of them subtly biased
   Claude toward a Coppersmith framing on MIHNP. The default should
   be *no* cross-CTF memory unless explicitly imported.

3. **Per-challenge directory templates.** Every challenge ended up with
   `work/`, `solve.py`, `README.md` — but the structure emerged
   ad-hoc. A `gpn-ctf init <category> <name>` command would have
   saved 10 minutes per challenge and given every writeup the same
   skeleton from the start.

4. **Pre-commit lint on the writeups themselves.** A second sub-agent
   reading the freshly-written README and complaining about
   un-justified claims (*"you say the verifier was removed — quote
   the diff that shows it"*) would catch about half the rough edges
   before the human ever reads them.

## Coda

The thing I want to leave with anyone building an LLM-driven CTF harness
is that the *interesting* engineering isn't getting Claude to write a
fpylll solver. It's getting Claude to **stop** writing fpylll solvers
and re-read the problem. The harness has to make stepping-back cheap and
default-friendly, or you will burn an evening on the wrong attack and
publish a writeup that says the real solve was eight lines.

Everything else in this repo is a footnote to that.
