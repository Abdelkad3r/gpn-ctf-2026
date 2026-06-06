# customer-service

**Category:** Misc
**Event:** GPN CTF 2026

> The customer is always right. RIGHT? Experienced staff will tell you
> that customers are always worst case users. Just last week one customer
> proclaimed that pineapple does not belong on sushi pizza. Yeah I know,
> how could he? But the customer is always right. My friend fears for his
> sanity. So please help me work out the logic details for such an
> argument.
>
> `ncat --ssl grilled-souffle-beside-roasted-tomato-juss.gpn24.ctf.kitctf.de 443`

## TL;DR

`checker.py` is a thin shell around [holpy](https://github.com/Mr-Pine/holpy),
an LCF-style higher-order-logic proof assistant. The server reads a hex
blob of JSON, runs each item through holpy's monitor, and prints the flag
if a `thm` item ends up with conclusion `false`, no hypotheses, no
assumptions.

It pretends to forbid axioms — but the guard is broken three ways:

1. `report.get_axioms() == 1` compares a list to the integer `1`. That
   branch can never fire, so each item is silently allowed **one** axiom,
   not zero.
2. `Theorem.get_extension()` strips the proof, so even valid `thm` items
   are re-added as axioms by `checked_extend`. The "≤1 axiom" budget
   already pays for the soundness of every successful theorem.
3. The win condition only checks `concl.is_const("false")` — by name. The
   loader runs against an `EmptyTheory` that has no `false` in scope. So
   we declare our own opaque `false : bool` constant and the name match
   accepts it as if it were logical falsity.

Three items — declare `false`, axiomatize it, point a one-line proof at
the axiom. Pop the flag:

```
GPNCTF{Ex-Un4-Line4-VACu4-sEqui7ur-QuOdl1b3t}
```

*Ex contradictione quodlibet* — "from a contradiction, anything follows."
The customer says pineapple belongs on sushi pizza; the kitchen agrees;
the universe explodes.

## The oracle

`checker.py`, ~115 lines, in full:

```python
hex_proof = input("give me your hex proof")
data = json.loads(bytes.fromhex(hex_proof).decode("utf-8"))

with theory.fresh_theory():
    for imp in data.get("imports", []):
        basic.load_theory(imp)

    for raw in data.get("content", []):
        item = items.parse_item(raw)
        if item.error: continue

        if item.ty == "thm":
            result = monitor.check_proof(item, rewrite=False)
            if result["status"] in ["OK", "ProofOK"]:
                exts = item.get_extension()
                report = theory.thy.checked_extend(exts)
                if len(report.get_axioms()) > 1: sys.exit(1)
                elif report.get_axioms() == 1 and item.ty != "thm": sys.exit(1)
                thm = theory.thy.get_theorem(item.name)
                if theorem_proves_false_unconditioned(thm):
                    win()           # prints the flag
                sys.exit(0)
            else: sys.exit(1)
        else:
            exts = item.get_extension()
            report = theory.thy.checked_extend(exts)
        if len(report.get_axioms()) > 1: sys.exit(1)
        elif report.get_axioms() == 1 and item.ty != "thm": sys.exit(1)
```

…with the comment `# HELP WTF IS THIS IG` over the `thm` branch and
`# ig we addd it ??` over the `else`. The author is telling you they
glued this together and they're not sure why it works either. They are
correct to be unsure.

And the win check:

```python
def theorem_proves_false_unconditioned(thm):
    concl_str = str(thm.concl).strip().lower()
    is_false = (thm.concl.is_const("false") or
                concl_str == "false" or concl_str == "?false")
    return is_false and len(thm.assums) == 0 and len(thm.hyps) == 0
```

## Bug 1 — `list == 1`

```python
if (len(report.get_axioms())) > 1: …                 # OK, length check
elif report.get_axioms() == 1 and item.ty != "thm": … # dead
```

`ExtensionReport.get_axioms()` returns `self.axioms`, a list of
`(name, info)` tuples. `[] == 1`, `[("x", t)] == 1` — both `False`. The
`elif` is unreachable. So the real budget is *up to one* axiom per item,
not zero.

## Bug 2 — every `thm` is also an axiom

`server/items.py::Theorem(Axiom)` inherits `get_extension()` from `Axiom`:

```python
def get_extension(self):
    res = [extension.Theorem(self.name, Thm(self.prop))]   # prf=None!
    …
```

Then `kernel/theory.py::checked_extend`:

```python
elif ext.is_theorem():
    if ext.prf:
        self.check_proof(ext.prf)
    else:                                  # this branch
        ext_report.add_axiom(ext.name, ext.th)
    self.add_theorem(ext.name, ext.th)
```

So even a `thm` item that just had its proof checked by
`monitor.check_proof` is re-installed as an axiomatic theorem and ticks
the axiom counter. The `>1` bound is the entire safety net, and it allows
exactly this.

## Bug 3 — a homemade `false`

The loader runs in `fresh_theory()` which calls `EmptyTheory()`:

```python
thy.add_type_sig("bool", 0)
thy.add_type_sig("fun", 2)
thy.add_term_sig("equals", …)
thy.add_term_sig("implies", …)
thy.add_term_sig("all", …)
```

That's it. No `false`, no `not`, no `&`. The real `false` constant lives
in `library/logic_base.json`, which **isn't shipped** in the installed
wheel — `imports: ["logic_base"]` errors with
`No such file or directory: '/challenge/.venv/.../library/'`.

`theorem_proves_false_unconditioned` doesn't notice. It just calls
`thm.concl.is_const("false")` — true for **any** `Const("false", _)`.
So we declare a `false : bool` of our own with `def.ax`.

## The exploit

```json
{
  "imports": [],
  "content": [
    { "ty": "def.ax",  "name": "false",             "type": "bool" },
    { "ty": "thm.ax",  "name": "customer_is_right", "vars": {}, "prop": "false" },
    {
      "ty": "thm", "name": "pwn", "vars": {}, "prop": "false", "num_gaps": 0,
      "proof": [
        { "id": "0", "rule": "theorem", "args": "customer_is_right",
          "prevs": [], "th": "⊢ false" }
      ]
    }
  ]
}
```

Walking the loop:

| # | Item                              | `len(get_axioms())` after | `>1`? |
|---|-----------------------------------|---------------------------|-------|
| 0 | `def.ax false : bool`             | 0 (constants don't count) | ok    |
| 1 | `thm.ax customer_is_right : false`| 1 (axiom)                 | ok    |
| 2 | `thm pwn` with `theorem` rule     | 1 (Bug 2)                 | ok    |

For item 2, `monitor.check_proof` enters the `item.proof` branch,
parses one step, and looks it up by `kernel/theory.py:339`:

```python
if seq.rule == "theorem":
    res_th = self.get_theorem(seq.args)   # customer_is_right
```

`res_th` is `Thm(false)` with empty hyps. The advertised `seq.th =
"⊢ false"` matches, status is `ProofOK`. `checked_extend` then re-adds
`pwn` as a no-proof theorem (Bug 2), the axiom count is 1 (Bug 1 lets it
slide), `get_theorem("pwn")` returns `Thm(false)` — `concl.is_const
("false")` ✓, `hyps == ()` ✓, `assums == ()` (an unconditioned `false`
has no implication prefix) ✓.

`win()` opens `./flag.txt`.

## Running it

```bash
hex=$(python3 -c "print(open('exploit.json').read().encode().hex())")
echo "$hex" | openssl s_client -quiet \
  -connect grilled-souffle-beside-roasted-tomato-juss.gpn24.ctf.kitctf.de:443
```

```
give me your hex proof✓ Proof check passed
Congratulations! You've found the flag: GPNCTF{Ex-Un4-Line4-VACu4-sEqui7ur-QuOdl1b3t}
```

(Or run `solve.sh` — it does the same thing.)

## Why it was solvable at all

In a real LCF kernel none of this would land. The two real load-bearing
mistakes are:

- The author's *intent* was "you can ship definitions and theorems but
  not raw axioms" — they tried to enforce that on the report. But
  `checked_extend` itself was designed around the assumption that a
  `Theorem` extension *with* a proof is fine, and a Theorem *without* a
  proof is by definition an axiom. `Theorem.get_extension()` always
  produces the second flavor — the proof never makes it past
  `monitor.check_proof`. So every `thm` accepted by the monitor is then
  re-typed as an axiom by the kernel. Fixing the `list == 1` typo
  would *also* lock out every valid theorem; the real fix is to thread
  the checked proof into the extension.
- The win check uses a string-name comparison instead of comparing the
  conclusion term to the actual logical `false` in scope. Since the
  loader runs in `EmptyTheory()` and the `library/` directory isn't
  shipped, there *is* no logical false to compare to — any opaque
  `Const("false", bool)` wins.

The flag name spells it out: `Ex-Un4-Line4-VACu4-sEqui7ur-QuOdl1b3t` →
*ex una linea vacua sequitur quodlibet* — "from one empty line, anything
follows." The "one empty line" is the lone allowed axiom.
