# com-petition

**Category:** Crypto
**Event:** GPN CTF 2026

> I want to play a game...

## TL;DR

The server plays 100 rounds of rock-paper-scissors. Each round we commit to
our move first, then the server reveals theirs, then we open our commitment.
We win the flag if we beat (or draw and then beat) the server every round.

The commitment scheme is `sha256(r1 || message || r2)` with **two** user-supplied
nonces. The verifier never enforces a length on `r1` or `r2`, so we can shift
the message boundary inside the hash input: a single hash like
`sha256("rockpaperscissors")` opens to **any** of the three moves by choosing
which slice we call `message`. After seeing the server's pick we open to the
counter.

**Flag:** `GPNCTF{rock_paper_scissors_lizard_spock}`

## The bug

```python
def verify(commitment, message, unveil_info):
    r1, r2 = unveil_info  # two is better than one, right?
    return commitment == sha256(r1 + message + r2).digest()
```

`r1` and `r2` are independent byte strings. The hash input is just their
concatenation with `message` sandwiched between them — the verifier never
checks where `message` *starts* inside the preimage, only that the bytes
line up somewhere. So a preimage that contains all three move names lets us
"slide" the message window.

Use the preimage `rockpaperscissors`:

| message | r1 | r2 | r1 ‖ message ‖ r2 |
| :- | :- | :- | :- |
| `rock` | `""` | `paperscissors` | `rockpaperscissors` |
| `paper` | `rock` | `scissors` | `rockpaperscissors` |
| `scissors` | `rockpaper` | `""` | `rockpaperscissors` |

All three hash to the same value.

## Defeating the replay check

```python
elif com in already_seen and already_seen[com] != your_choice:
    print("Something fishy is going on here. What are you doing?")
```

So a given commitment is locked to whichever move it first opened to. Fine —
prepend a per-round nonce to the preimage. We commit
`sha256(str(round) + "rockpaperscissors")` for round `i`, each commitment is
fresh, and we keep our freedom to open to anything.

## Strategy

After the server reveals its move we open to the **beat** of that move:

| server | we open to |
| :- | :- |
| `rock` | `paper` |
| `paper` | `scissors` |
| `scissors` | `rock` |

100 wins → flag.

## Run

```
$ python3 solve.py <host> <port>
...
Round 99: server=rock we=paper ✓
flag: GPNCTF{rock_paper_scissors_lizard_spock}
```
