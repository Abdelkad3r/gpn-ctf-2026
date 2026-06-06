# double-fried

**Category:** Misc
**Event:** GPN CTF 2026

> I was planning to go to dinner with a friend but something felt off.
> Can you help me sort everything out?

## TL;DR

`kitchen_log.pcap` is 115 UDP syslog packets (port 514) from a chef logging
its kitchen. Two RFC 5424 streams are interleaved into the same flow,
distinguished only by their `MSGID` field:

- `R####` — the **R**eal stream: the chef's narrative, including the flag
  sent **one character per packet** starting at `R0016`.
- `F####` — the **F**ries decoy: a parallel stream spelling out a taunt.

UDP reorders the two against each other on the wire, so reading the pcap
top-to-bottom looks like noise. Split on `R`/`F`, sort each by its 4-digit
sequence number, and the R stream's char-per-packet block is the flag.

**Flag:** `GPNCTF{NiC3, YOu F0UnD OUt WH0 Did No7 8ELON6 tH3RE}`

## Recon

```
$ capinfos kitchen_log.pcap
Number of packets:   115
File encapsulation:  Ethernet
Capture duration:    57.493224 seconds

$ tshark -r kitchen_log.pcap -q -z io,phs
frame > eth > ip > udp > syslog        frames:115 bytes:12679
```

Everything is `10.0.0.10:40100 → 192.168.1.1:514`, all syslog. No TCP, no
DNS, no HTTP — just one long monologue.

The first packets read sensibly:

```
R0001 KITchen ready!
R0002 Awaiting orders
R0003 Got order for a loaded binary
R0004 Order delivered!
R0005 WARNING: Sous chef injured
…
R0013 Received an order for a very delicious flag :)
R0014 For security I'll send out the flag char by char
R0015 Have fun with it
```

Then from frame 17 onward each packet carries one printable character —
but reading them in arrival order gives `GNPTC{FN0tN i3C ,YuO4 …`. The
characters of `GPNCTF{` are present, in pairs that look swapped. The
challenge title — **double**-fried — and the hint *"sort everything out"*
point straight at the cause: two streams, double-counted.

## The two streams

Each syslog payload is RFC 5424 framed:

```
<14>1 2023-11-15T00:00:42.229Z kitchen-01 kitchen 1337 R0016 - G
                                                       ^^^^^
                                                       MSGID
```

Sequence IDs cluster into two interleaved namespaces:

| MSGID prefix | Count | Content |
| :- | -: | :- |
| `R####` | 69 | Chef narrative + 52 single-char flag packets (`R0016`..`R0067`) |
| `F####` | 46 | Decoy: `Beep`, 44 single chars, `Boop` |

The chef has two independent loggers — the main monologue (`R`) and a
"fries" channel (`F`) — both syslogging into the same UDP socket. UDP
reorders packets between the two streams freely; the per-stream sequence
numbers are the only thing that survives.

## Reconstruction

```python
import re, subprocess
MSGID = re.compile(r"\s([RF])(\d{4})\s+-\s+(.+?)\s*$")
hex_payloads = subprocess.check_output(
    ["tshark", "-r", "kitchen_log.pcap", "-T", "fields",
     "-e", "udp.payload", "-Y", "syslog"], text=True
)
R, F = [], []
for h in hex_payloads.split():
    msg = bytes.fromhex(h.replace(":", "")).decode()
    m = MSGID.search(msg)
    (R if m.group(1) == "R" else F).append((int(m.group(2)), m.group(3)))
R.sort(); F.sort()

flag  = "".join(c for sid, c in R if sid >= 16 and len(c) == 1)
fries = "".join(c for _, c in F)
```

Output:

```
flag:  GPNCTF{NiC3, YOu F0UnD OUt WH0 Did No7 8ELON6 tH3RE}
fries: BeepN0t  4lm0st but n0t qu1t3. H1nt: 1t 15 m3 :)Boop
```

## What the decoy says

The F stream is the "friend" from the prompt. Decoded:

> Beep — N0t 4lm0st but n0t qu1t3. H1nt: 1t 15 m3 :) — Boop

So the *something felt off* is literally that there's a second sender on
the same wire impersonating the kitchen. The narrative even foreshadows
it: `R0012 Noticed weird beeping` right after the F stream's first
`Beep`.

Decoded flag: *"Nice, you found out who did not belong there"* — the
friend who didn't belong is the second syslog stream.

## Run

```
$ python3 solve.py kitchen_log.pcap
…
flag: GPNCTF{NiC3, YOu F0UnD OUt WH0 Did No7 8ELON6 tH3RE}
```
