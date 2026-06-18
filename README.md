# GPN CTF 2026 — writeups

Writeups for [Gulaschprogrammiernacht CTF 2026](https://ctf.kitctf.de/)
by **Abdelkad3r**. Long-form versions will also appear at
<https://cybersecurityelite.com/ctf-writeups/>.

20 writeups: 6 reverse, 4 crypto, 3 web, 1 pwn, 5 misc, and one
meta-writeup on the LLM harness that produced the rest.

## Reading order suggestions

Each writeup is standalone, but if you want a guided tour:

- **Start with one challenge per category** — `reverse/stupidcontract`,
  `crypto/justfollowtherecipe`, `web/tinyweb`, `pwn/recipe-for-disaster`,
  `misc/organized`. Five flags, five entirely different vulnerability
  classes.
- **Then the paired challenges** — `reverse/leftovers` and
  `reverse/leftover-leftovers` are the same author's two-act lesson on
  why AOT caches are part of your TCB.
  reflects on the workflow behind everything else, including the
  six-hour rabbit hole on `crypto/guess-the-taste` that nearly cost the
  flag.

## Reverse Engineering

| Challenge | Writeup | One-line takeaway |
|-----------|---------|--------------------|
| autocooker | [reverse/autocooker](./reverse/autocooker) | Four involutions stacked = trivially invertible "encryption" |
| specCTF | [reverse/specCTF](./reverse/specCTF) | The whole Spectre rig is theatre — real check is `hash(input) == ENC[i]`, hash is splitmix64 |
| Königsberg Delivery Problem | [reverse/koenigsberg-delivery-problem](./reverse/koenigsberg-delivery-problem) | Hamiltonian (not Eulerian) path on a 250-state FSM extracted from jump tables |
| leftovers | [reverse/leftovers](./reverse/leftovers) | AOT cache silently overrides a JAR method — disassemble the ConstMethod blob |
| leftover-leftovers | [reverse/leftover-leftovers](./reverse/leftover-leftovers) | One-byte cache patch (`iconst_0`→`iconst_1`) bypasses a homemade `verifyStuff` |
| stupidcontract | [reverse/stupidcontract](./reverse/stupidcontract) | Kernel patched to strip BPF verifier checks → signed-cmp OOB write in eBPF map |

## Crypto

| Challenge | Writeup | One-line takeaway |
|-----------|---------|--------------------|
| com-petition | [crypto/com-petition](./crypto/com-petition) | `sha256(r1‖m‖r2)` with both nonces user-controlled = same commitment opens to 3 moves |
| easy-dsa | [crypto/easy-dsa](./crypto/easy-dsa) | `uuid3` is MD5 → fastcoll collision → ECDSA nonce reuse → key recovery |
| guess-the-taste | [crypto/guess-the-taste](./crypto/guess-the-taste) | NTRU ciphertext never reduced mod q ⇒ `c mod p == m` |
| justfollowtherecipe | [crypto/justfollowtherecipe](./crypto/justfollowtherecipe) | `gcc -O3 -mavx2` swaps lanes 1↔2 in inner-product `mat_mul` — fix the leak, then BKZ-58 SIS |

## Web

| Challenge | Writeup | One-line takeaway |
|-----------|---------|--------------------|
| restaurant-builder | [web/restaurant-builder](./web/restaurant-builder) | Pydantic `create_model` eval's `ForwardRef` annotations → exfil FLAG via JSON schema description |
| pharry | [web/pharry](./web/pharry) | PHP 7.4 PHAR deserialization; `md5_file` + `file_get_contents` open two TCP connections, exploit with a counting server |
| tinyweb | [web/tinyweb](./web/tinyweb) | `Link: rel=stylesheet` CSS injection + `body[onload^=…]` attribute selectors leak the cookie char-by-char |

## Pwn

| Challenge | Writeup | One-line takeaway |
|-----------|---------|--------------------|
| recipe-for-disaster | [pwn/recipe-for-disaster](./pwn/recipe-for-disaster) | `gets()` overflows `note[32]` into adjacent `int price`; `price=-1` triggers `print_coupon` |

## Misc

| Challenge | Writeup | One-line takeaway |
|-----------|---------|--------------------|
| customer-service | [misc/customer-service](./misc/customer-service) | holpy proof checker: `list == 1` typo + every `thm` re-axiomatized + name-based `false` check |
| double-fried | [misc/double-fried](./misc/double-fried) | Two interleaved RFC 5424 syslog streams in one UDP flow; split on MSGID prefix |
| knitted-flag | [misc/knitted-flag](./misc/knitted-flag) | Knitout front-bed vs back-bed bit = 978×20 pixel art; carrier colors are a decoy |
| organized | [misc/organized](./misc/organized) | Ternary amplitude-modulated UART hidden in per-block popcount density |
| supercat | [misc/supercat](./misc/supercat) | TOCTOU symlink swap between `metadata()` and `read_to_string()` in a setuid Rust gate |

## Meta

| Writeup | Description |
|---------|-------------|

## Note for the prize jury

These are the writeups I'm submitting for the GPN CTF 2026 writeup
prizes:

- **Best overall:** [`crypto/justfollowtherecipe`](./crypto/justfollowtherecipe) —
  two stacked bugs (a `gcc -O3 -mavx2` lane-1/2 swap in `mat_mul`, plus a
  textbook SIS / Kannan-embedding lattice attack). The compiler-bug
  diagnosis is the part I'd want a jury to read.
- **Best in category — reverse:** [`reverse/stupidcontract`](./reverse/stupidcontract)
  and [`reverse/leftover-leftovers`](./reverse/leftover-leftovers).
- **Best in category — crypto:** [`crypto/justfollowtherecipe`](./crypto/justfollowtherecipe)
  and [`crypto/easy-dsa`](./crypto/easy-dsa).
- **Best in category — web:** [`web/tinyweb`](./web/tinyweb) and
  [`web/pharry`](./web/pharry).
- **Best in category — misc:** [`misc/organized`](./misc/organized) and
  [`misc/customer-service`](./misc/customer-service).
- **Best in category — pwn:** [`pwn/recipe-for-disaster`](./pwn/recipe-for-disaster).
  honest post-mortem, not a marketing piece.

## License

Writeups are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Solver code is MIT.
