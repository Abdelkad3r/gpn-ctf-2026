#!/usr/bin/env python3
"""
Solver for the `Königsberg Delivery Problem` challenge.

`cartographer` reads 250 signed bytes and dispatches them through a hand-built
finite state machine of 250 states. The win condition (in `check_instance`) is
that every per-state visit counter is non-zero, i.e. *every state was visited
at least once*. With exactly 250 input bytes available, that forces a
Hamiltonian path on the state graph: 249 transition bytes + 1 out-of-range
byte to terminate via the OOB → `check_instance` tail call.

This script:
  1. Disassembles `cartographer` with `objdump`.
  2. Parses each FSM state (entry address, counter index, max symbol,
     jump-table base).
  3. Reads each jump table out of `.rodata` and builds the transition map.
  4. Finds a Hamiltonian path from state 0 using DFS with Warnsdorff's rule.
  5. Emits the resulting `input.txt` of semicolon-separated signed bytes.

Pipe the output at the remote service:
    cat input.txt | ncat --ssl <host> 443
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

BINARY = Path(__file__).with_name("cartographer")
OOB_TAIL = 0x40D4  # `cfg+0x2f44`: jumps here when the next symbol exceeds the
                   # current state's max, then calls check_instance(rsp, 250).


def disassemble(path: Path) -> list[str]:
    return subprocess.check_output(
        ["objdump", "-d", "-M", "intel", str(path)],
    ).decode().splitlines()


def dump_rodata(path: Path) -> dict[int, int]:
    out = subprocess.check_output(
        ["objdump", "-s", "-j", ".rodata", str(path)],
    ).decode()
    rodata = {}
    line_re = re.compile(r"^\s*([0-9a-f]+)\s+([0-9a-f ]+)\s+")
    for line in out.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        base = int(m.group(1), 16)
        hexstr = m.group(2).replace(" ", "")
        for i in range(0, len(hexstr), 2):
            rodata[base + i // 2] = int(hexstr[i : i + 2], 16)
    return rodata


def parse_states(lines: list[str]) -> list[tuple[int, int, int, int]]:
    """Return list of (addr, idx, max_sym, jt_base) tuples, in source order."""
    state_re = re.compile(
        r"^\s*([0-9a-f]+):.*\binc\b\s+byte ptr \[rsp(?:\s*\+\s*0x([0-9a-f]+))?\]"
    )
    cmp_re = re.compile(r"\bcmp\s+rdx,\s*0x([0-9a-f]+)")
    lea_rsi = re.compile(r"\blea\s+rsi,\s*\[rip\s*\+\s*0x[0-9a-f]+\].*#\s*0x([0-9a-f]+)")
    lea_rax = re.compile(r"\blea\s+rax,\s*\[rip\s*\+\s*0x[0-9a-f]+\].*#\s*0x([0-9a-f]+)")

    rax_base = None
    in_cfg = False
    states = []
    for i, ln in enumerate(lines):
        if "<cfg>:" in ln:
            in_cfg = True
            continue
        if not in_cfg:
            continue
        # objdump emits "0000000000XXXXXX <name>:" between functions.
        if ln.startswith("00000000") and "<cfg>" not in ln:
            break

        if rax_base is None:
            m = lea_rax.search(ln)
            if m:
                rax_base = int(m.group(1), 16)

        m = state_re.match(ln)
        if not m:
            continue
        addr = int(m.group(1), 16)
        idx = int(m.group(2), 16) if m.group(2) else 0

        max_val, jt_base = None, None
        for j in range(i + 1, min(i + 12, len(lines))):
            l2 = lines[j]
            if max_val is None:
                mc = cmp_re.search(l2)
                if mc:
                    max_val = int(mc.group(1), 16)
            ml = lea_rsi.search(l2)
            if ml:
                jt_base = int(ml.group(1), 16)
                break
        if jt_base is None:
            jt_base = rax_base  # state 0 reuses rax set just before its entry
        states.append((addr, idx, max_val, jt_base))
    return states


def build_transitions(states, rodata):
    addr_to_state = {addr: idx for addr, idx, _, _ in states}
    transitions = {}
    for _, idx, mx, jt in states:
        row = []
        for sym in range(mx + 1):
            raw = bytes(rodata[jt + sym * 4 + b] for b in range(4))
            off = struct.unpack("<i", raw)[0]
            target = (jt + off) & ((1 << 64) - 1)
            if target == OOB_TAIL:
                row.append(-1)
            elif target in addr_to_state:
                row.append(addr_to_state[target])
            else:
                raise RuntimeError(f"unexpected target 0x{target:x} from state {idx}")
        transitions[idx] = row
    return transitions


def find_hamiltonian(transitions, n_states):
    # Per-state successor sets (deduplicated, OOB excluded) and the smallest
    # symbol that leads to each successor.
    nbrs = {}
    first_sym = {}
    for s, row in transitions.items():
        seen = {}
        for sym, t in enumerate(row):
            if t != -1 and t not in seen:
                seen[t] = sym
        nbrs[s] = set(seen)
        first_sym[s] = seen

    # An OOB-producing symbol for each state (for the terminating byte).
    oob_sym = {}
    for s, row in transitions.items():
        for sym, t in enumerate(row):
            if t == -1:
                oob_sym[s] = sym
                break
        else:
            oob_sym[s] = len(row)  # one past max → OOB

    visited = [False] * n_states
    path = [0]
    visited[0] = True

    sys.setrecursionlimit(n_states * 4)

    def dfs() -> bool:
        if len(path) == n_states:
            return True
        cur = path[-1]
        # Warnsdorff: try successors with the fewest unvisited successors first.
        cands = [c for c in nbrs[cur] if not visited[c]]
        cands.sort(key=lambda c: sum(1 for x in nbrs[c] if not visited[x]))
        for nxt in cands:
            visited[nxt] = True
            path.append(nxt)
            if dfs():
                return True
            path.pop()
            visited[nxt] = False
        return False

    if not dfs():
        raise RuntimeError("no Hamiltonian path found")
    return path, first_sym, oob_sym


def encode_input(path, first_sym, oob_sym) -> str:
    bytes_seq = [first_sym[path[i]][path[i + 1]] for i in range(len(path) - 1)]
    bytes_seq.append(oob_sym[path[-1]])
    # scanf %hhd expects a signed decimal; symbols 0..127 map to themselves.
    # State maxes top out around 0x6e (110), so we always stay in non-negative
    # territory and never need the signed-wrap encoding.
    assert max(bytes_seq) < 128, "would need signed-wrap encoding"
    return "".join(f"{b};" for b in bytes_seq)


def main() -> None:
    lines = disassemble(BINARY)
    states = parse_states(lines)
    assert len(states) == 250 and [s[1] for s in states] == list(range(250))

    rodata = dump_rodata(BINARY)
    transitions = build_transitions(states, rodata)

    path, first_sym, oob_sym = find_hamiltonian(transitions, n_states=250)
    text = encode_input(path, first_sym, oob_sym)

    out = Path(__file__).with_name("input.txt")
    out.write_text(text)
    print(f"Hamiltonian path found over {len(path)} states.")
    print(f"Wrote {len(text)} bytes of input to {out}")
    print("Run:  cat input.txt | ncat --ssl <host> 443")


if __name__ == "__main__":
    main()
