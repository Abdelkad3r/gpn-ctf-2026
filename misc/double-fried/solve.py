#!/usr/bin/env python3
"""Solve double-fried.

`kitchen_log.pcap` is 115 UDP syslog packets from the same kitchen. Each
RFC 5424 message carries a MSGID of either ``R####`` (the real / regular
stream, including the chef's narrative and the char-by-char flag) or
``F####`` (the parallel "fries" decoy stream). UDP arrival interleaves the
two; sorting each stream by its 4-digit sequence number restores it.

The flag is the per-char block of the R stream starting at R0016.
"""
import re
import subprocess
import sys

MSGID = re.compile(r"\s([RF])(\d{4})\s+-\s+(.+?)\s*$")


def streams(pcap: str):
    payloads = subprocess.check_output(
        ["tshark", "-r", pcap, "-T", "fields", "-e", "udp.payload", "-Y", "syslog"],
        text=True,
    )
    R, F = [], []
    for hexline in payloads.splitlines():
        hexline = hexline.strip().replace(":", "")
        if not hexline:
            continue
        msg = bytes.fromhex(hexline).decode("utf-8", "replace")
        m = MSGID.search(msg)
        if not m:
            continue
        bucket = R if m.group(1) == "R" else F
        bucket.append((int(m.group(2)), m.group(3)))
    R.sort()
    F.sort()
    return R, F


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "kitchen_log.pcap"
    R, F = streams(pcap)
    flag = "".join(c for sid, c in R if sid >= 16 and len(c) == 1)
    print("R-stream (chef narrative + flag):")
    for sid, body in R:
        print(f"  R{sid:04d}  {body}")
    print()
    print("F-stream (decoy):")
    print(" ", "".join(c for _, c in F))
    print()
    print("flag:", flag)
