#!/usr/bin/env python3
"""
Solver for the `autocooker` reverse-engineering challenge.

The binary applies four invertible transformations to a 64-byte buffer
that holds the user's input (the flag), then memcmps the result against
a constant `DELICIOUS` blob. We extract the constants from the binary
and invert each step to recover the flag.
"""

# DELICIOUS lives in .data at 0x404080 (64 bytes).
DELICIOUS = bytes.fromhex(
    "0a0a0a0a7ddda94e5f9f992e9d3eec5f"
    "ef9dfcee8fbc2c5f8dff5c5f8f5ece5f"
    "3fecbefe8d5ffe8fbe5ffda93f5f991c"
    "b96c5f6e99fecc5fb91dceef9e4eafde"
)

GRAIN_OF_SALT = 0xAA  # .data @ 0x404064
TARGET_LENGTH = 0x3D  # .data @ 0x404060  (61)


def nibble_swap(b: int) -> int:
    return ((b << 4) | (b >> 4)) & 0xFF


def cook(recipe: bytes) -> bytes:
    """Forward pipeline, mirroring main() in the binary."""
    food = bytearray(recipe.ljust(64, b"\x00"))
    food = bytearray(b ^ GRAIN_OF_SALT for b in food)        # salt
    food = bytearray(nibble_swap(b) for b in food)           # fry
    for i in range(TARGET_LENGTH, 64):                       # trim
        food[i] &= 0x0F
    return bytes(food[::-1])                                 # mix


def solve() -> bytes:
    # `mix` is reverse, so the post-fry byte at index 63-i must equal DELICIOUS[i].
    # `fry` (nibble swap) is its own inverse.
    # `salt` is XOR with 0xAA.
    # For the flag bytes (input indices 0..59), `trim` does nothing.
    return bytes(nibble_swap(DELICIOUS[63 - i]) ^ GRAIN_OF_SALT for i in range(60))


if __name__ == "__main__":
    flag = solve()
    print(f"Flag: {flag.decode()}")

    # Self-check: feed the flag (plus the trailing newline fgets would capture)
    # back through the forward pipeline and confirm it matches DELICIOUS.
    assert cook(flag + b"\n") == DELICIOUS, "forward verification failed"
    print("Verified against DELICIOUS.")
