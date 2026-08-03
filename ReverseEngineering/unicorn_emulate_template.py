#!/usr/bin/env python3
"""
unicorn_emulate_template.py -- Emulate a chunk of machine code with Unicorn
Engine when a rev challenge has heavy obfuscation/anti-debug and static
decompilation stalls. Useful for emulating a "check" function in isolation
and brute-forcing/solving its behavior without running the whole binary.

Requires: pip install unicorn capstone

Usage: customize CODE_BYTES / addresses below, then:
    python3 unicorn_emulate_template.py
"""
from unicorn import *
from unicorn.x86_const import *

# ---- Configuration: fill in from your binary ----
ADDRESS = 0x1000000          # base address to map code at
CODE_BYTES = b""              # raw bytes of the function to emulate (extract via objdump/Ghidra)
STACK_ADDR = 0x2000000
STACK_SIZE = 0x10000
ENTRY_OFFSET = 0               # offset within CODE_BYTES to start executing
STOP_OFFSET = None             # offset to stop at, or None to run until code ends


def hook_code(uc, address, size, user_data):
    """Optional: trace every instruction for debugging."""
    # print(f"0x{address:x}: size={size}")
    pass


def setup_emulator():
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map code region
    mu.mem_map(ADDRESS, 0x1000 * ((len(CODE_BYTES) // 0x1000) + 1))
    mu.mem_write(ADDRESS, CODE_BYTES)

    # Map stack
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)
    mu.reg_write(UC_X86_REG_RBP, STACK_ADDR + STACK_SIZE // 2)

    return mu


def emulate_with_input(candidate: bytes, input_addr=0x3000000):
    mu = setup_emulator()

    # Map memory region for the candidate input buffer
    mu.mem_map(input_addr, 0x1000)
    mu.mem_write(input_addr, candidate.ljust(0x1000, b"\x00"))

    # Example: pass pointer to input as first arg (System V AMD64 -> RDI)
    mu.reg_write(UC_X86_REG_RDI, input_addr)
    mu.reg_write(UC_X86_REG_RSI, len(candidate))

    mu.hook_add(UC_HOOK_CODE, hook_code)

    start = ADDRESS + ENTRY_OFFSET
    end = ADDRESS + (STOP_OFFSET if STOP_OFFSET else len(CODE_BYTES))

    try:
        mu.emu_start(start, end, timeout=0, count=0)
    except UcError as e:
        print(f"[!] Emulation stopped: {e}")

    # Example: read return value (RAX = check function's result)
    result = mu.reg_read(UC_X86_REG_RAX)
    return result


def brute_force_example(charset=b"abcdefghijklmnopqrstuvwxyz0123456789", length=6):
    """Naive brute force loop -- fine for short check functions; for longer
    inputs use angr's symbolic execution (see angr_template.py) instead."""
    import itertools
    for combo in itertools.product(charset, repeat=length):
        candidate = bytes(combo)
        result = emulate_with_input(candidate)
        if result == 1:   # adjust success condition to match the target function
            print(f"[+] Found: {candidate}")
            return candidate
    print("[-] Exhausted search space without success")
    return None


if __name__ == "__main__":
    print(__doc__)
    print("Fill in CODE_BYTES and success condition, then call emulate_with_input() "
          "or brute_force_example() as appropriate for your challenge.")
