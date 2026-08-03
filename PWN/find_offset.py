#!/usr/bin/env python3
"""
find_offset.py -- Find the exact byte offset that overwrites a saved
return address / register, using pwntools' de Bruijn cyclic patterns.

Requires: pip install pwntools

Usage:
    # 1) Generate a pattern to feed the crashing program
    python3 find_offset.py gen 200

    # 2) After it crashes in gdb, read the value in $rsp / crash register
    #    (e.g. "0x6161616161616168") and find its offset:
    python3 find_offset.py find 0x6161616161616168

    # 3) Or automate crash + offset detection against a local binary:
    python3 find_offset.py auto ./chall 200
"""
import sys
from pwn import cyclic, cyclic_find, process, context


def gen(length):
    pat = cyclic(int(length))
    print(pat.decode(errors="replace"))
    print(f"\n[raw bytes] {pat}")


def find(value):
    if isinstance(value, str) and value.startswith("0x"):
        value = int(value, 16)
        # pwntools expects either bytes or an int representing the register value
        value = value.to_bytes(8, "little")
    elif isinstance(value, str):
        value = value.encode()
    offset = cyclic_find(value)
    print(f"[+] Offset: {offset}")
    return offset


def auto(binary, length):
    """Send a cyclic pattern to the binary and read the crash address via core dump / gdb.
    This is a starting point -- for full automation pair with gdb.attach() in pwntools."""
    context.binary = binary
    pat = cyclic(int(length))
    io = process(binary)
    io.sendline(pat)
    io.wait()
    core = io.corefile
    if core is None:
        print("[-] No corefile found. Run `ulimit -c unlimited` first, "
              "or use GDB.attach in exploit_template.py to catch the crash live.")
        return
    crash_value = core.read(core.sp, 8)
    print(f"[+] Value at crash $sp: {crash_value}")
    offset = cyclic_find(crash_value)
    print(f"[+] Offset: {offset}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "gen":
        gen(sys.argv[2])
    elif cmd == "find":
        find(sys.argv[2])
    elif cmd == "auto":
        auto(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
