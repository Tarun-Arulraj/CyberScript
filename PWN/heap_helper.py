#!/usr/bin/env python3
"""
heap_helper.py -- Reference helper for modern glibc heap exploitation
(tcache poisoning, safe-linking bypass, house-of-* primitives). This is a
knowledge/calculation aid, not a fully automated exploit -- heap challenges
need per-binary tailoring, but the safe-linking math and offset tracking
below save a lot of manual arithmetic.

Requires: pip install pwntools

Usage:
    python3 heap_helper.py decode-safelink <mangled_fd_hex> <chunk_addr_hex>
    python3 heap_helper.py encode-safelink <target_addr_hex> <chunk_addr_hex>
"""
import argparse


def decode_safelink(mangled_fd: int, chunk_addr: int) -> int:
    """glibc >= 2.32 safe-linking: fd is XORed with (chunk_addr >> 12).
    Given the mangled fd read from the heap and the chunk's own address,
    recover the real forward pointer (e.g. to leak heap layout)."""
    return mangled_fd ^ (chunk_addr >> 12)


def encode_safelink(target_addr: int, chunk_addr: int) -> int:
    """Inverse operation: compute the mangled fd value to write so that,
    after tcache applies safe-linking, the real fd becomes target_addr.
    Use this when poisoning tcache to redirect the next allocation."""
    return target_addr ^ (chunk_addr >> 12)


NOTES = """
[Heap exploitation quick reference for modern glibc]

1. tcache poisoning (glibc < 2.32, no safe-linking):
   - Free two chunks of the same size (into tcache bin, max 7 per size by default)
   - Use a UAF/overflow to overwrite the fd pointer of the top chunk in the bin
   - Next two mallocs of that size: first returns the freed chunk, second returns
     your forged fd target (e.g. GOT entry, a stack address, __free_hook, etc.)

2. Safe-linking (glibc >= 2.32):
   - fd pointers in tcache/fastbins are now mangled: stored_fd = real_fd ^ (chunk_addr >> 12)
   - You need to know/leak a heap address to correctly forge fd values
   - Use decode_safelink()/encode_safelink() above for the math

3. House of primitives worth knowing (glibc 2.31+):
   - House of Force      -- overwrite top chunk size for huge malloc, arbitrary write near heap
   - House of Orange     -- unsorted bin attack via top chunk overflow -> _IO_FILE hijack
   - House of Botcake    -- double-free via overlapping tcache/unsorted bin abuse
   - House of Spirit     -- free a fake chunk into tcache, later malloc returns fake chunk
   - Tcache dup (double free): glibc 2.29 checks the *same* freed chunk twice in a row via
     `e->key == tcache`, but you can bypass by freeing a different chunk in between

4. Typical exploitation goal chains:
   - Leak heap/libc base (via unsorted bin fd/bk pointers left after a free, or a UAF read)
   - Corrupt tcache fd -> malloc into __free_hook / __malloc_hook (pre-2.34) or
     into a function pointer / GOT entry for RCE
   - Post-2.34 (no more hooks): commonly target FILE structure exploitation (House of Orange /
     House of Apple) or overwrite a stack return address via a forged chunk

5. Tools:
   - `pwndbg` heap commands: `bins`, `tcache`, `chunk <addr>`, `heap`
   - `gef`: `heap chunks`, `heap bins tcache`
"""


def main():
    ap = argparse.ArgumentParser(description="Heap exploitation helper (glibc tcache/safe-linking math)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_dec = sub.add_parser("decode-safelink")
    p_dec.add_argument("mangled_fd_hex")
    p_dec.add_argument("chunk_addr_hex")

    p_enc = sub.add_parser("encode-safelink")
    p_enc.add_argument("target_addr_hex")
    p_enc.add_argument("chunk_addr_hex")

    sub.add_parser("notes")

    args = ap.parse_args()

    if args.cmd == "decode-safelink":
        real = decode_safelink(int(args.mangled_fd_hex, 16), int(args.chunk_addr_hex, 16))
        print(f"[+] Real fd pointer: {hex(real)}")
    elif args.cmd == "encode-safelink":
        mangled = encode_safelink(int(args.target_addr_hex, 16), int(args.chunk_addr_hex, 16))
        print(f"[+] Value to write as mangled fd: {hex(mangled)}")
    elif args.cmd == "notes":
        print(NOTES)


if __name__ == "__main__":
    main()
