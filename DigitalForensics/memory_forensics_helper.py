#!/usr/bin/env python3
"""
memory_forensics_helper.py -- Volatility3 wrapper for common CTF memory
forensics tasks: process listing, suspicious process detection, command-line
history, network connections, and dumping a process for further static
analysis (feed the dump to recon.sh / ghidra scripts / strings|grep).

Requires: pip install volatility3
    (plus its symbol tables -- see https://github.com/volatilityfoundation/volatility3
     for the symbol-table setup for the target OS)

Usage examples:
    python3 memory_forensics_helper.py --dump mem.raw --pslist
    python3 memory_forensics_helper.py --dump mem.raw --cmdline
    python3 memory_forensics_helper.py --dump mem.raw --netscan
    python3 memory_forensics_helper.py --dump mem.raw --suspicious
    python3 memory_forensics_helper.py --dump mem.raw --dump-proc 1337 --out proc_1337.dmp
    python3 memory_forensics_helper.py --dump mem.raw --strings-flag "flag{"
"""
import argparse
import subprocess
import re


VOL_PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "cmdline": "windows.cmdline.CmdLine",
    "netscan": "windows.netscan.NetScan",
    "linux_pslist": "linux.pslist.PsList",
    "linux_bash": "linux.bash.Bash",
    "malfind": "windows.malfind.Malfind",
    "hashdump": "windows.hashdump.Hashdump",
    "filescan": "windows.filescan.FileScan",
}

SUSPICIOUS_NAME_HINTS = [
    "powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32",
    "regsvr32", "certutil", "nc.exe", "ncat", "netcat", "python", "perl",
    "bash", "sh", "nohup",
]


def run_vol(dump_path, plugin, extra_args=None):
    cmd = ["vol", "-f", dump_path, plugin]
    if extra_args:
        cmd += extra_args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0 and not result.stdout:
        print("[-] volatility3 error:", result.stderr[:2000])
    return result.stdout


def pslist(dump_path, os_hint="windows"):
    plugin = VOL_PLUGINS["pslist"] if os_hint == "windows" else VOL_PLUGINS["linux_pslist"]
    out = run_vol(dump_path, plugin)
    print(out)
    return out


def cmdline(dump_path):
    out = run_vol(dump_path, VOL_PLUGINS["cmdline"])
    print(out)
    return out


def netscan(dump_path):
    out = run_vol(dump_path, VOL_PLUGINS["netscan"])
    print(out)
    return out


def suspicious_processes(dump_path, os_hint="windows"):
    """Cross-references pslist output against a short list of names that
    commonly indicate a CTF-planted foothold/payload process, and also runs
    malfind (Windows) to flag injected/hidden memory regions."""
    out = pslist(dump_path, os_hint)
    hits = []
    for line in out.splitlines():
        lower = line.lower()
        if any(hint in lower for hint in SUSPICIOUS_NAME_HINTS):
            hits.append(line)
    print("\n[*] Processes matching suspicious-name heuristics:")
    for h in hits:
        print("   ", h)
    if os_hint == "windows":
        print("\n[*] Running malfind (injected/hidden memory regions) ...")
        malfind_out = run_vol(dump_path, VOL_PLUGINS["malfind"])
        print(malfind_out)
    return hits


def dump_process(dump_path, pid, out_path=None):
    """Dumps a process's memory (Windows: windows.memmap with --dump, or
    windows.pslist --pid <pid> --dump depending on your vol3 version)."""
    args = ["--pid", str(pid), "--dump"]
    out = run_vol(dump_path, "windows.pslist.PsList", args)
    print(out)
    print(f"[*] Look for a .dmp file written in the current directory for pid {pid}.")
    if out_path:
        print(f"[*] Rename/move it to {out_path} for further static analysis "
              f"(feed to ReverseEngineering/recon.sh next).")
    return out


def strings_grep_flag(dump_path, flag_prefix="flag{"):
    """Fallback when a targeted plugin doesn't surface the flag: raw strings
    grep across the whole memory image."""
    try:
        proc = subprocess.run(
            ["bash", "-c", f"strings -n 6 {dump_path} | grep -a -F {flag_prefix!r}"],
            capture_output=True, text=True, timeout=300,
        )
        print(proc.stdout or "[-] No matches found.")
        return proc.stdout
    except FileNotFoundError:
        print("[-] `strings` not found -- apt install binutils")
        return ""


def main():
    ap = argparse.ArgumentParser(description="Volatility3 wrapper for CTF memory forensics")
    ap.add_argument("--dump", required=True, help="path to the memory image")
    ap.add_argument("--os", default="windows", choices=["windows", "linux"])
    ap.add_argument("--pslist", action="store_true")
    ap.add_argument("--cmdline", action="store_true")
    ap.add_argument("--netscan", action="store_true")
    ap.add_argument("--suspicious", action="store_true")
    ap.add_argument("--dump-proc", type=int, metavar="PID")
    ap.add_argument("--out", help="rename hint for --dump-proc output")
    ap.add_argument("--strings-flag", metavar="PREFIX", help='e.g. "flag{"')
    args = ap.parse_args()

    if args.pslist:
        pslist(args.dump, args.os)
    if args.cmdline:
        cmdline(args.dump)
    if args.netscan:
        netscan(args.dump)
    if args.suspicious:
        suspicious_processes(args.dump, args.os)
    if args.dump_proc:
        dump_process(args.dump, args.dump_proc, args.out)
    if args.strings_flag:
        strings_grep_flag(args.dump, args.strings_flag)

    if not any([args.pslist, args.cmdline, args.netscan, args.suspicious,
                args.dump_proc, args.strings_flag]):
        ap.print_help()


if __name__ == "__main__":
    main()
