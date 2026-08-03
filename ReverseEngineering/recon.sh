#!/usr/bin/env bash
# recon.sh -- First-pass recon for an unknown reversing / pwn binary.
# Requires: file, strings, binwalk, checksec (pwntools' `checksec` or the standalone tool),
#           objdump, readelf, ltrace/strace (optional)
#
# Usage: ./recon.sh <binary>

set -uo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

BIN="$1"

sep() { printf '\n=== %s ===\n' "$1"; }

sep "file"
file "$BIN"

sep "checksec (protections: canary/NX/PIE/RELRO)"
if command -v checksec &>/dev/null; then
    checksec --file="$BIN" 2>/dev/null || checksec "$BIN"
else
    echo "checksec not installed -- pip install pwntools (has checksec) or apt install checksec"
fi

sep "readelf headers (ELF only)"
if file "$BIN" | grep -qi elf; then
    readelf -h "$BIN" 2>/dev/null | head -30
    echo "--- dynamic symbols (imports) ---"
    readelf -d "$BIN" 2>/dev/null | grep NEEDED
fi

sep "interesting strings (flags, urls, formats, paths)"
strings -n 6 "$BIN" | grep -Ei 'flag|ctf|http|ssh|password|key|/bin/|%s|%d|system|exec' | sort -u | head -60

sep "all printable strings > 8 chars (first 100)"
strings -n 8 "$BIN" | head -100

sep "binwalk (embedded files / signatures)"
if command -v binwalk &>/dev/null; then
    binwalk "$BIN"
else
    echo "binwalk not installed -- apt install binwalk"
fi

sep "objdump - interesting functions"
objdump -d "$BIN" 2>/dev/null | grep -E '<(main|win|flag|system|exec|vuln|backdoor|admin)' 

sep "objdump - PLT / GOT relevant calls"
objdump -d "$BIN" 2>/dev/null | grep -E 'call.*<(system|exec|strcpy|gets|scanf|printf|sprintf)@plt>' | head -30

sep "done"
echo "Next steps depending on findings:"
echo "  - Static analysis:  ghidra / IDA / Binary Ninja"
echo "  - Dynamic analysis: gdb + pwndbg/gef/peda, ltrace, strace"
echo "  - Symbolic exec:    angr (see angr_template.py)"
echo "  - Packed/obfuscated: try 'upx -d $BIN' if UPX packed"
