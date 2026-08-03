#!/usr/bin/env bash
# firmware_analysis.sh -- First-pass triage of an embedded/IoT firmware blob.
# Requires: binwalk, file, strings, unsquashfs (squashfs-tools), jefferson (JFFS2),
#           ubireader (UBIFS) as needed
#
# Usage: ./firmware_analysis.sh <firmware.bin>

set -uo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <firmware.bin>"
    exit 1
fi

FW="$1"
OUTDIR="firmware_extracted_$$"

sep() { printf '\n=== %s ===\n' "$1"; }

sep "file type"
file "$FW"

sep "binwalk signature scan"
binwalk "$FW"

sep "binwalk entropy plot (helps spot encryption/compression boundaries)"
binwalk -E "$FW" 2>/dev/null | head -20
echo "(run 'binwalk -E $FW' interactively for the full graph)"

sep "extracting embedded filesystems"
binwalk -e --dd='.*' -C "$OUTDIR" "$FW"
echo "[+] Extracted contents (if any) under: $OUTDIR"

sep "searching extracted files for interesting strings"
if [[ -d "$OUTDIR" ]]; then
    grep -rIiE 'flag\{|ctf\{|password|private.?key|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY' "$OUTDIR" 2>/dev/null | head -50
fi

sep "common firmware artifacts to check manually"
cat << 'EOF'
- /etc/passwd, /etc/shadow          -> default/hardcoded credentials
- /etc/dropbear or /etc/ssh         -> hardcoded SSH host keys (often reused across devices!)
- *.pem, *.key, *.crt               -> hardcoded certs/private keys
- squashfs-root/www or /html        -> web management interface source (look for authbypass, command injection)
- squashfs-root/bin/*, /sbin/*      -> custom binaries worth reversing (checksec + recon.sh from ReverseEngineering/)
- U-Boot environment (uboot-env)    -> often contains boot arguments with debug flags/console access
EOF

sep "done"
echo "If UART/JTAG access is implied by the challenge (physical/simulated):"
echo "  - UART: identify via TX/RX/GND pins, connect at common bauds (115200, 9600) with a USB-serial adapter"
echo "  - JTAG: use OpenOCD with a matching config for the SoC to get a debug shell"
echo "  - Check for a bootloader console -- often reachable by hitting a key during boot"
