#!/usr/bin/env bash
# forensics_triage.sh -- First-pass triage of an unknown forensics file/image/pcap.
# Requires: file, exiftool, binwalk, foremost, strings, steghide, zsteg (gem),
#           tshark/wireshark (for pcaps), volatility3 (for memory dumps)
#
# Usage: ./forensics_triage.sh <path-to-file>

set -uo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <file>"
    exit 1
fi

TARGET="$1"

sep() { printf '\n=== %s ===\n' "$1"; }

sep "file type"
file "$TARGET"

sep "exiftool metadata (often hides flags in EXIF/comments)"
if command -v exiftool &>/dev/null; then
    exiftool "$TARGET"
else
    echo "exiftool not installed -- apt install libimage-exiftool-perl"
fi

sep "strings for flag/ctf markers"
strings -n 6 "$TARGET" | grep -Ei 'flag\{|ctf\{|flag:' | sort -u

sep "binwalk signature scan + extraction hint"
if command -v binwalk &>/dev/null; then
    binwalk "$TARGET"
    echo "--> to extract embedded files: binwalk -e \"$TARGET\""
else
    echo "binwalk not installed -- apt install binwalk"
fi

MIME=$(file --mime-type -b "$TARGET")

case "$MIME" in
    image/*)
        sep "image-specific checks"
        echo "- Check dimensions vs file size (possible appended data)"
        echo "- Try: steghide info \"$TARGET\"     (steganography container check)"
        echo "- Try: zsteg \"$TARGET\"              (PNG/BMP LSB steganography)"
        echo "- Try: pngcheck -v \"$TARGET\"        (PNG chunk anomalies, if PNG)"
        ;;
    application/pcap*|application/vnd.tcpdump.pcap)
        sep "pcap-specific checks"
        echo "- tshark -r \"$TARGET\" -q -z io,phs           (protocol hierarchy)"
        echo "- tshark -r \"$TARGET\" --export-objects http,/tmp/http_objs"
        echo "- tshark -r \"$TARGET\" -Y 'ftp || http.request || dns'"
        echo "- Look for credentials in cleartext protocols: ftp, http, telnet"
        ;;
    *)
        if [[ "$TARGET" == *.pcap || "$TARGET" == *.pcapng ]]; then
            echo "(pcap extension detected, see network checks above)"
        fi
        if [[ "$TARGET" == *.mem || "$TARGET" == *.raw || "$TARGET" == *.dmp ]]; then
            sep "memory-dump-specific checks"
            echo "- vol3 -f \"$TARGET\" windows.info    (identify profile/OS)"
            echo "- vol3 -f \"$TARGET\" windows.pslist   (running processes)"
            echo "- vol3 -f \"$TARGET\" windows.cmdline  (process command lines)"
            echo "- vol3 -f \"$TARGET\" windows.filescan | grep -i flag"
        fi
        ;;
esac

sep "done"
echo "If this looks like a container/archive, also try:"
echo "  7z l \"$TARGET\"   /   unzip -l \"$TARGET\"   /   tar tvf \"$TARGET\""
