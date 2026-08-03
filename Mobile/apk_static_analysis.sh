#!/usr/bin/env bash
# apk_static_analysis.sh -- First-pass static analysis of an Android APK for
# mobile-track CTF challenges.
#
# Requires: apktool, jadx, unzip, grep
#   apktool: https://ibotpeaches.github.io/Apktool/
#   jadx:    https://github.com/skylot/jadx
#
# Usage: ./apk_static_analysis.sh <app.apk>

set -uo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <app.apk>"
    exit 1
fi

APK="$1"
BASENAME=$(basename "$APK" .apk)
APKTOOL_OUT="${BASENAME}_apktool"
JADX_OUT="${BASENAME}_jadx"

sep() { printf '\n=== %s ===\n' "$1"; }

sep "unzip listing (raw APK contents)"
unzip -l "$APK" | head -40

sep "AndroidManifest.xml (via apktool -- decoded, human readable)"
if command -v apktool &>/dev/null; then
    apktool d -f -o "$APKTOOL_OUT" "$APK" >/dev/null 2>&1
    cat "$APKTOOL_OUT/AndroidManifest.xml" 2>/dev/null | head -80
else
    echo "apktool not installed -- get it from https://ibotpeaches.github.io/Apktool/"
fi

sep "exported components (potential attack surface: activities/services/receivers)"
if [[ -f "$APKTOOL_OUT/AndroidManifest.xml" ]]; then
    grep -E 'android:exported="true"' -B5 "$APKTOOL_OUT/AndroidManifest.xml"
fi

sep "permissions requested"
if [[ -f "$APKTOOL_OUT/AndroidManifest.xml" ]]; then
    grep 'uses-permission' "$APKTOOL_OUT/AndroidManifest.xml"
fi

sep "decompiling Java sources with jadx"
if command -v jadx &>/dev/null; then
    jadx -d "$JADX_OUT" "$APK" >/dev/null 2>&1
    echo "[+] Decompiled sources at: $JADX_OUT/sources"
else
    echo "jadx not installed -- get it from https://github.com/skylot/jadx"
fi

sep "grepping decompiled sources for interesting strings/patterns"
if [[ -d "$JADX_OUT/sources" ]]; then
    echo "--- hardcoded flags/secrets ---"
    grep -rIiE 'flag\{|ctf\{|api[_-]?key|secret|password\s*=' "$JADX_OUT/sources" 2>/dev/null | head -40
    echo "--- crypto usage (check for weak modes/hardcoded keys) ---"
    grep -rIiE '"AES|"DES|Cipher\.getInstance' "$JADX_OUT/sources" 2>/dev/null | head -20
    echo "--- root/debug detection (common anti-tamper you may need to bypass) ---"
    grep -rIiE 'isDebuggerConnected|RootBeer|SuperUser|/system/bin/su' "$JADX_OUT/sources" 2>/dev/null | head -20
    echo "--- WebView JS bridge (potential injection point) ---"
    grep -rIiE 'addJavascriptInterface' "$JADX_OUT/sources" 2>/dev/null | head -20
    echo "--- native library loading (check .so files for the real logic) ---"
    grep -rIiE 'System\.loadLibrary' "$JADX_OUT/sources" 2>/dev/null | head -20
fi

sep "native libraries present (.so files -- reverse with Ghidra/IDA if logic isn't in Java)"
unzip -l "$APK" | grep '\.so$'

sep "done"
cat << 'EOF'
Next steps depending on findings:
  - If logic is in a .so:      extract with `unzip $APK lib/*` then use recon.sh / angr_template.py
  - If root/debug detection:   patch it out with apktool + smali edits, then `apktool b` and re-sign
  - If server communicates:    proxy with Burp/mitmproxy + install cert, check for cert pinning (frida bypass script below)
  - Re-signing after edits:    apktool b <dir> -o patched.apk && apksigner sign --ks debug.keystore patched.apk
EOF
