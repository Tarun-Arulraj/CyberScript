#!/usr/bin/env bash
# smali_patch_helper.sh -- Decompile an APK to smali, apply a quick patch
# (flip a boolean check, NOP out a call, force a return value), then
# rebuild and self-sign so it installs on an emulator/device for further
# dynamic testing. Pairs with apk_static_analysis.sh (find the check first)
# and frida_templates.py (bypass at runtime instead of patching statically).
#
# Requires: apktool, apksigner (Android SDK build-tools), zipalign, keytool
#
# Usage:
#   ./smali_patch_helper.sh decompile <app.apk>
#   ...edit the smali under <app>_smali/... by hand...
#   ./smali_patch_helper.sh rebuild <app>_smali <output.apk>
#   ./smali_patch_helper.sh sign <output.apk>

set -uo pipefail

KEYSTORE="${KEYSTORE:-./ctf_debug.keystore}"
KEYSTORE_PASS="${KEYSTORE_PASS:-ctfpassword}"
KEY_ALIAS="${KEY_ALIAS:-ctfkey}"

ensure_keystore() {
    if [[ ! -f "$KEYSTORE" ]]; then
        echo "[*] Generating a throwaway debug keystore ($KEYSTORE) ..."
        keytool -genkeypair -v \
            -keystore "$KEYSTORE" -storepass "$KEYSTORE_PASS" \
            -alias "$KEY_ALIAS" -keypass "$KEYSTORE_PASS" \
            -keyalg RSA -keysize 2048 -validity 3650 \
            -dname "CN=ctf, OU=ctf, O=ctf, L=ctf, S=ctf, C=US"
    fi
}

cmd_decompile() {
    local apk="$1"
    local base
    base=$(basename "$apk" .apk)
    apktool d -f "$apk" -o "${base}_smali"
    echo "[+] Decompiled to ${base}_smali/"
    echo "    Common patch targets to grep for first:"
    echo "      grep -rn 'isDebuggerConnected\\|TracerPid\\|checkSignature\\|isRooted\\|SafetyNet' ${base}_smali/smali*"
    echo "    To force a boolean-returning method to always return true:"
    echo "      find the method's smali, replace its body with:"
    echo "        const/4 v0, 0x1"
    echo "        return v0"
}

cmd_rebuild() {
    local smali_dir="$1"
    local out_apk="$2"
    apktool b "$smali_dir" -o "$out_apk"
    echo "[+] Rebuilt (unsigned): $out_apk"
    echo "    Next: $0 sign $out_apk"
}

cmd_sign() {
    local apk="$1"
    ensure_keystore
    local aligned="${apk%.apk}_aligned.apk"
    zipalign -p -f 4 "$apk" "$aligned"
    apksigner sign --ks "$KEYSTORE" --ks-pass "pass:$KEYSTORE_PASS" \
        --key-pass "pass:$KEYSTORE_PASS" --ks-key-alias "$KEY_ALIAS" \
        "$aligned"
    echo "[+] Signed APK ready: $aligned"
    echo "    Install with: adb install -r $aligned"
}

case "${1:-}" in
    decompile) cmd_decompile "$2" ;;
    rebuild)   cmd_rebuild "$2" "$3" ;;
    sign)      cmd_sign "$2" ;;
    *)
        echo "Usage:"
        echo "  $0 decompile <app.apk>"
        echo "  $0 rebuild <smali_dir> <output.apk>"
        echo "  $0 sign <output.apk>"
        exit 1
        ;;
esac
