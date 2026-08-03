# Mobile CTF Cheatsheet — Speed Edition

*Built around common defaults: apktool, jadx, dex2jar, Frida, adb, MobSF, Burp (for
traffic interception), otool/class-dump for iOS, Ghidra (for native .so libraries).
Swap in your actual installed set once you send it.*

---

```bash
file app.apk                          # confirm it's actually a valid APK/ZIP
unzip -l app.apk | head -30           # peek contents without extracting
adb devices                           # confirm device/emulator connection before dynamic analysis
```

**Quick classification — what am I dealing with?**

| Given | Approach |
|---|---|
| `.apk` file | Android — apktool/jadx static analysis first |
| `.ipa` file | iOS — class-dump/otool, needs jailbroken device or simulator for dynamic |
| Just a package name + running app | Dynamic analysis via Frida/adb only, no static file given |
| App talks to a backend API | Intercept traffic (Burp/mitmproxy), treat backend like a Web challenge |

---

## 1. Android — Static Analysis

```bash
apktool d -f -o app_apktool app.apk                    # decode resources + smali + manifest
jadx -d app_jadx app.apk                                # decompile to readable Java source
jadx-gui app.apk                                         # GUI version, easier for browsing/searching

# Alternative decompile pipeline (dex -> jar -> read with any Java decompiler)
d2j-dex2jar app.apk -o app.jar
```

**AndroidManifest.xml — what to check first:**
```bash
cat app_apktool/AndroidManifest.xml | grep -E 'exported="true"' -B5    # exported attack surface
cat app_apktool/AndroidManifest.xml | grep 'uses-permission'            # requested permissions
cat app_apktool/AndroidManifest.xml | grep 'debuggable'                 # android:debuggable="true"?
```

**Grep decompiled sources for the usual suspects:**
```bash
grep -rIiE 'flag\{|ctf\{|api[_-]?key|secret|password\s*=' app_jadx/sources/
grep -rIiE '"AES|"DES|Cipher\.getInstance' app_jadx/sources/            # crypto usage, check for hardcoded keys
grep -rIiE 'isDebuggerConnected|RootBeer|SuperUser|/system/bin/su' app_jadx/sources/   # anti-tamper checks
grep -rIiE 'addJavascriptInterface' app_jadx/sources/                    # WebView JS bridge (injection point)
grep -rIiE 'System\.loadLibrary' app_jadx/sources/                       # native lib usage -- logic may be in a .so
```

**MobSF — automated static + dynamic scan if you want a broad first pass:**
```bash
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# then upload the APK/IPA via the web UI at localhost:8000
```

---

## 2. Android — Native Libraries (.so files)

```bash
unzip app.apk 'lib/*'                                   # extract native libraries
file lib/arm64-v8a/libnative.so                          # confirm arch
```
Treat the extracted `.so` exactly like a normal ELF rev challenge from here — hand it
to Ghidra/r2, use your ReverseEngineering cheatsheet's workflow. Native logic is
common when the challenge wants to hide the "real" check from easy Java decompilation.

---

## 3. Android — Dynamic Analysis (Frida)

```bash
adb install app.apk
frida-ps -U                                             # list running processes on device
frida -U -f com.example.app --no-pause -l script.js     # spawn + hook on launch
```

**SSL pinning bypass (extremely common blocker before you can even see traffic):**
```javascript
Java.perform(function () {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function (host, certs) {
            console.log('[+] Bypassing pin for ' + host);
        };
});
```
(see `frida_templates.py` in your Mobile toolkit repo for this plus TrustManager +
root-detection bypass, ready to run)

**Generic method hook to watch a suspicious function live:**
```javascript
Java.perform(function () {
    var target = Java.use('com.example.app.LicenseChecker');
    target.isValid.implementation = function (key) {
        var result = this.isValid(key);
        console.log('isValid(' + key + ') => ' + result);
        return result;
    };
});
```

---

## 4. Android — Root/Debug Detection Bypass (without Frida, via patching)

```bash
# Patch out a root check directly in smali if Frida isn't an option (e.g. anti-Frida checks present)
apktool d app.apk -o app_patch
# find the check in smali (grep for isDeviceRooted, checkSu, etc), edit the .smali file directly
# e.g. change a conditional jump so the root-check branch is never taken
apktool b app_patch -o patched.apk
apksigner sign --ks debug.keystore patched.apk
adb install patched.apk
```

---

## 5. Traffic Interception

```bash
# Install Burp/mitmproxy's CA cert on the device/emulator first, then:
adb shell settings put global http_proxy <burp_host>:8080         # set device-wide proxy (older Android)
# Newer Android: set proxy in WiFi settings UI, or use a rooted device + iptables redirect

mitmproxy --mode transparent                                        # if redirecting via iptables
```
If the app pins certificates, you need the Frida SSL-bypass script above *before*
traffic will show up cleanly in the proxy.

---

## 6. iOS

```bash
class-dump app_binary                       # dump Objective-C class/method signatures
otool -L app_binary                          # linked libraries
otool -tv app_binary                         # disassembly (Objective-C, less common now vs Swift)
```
iOS challenges usually assume a jailbroken device or simulator; Frida works the same
way as Android (`frida -U -f com.example.app`) once you have that access. Swift
binaries are harder to decompile than Objective-C — treat as a standard ARM64 rev
challenge with Ghidra if class-dump doesn't give you much.

---

## 7. Quick Reference — CTF Triage Checklist

**Given only an APK:**
```
apktool + jadx first (static) → grep for flags/secrets/crypto/native-lib usage →
if logic is in a .so, treat as ReverseEngineering challenge from there →
if nothing obvious, move to dynamic analysis with Frida
```

**App won't run under Frida / detects tampering:**
```
Check smali for root/debug/Frida-detection strings → patch out the check directly via
apktool + smali edit, re-sign, re-install → retry Frida attach
```

**App talks to a backend, need to see the traffic:**
```
Install proxy CA cert on device → if traffic doesn't show: SSL pinning is active →
run Frida SSL-bypass script first → retry proxy interception → once visible,
treat the backend like a normal Web challenge
```

**Given an IPA (iOS) instead:**
```
class-dump for Obj-C classes → otool -L for linked libs → if Swift and class-dump
comes up empty, treat as ARM64 native binary and use your RE cheatsheet directly
```

---
