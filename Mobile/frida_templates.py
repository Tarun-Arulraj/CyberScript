#!/usr/bin/env python3
"""
frida_templates.py -- Ready-to-adapt Frida scripts for common mobile CTF
needs: SSL pinning bypass, root/jailbreak detection bypass, and hooking a
specific method to log or override its return value.

Requires: pip install frida-tools   (and the frida-server running on device/emulator)

Usage:
    python3 frida_templates.py ssl-bypass --package com.example.app
    python3 frida_templates.py root-bypass --package com.example.app
    python3 frida_templates.py hook-method --package com.example.app \\
        --class com.example.app.LicenseChecker --method isValid
"""
import argparse
import frida
import sys

SSL_PINNING_BYPASS_JS = """
Java.perform(function () {
    console.log("[*] Attempting universal SSL pinning bypass...");

    // 1) Bypass TrustManager-based pinning
    try {
        var TrustManager = Java.registerClass({
            name: 'com.ctf.TrustManagerBypass',
            implements: [Java.use('javax.net.ssl.X509TrustManager').class],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        ).implementation = function (keyManager, trustManager, secureRandom) {
            console.log('[+] Overriding SSLContext.init with permissive TrustManager');
            this.init(keyManager, [TrustManager.$new()], secureRandom);
        };
    } catch (e) { console.log('[-] TrustManager bypass failed: ' + e); }

    // 2) Bypass OkHttp3 CertificatePinner (very common)
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, certs) {
            console.log('[+] Bypassing OkHttp3 CertificatePinner for ' + host);
        };
    } catch (e) { console.log('[i] OkHttp3 CertificatePinner not present or different overload: ' + e); }

    console.log("[*] SSL pinning bypass hooks installed.");
});
"""

ROOT_DETECTION_BYPASS_JS = """
Java.perform(function () {
    console.log("[*] Attempting common root/debug detection bypasses...");

    // Bypass common RootBeer-style checks by hooking File.exists on su paths
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1) {
                console.log('[+] Hiding root indicator path: ' + path);
                return false;
            }
            return this.exists();
        };
    } catch (e) { console.log('[-] File.exists hook failed: ' + e); }

    // Bypass Debug.isDebuggerConnected
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            console.log('[+] Hiding debugger presence');
            return false;
        };
    } catch (e) { console.log('[i] Debug.isDebuggerConnected hook not applicable: ' + e); }

    console.log("[*] Root/debug detection bypass hooks installed.");
});
"""


def hook_method_js(class_name, method_name):
    return f"""
Java.perform(function () {{
    var target = Java.use('{class_name}');
    var overloads = target['{method_name}'].overloads;
    console.log('[*] Found ' + overloads.length + ' overload(s) of {method_name}');
    overloads.forEach(function (overload) {{
        overload.implementation = function () {{
            console.log('[+] {class_name}.{method_name} called with args: ' + JSON.stringify(arguments));
            var ret = this['{method_name}'].apply(this, arguments);
            console.log('[+] Original return value: ' + ret);
            // Uncomment to force a specific return value, e.g. bypass a license/auth check:
            // return true;
            return ret;
        }};
    }});
}});
"""


def run_script(package, script_source):
    print(f"[*] Attaching to {package} ...")
    device = frida.get_usb_device(timeout=5)
    pid = device.spawn([package])
    session = device.attach(pid)
    script = session.create_script(script_source)
    script.on("message", lambda msg, data: print(msg))
    script.load()
    device.resume(pid)
    print("[*] Script loaded. Press Ctrl+C to detach.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass


def main():
    ap = argparse.ArgumentParser(description="Frida script templates for mobile CTF challenges")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ssl = sub.add_parser("ssl-bypass")
    p_ssl.add_argument("--package", required=True)

    p_root = sub.add_parser("root-bypass")
    p_root.add_argument("--package", required=True)

    p_hook = sub.add_parser("hook-method")
    p_hook.add_argument("--package", required=True)
    p_hook.add_argument("--class", dest="class_name", required=True)
    p_hook.add_argument("--method", required=True)

    p_print = sub.add_parser("print-script")
    p_print.add_argument("which", choices=["ssl-bypass", "root-bypass"])

    args = ap.parse_args()

    if args.cmd == "ssl-bypass":
        run_script(args.package, SSL_PINNING_BYPASS_JS)
    elif args.cmd == "root-bypass":
        run_script(args.package, ROOT_DETECTION_BYPASS_JS)
    elif args.cmd == "hook-method":
        run_script(args.package, hook_method_js(args.class_name, args.method))
    elif args.cmd == "print-script":
        print(SSL_PINNING_BYPASS_JS if args.which == "ssl-bypass" else ROOT_DETECTION_BYPASS_JS)


if __name__ == "__main__":
    main()
