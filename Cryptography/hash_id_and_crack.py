#!/usr/bin/env python3
"""
hash_id_and_crack.py -- Identify a hash's likely algorithm by length/format,
then optionally shell out to hashcat or john for cracking.

Requires: hashcat or john installed for the --crack option.

Usage:
    python3 hash_id_and_crack.py identify <hash>
    python3 hash_id_and_crack.py crack <hash> --wordlist rockyou.txt --tool hashcat
"""
import argparse
import re
import subprocess

# (regex, name, hashcat mode)
HASH_PATTERNS = [
    (r"^[a-f0-9]{32}$", "MD5", 0),
    (r"^[a-f0-9]{40}$", "SHA1", 100),
    (r"^[a-f0-9]{56}$", "SHA224", 1300),
    (r"^[a-f0-9]{64}$", "SHA256", 1400),
    (r"^[a-f0-9]{96}$", "SHA384", 10800),
    (r"^[a-f0-9]{128}$", "SHA512", 1700),
    (r"^\$2[aby]\$", "bcrypt", 3200),
    (r"^\$1\$", "MD5 crypt (Unix)", 500),
    (r"^\$6\$", "SHA512 crypt (Unix)", 1800),
    (r"^\$argon2", "Argon2", None),
    (r"^[a-f0-9]{32}:[a-f0-9]+$", "MD5 with salt (hash:salt)", None),
    (r"^[A-Za-z0-9+/]{27}=$", "NTLM/base64-like (verify context)", 1000),
]


def identify(hash_str: str):
    hash_str = hash_str.strip()
    matches = []
    for pattern, name, mode in HASH_PATTERNS:
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append((name, mode))
    if not matches:
        print("[-] No pattern matched. Consider using `hashid` or `name-that-hash` (nth) for ambiguous formats.")
        return []
    print("[+] Possible algorithms:")
    for name, mode in matches:
        mode_str = f"(hashcat mode {mode})" if mode is not None else ""
        print(f"    - {name} {mode_str}")
    return matches


def crack_hashcat(hash_str, wordlist, mode):
    if mode is None:
        print("[-] No known hashcat mode for this hash type -- crack manually or with john.")
        return
    cmd = ["hashcat", "-m", str(mode), "-a", "0", hash_str, wordlist, "--show"]
    print(f"[*] Running: {' '.join(cmd)}")
    print("    (if not cracked yet, drop --show and run again, then rerun with --show)")
    subprocess.run(["hashcat", "-m", str(mode), "-a", "0", hash_str, wordlist])
    subprocess.run(cmd)


def crack_john(hash_str, wordlist):
    tmp_file = "/tmp/hash_to_crack.txt"
    with open(tmp_file, "w") as f:
        f.write(hash_str + "\n")
    cmd = ["john", "--wordlist=" + wordlist, tmp_file]
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd)
    subprocess.run(["john", "--show", tmp_file])


def main():
    ap = argparse.ArgumentParser(description="Hash identifier + cracker wrapper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("identify")
    p_id.add_argument("hash")

    p_crack = sub.add_parser("crack")
    p_crack.add_argument("hash")
    p_crack.add_argument("--wordlist", required=True)
    p_crack.add_argument("--tool", choices=["hashcat", "john"], default="hashcat")

    args = ap.parse_args()

    if args.cmd == "identify":
        identify(args.hash)
    elif args.cmd == "crack":
        matches = identify(args.hash)
        if args.tool == "hashcat":
            mode = matches[0][1] if matches else None
            crack_hashcat(args.hash, args.wordlist, mode)
        else:
            crack_john(args.hash, args.wordlist)


if __name__ == "__main__":
    main()
