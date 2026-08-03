#!/usr/bin/env python3
"""
classical_ciphers.py -- Caesar, Vigenere, Atbash, ROT-N, substitution helpers.

Usage:
    python3 classical_ciphers.py --text "KHOOR ZRUOG" --caesar-brute
    python3 classical_ciphers.py --text "..." --vigenere-key "KEY" --decrypt
    python3 classical_ciphers.py --text "..." --atbash
"""
import argparse
import string

ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"


def caesar_shift(text: str, shift: int) -> str:
    out = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def caesar_brute(text: str):
    for shift in range(26):
        print(f"shift={shift:2d}: {caesar_shift(text, shift)}")


def atbash(text: str) -> str:
    out = []
    for c in text:
        if c.isupper():
            out.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif c.islower():
            out.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            out.append(c)
    return "".join(out)


def vigenere(text: str, key: str, decrypt=True) -> str:
    out = []
    key = key.upper()
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('A')
            shift = -k if decrypt else k
            out.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def index_of_coincidence(text: str) -> float:
    text = [c.upper() for c in text if c.isalpha()]
    n = len(text)
    if n < 2:
        return 0.0
    freqs = {c: text.count(c) for c in set(text)}
    return sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1))


def guess_vigenere_keylen(text: str, max_len=20):
    """Basic IoC-based key length guesser."""
    letters = [c for c in text if c.isalpha()]
    results = []
    for keylen in range(1, max_len + 1):
        cols = ["".join(letters[i::keylen]) for i in range(keylen)]
        avg_ioc = sum(index_of_coincidence(c) for c in cols) / keylen
        results.append((avg_ioc, keylen))
    results.sort(reverse=True)
    return results[:5]


def main():
    ap = argparse.ArgumentParser(description="Classical cipher toolkit")
    ap.add_argument("--text", required=True)
    ap.add_argument("--caesar-brute", action="store_true")
    ap.add_argument("--shift", type=int, help="apply single caesar shift")
    ap.add_argument("--atbash", action="store_true")
    ap.add_argument("--vigenere-key")
    ap.add_argument("--decrypt", action="store_true", default=True)
    ap.add_argument("--encrypt", action="store_true")
    ap.add_argument("--guess-keylen", action="store_true", help="guess Vigenere key length via IoC")
    args = ap.parse_args()

    if args.caesar_brute:
        caesar_brute(args.text)
    elif args.shift is not None:
        print(caesar_shift(args.text, args.shift))
    elif args.atbash:
        print(atbash(args.text))
    elif args.vigenere_key:
        print(vigenere(args.text, args.vigenere_key, decrypt=not args.encrypt))
    elif args.guess_keylen:
        print("Top candidate key lengths (index of coincidence):")
        for ioc, kl in guess_vigenere_keylen(args.text):
            print(f"  keylen={kl:2d} IoC={ioc:.4f}")
    else:
        print("Specify an operation: --caesar-brute, --shift, --atbash, --vigenere-key, --guess-keylen")


if __name__ == "__main__":
    main()
