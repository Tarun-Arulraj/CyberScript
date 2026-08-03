#!/usr/bin/env python3
"""
xor_solver.py -- Single-byte and multi-byte (repeating-key) XOR solving.

Usage:
    python3 xor_solver.py --hex <hexstring> --single
    python3 xor_solver.py --hex <hexstring> --multi --max-keylen 40
    python3 xor_solver.py --hex <hexstring> --known "flag{" 
"""
import argparse
import string
from itertools import cycle

PRINTABLE = set(bytes(string.printable, "ascii"))


def score_english(data: bytes) -> float:
    """Simple frequency-based English scoring."""
    freq = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95,
        's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88,
        ' ': 13.0
    }
    score = 0.0
    for b in data:
        c = chr(b).lower()
        score += freq.get(c, 0)
        if b not in PRINTABLE:
            score -= 5
    return score


def single_byte_xor(data: bytes):
    results = []
    for key in range(256):
        out = bytes(b ^ key for b in data)
        results.append((score_english(out), key, out))
    results.sort(reverse=True, key=lambda x: x[0])
    return results


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keysize(data: bytes, max_keylen=40):
    scores = []
    for keysize in range(2, min(max_keylen, len(data) // 4)):
        chunks = [data[i:i+keysize] for i in range(0, len(data), keysize)][:4]
        if len(chunks) < 4:
            continue
        dist = 0
        pairs = 0
        for i in range(len(chunks) - 1):
            dist += hamming_distance(chunks[i], chunks[i+1])
            pairs += 1
        norm = (dist / pairs) / keysize
        scores.append((norm, keysize))
    scores.sort()
    return [k for _, k in scores[:5]]


def repeating_key_xor_break(data: bytes, keysize: int):
    key = bytearray()
    for i in range(keysize):
        block = data[i::keysize]
        best = single_byte_xor(block)[0]
        key.append(best[1])
    return bytes(key)


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(data, cycle(key)))


def crib_drag_key(data: bytes, crib: bytes):
    """Find key bytes at every offset where the crib might appear (known-plaintext attack)."""
    found = []
    for offset in range(len(data) - len(crib) + 1):
        segment = data[offset:offset+len(crib)]
        key_fragment = bytes(a ^ b for a, b in zip(segment, crib))
        found.append((offset, key_fragment))
    return found


def main():
    ap = argparse.ArgumentParser(description="XOR cipher solver")
    ap.add_argument("--hex", help="ciphertext as hex string")
    ap.add_argument("--file", help="path to binary ciphertext file")
    ap.add_argument("--single", action="store_true", help="single-byte XOR brute force")
    ap.add_argument("--multi", action="store_true", help="repeating-key XOR (Vigenere-style) break")
    ap.add_argument("--max-keylen", type=int, default=40)
    ap.add_argument("--known", help="known plaintext crib for crib-dragging")
    ap.add_argument("--top", type=int, default=5, help="how many results to show")
    args = ap.parse_args()

    if args.hex:
        data = bytes.fromhex(args.hex)
    elif args.file:
        data = open(args.file, "rb").read()
    else:
        print("Provide --hex or --file")
        return

    if args.known:
        print("[*] Crib-dragging for:", args.known)
        for offset, keyfrag in crib_drag_key(data, args.known.encode()):
            print(f"  offset={offset} key_fragment={keyfrag}")
        return

    if args.single:
        print("[*] Single-byte XOR brute force, top results:")
        for score, key, out in single_byte_xor(data)[:args.top]:
            print(f"  key=0x{key:02x} score={score:.1f} -> {out}")
        return

    if args.multi:
        print("[*] Guessing likely key sizes ...")
        candidates = guess_keysize(data, args.max_keylen)
        print("    candidate key sizes:", candidates)
        for ks in candidates:
            key = repeating_key_xor_break(data, ks)
            out = xor_decrypt(data, key)
            print(f"\n  keysize={ks} key={key!r}")
            print(f"  plaintext[:120]={out[:120]}")
        return

    print("Specify --single, --multi, or --known")


if __name__ == "__main__":
    main()
