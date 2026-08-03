#!/usr/bin/env python3
"""
stego_lsb.py -- Extract least-significant-bit data from images, a common
CTF steganography technique. Also checks basic image anomalies.

Requires: pip install pillow numpy

Usage:
    python3 stego_lsb.py extract image.png --channel r --bits 1
    python3 stego_lsb.py extract image.png --channel all --bits 2
    python3 stego_lsb.py diff original.png modified.png
"""
import argparse
import numpy as np
from PIL import Image


CHANNEL_MAP = {"r": 0, "g": 1, "b": 2, "a": 3}


def extract_lsb(path, channels="r", bits=1):
    img = Image.open(path)
    arr = np.array(img)

    if channels == "all":
        chan_indices = list(range(arr.shape[2])) if arr.ndim == 3 else [0]
    else:
        chan_indices = [CHANNEL_MAP[c] for c in channels]

    bitstream = []
    flat = arr.reshape(-1, arr.shape[2]) if arr.ndim == 3 else arr.reshape(-1, 1)

    for pixel in flat:
        for ci in chan_indices:
            value = pixel[ci]
            for b in range(bits):
                bitstream.append((value >> b) & 1)

    # Pack bits into bytes
    byte_data = bytearray()
    for i in range(0, len(bitstream) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= bitstream[i + j] << j
        byte_data.append(byte)

    return bytes(byte_data)


def find_printable_runs(data, min_len=6):
    import re
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    return runs


def diff_images(path_a, path_b):
    """Compare two images pixel-by-pixel -- common trick: same image published
    twice with a hidden diff encoding a message."""
    a = np.array(Image.open(path_a).convert("RGB"))
    b = np.array(Image.open(path_b).convert("RGB"))
    if a.shape != b.shape:
        print(f"[!] Size mismatch: {a.shape} vs {b.shape}")
        return
    diff = np.where(a != b)
    coords = list(zip(*diff))
    print(f"[+] {len(coords)} differing sub-pixel values found")
    if coords:
        print("    First 20 diffs (y, x, channel):", coords[:20])


def main():
    ap = argparse.ArgumentParser(description="Image steganography LSB toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_extract = sub.add_parser("extract")
    p_extract.add_argument("image")
    p_extract.add_argument("--channel", default="r", choices=["r", "g", "b", "a", "all"])
    p_extract.add_argument("--bits", type=int, default=1, help="how many low bits per channel to extract")
    p_extract.add_argument("--out", help="write raw extracted bytes to file")

    p_diff = sub.add_parser("diff")
    p_diff.add_argument("image_a")
    p_diff.add_argument("image_b")

    args = ap.parse_args()

    if args.cmd == "extract":
        data = extract_lsb(args.image, args.channel, args.bits)
        if args.out:
            with open(args.out, "wb") as f:
                f.write(data)
            print(f"[+] Wrote {len(data)} bytes to {args.out}")
        printable = find_printable_runs(data)
        print(f"[*] Found {len(printable)} printable runs (>=6 chars):")
        for run in printable[:30]:
            print("   ", run)
    elif args.cmd == "diff":
        diff_images(args.image_a, args.image_b)


if __name__ == "__main__":
    main()
