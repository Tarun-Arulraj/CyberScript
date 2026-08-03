#!/usr/bin/env python3
"""
aes_ctf_toolkit.py -- Common AES attack patterns seen in CTF crypto:
ECB detection, ECB byte-at-a-time decryption, CBC bit-flipping,
and a padding-oracle attack skeleton to plug into a live oracle.

Requires: pip install pycryptodome requests

Usage:
    python3 aes_ctf_toolkit.py detect-ecb <hexciphertext>
    python3 aes_ctf_toolkit.py bitflip --known-plaintext-offset 16 --target " admin=true"
"""
import argparse
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


def detect_ecb(ciphertext: bytes, block_size=16):
    """ECB mode reuses identical ciphertext blocks for identical plaintext blocks."""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    seen = set()
    dupes = 0
    for b in blocks:
        if b in seen:
            dupes += 1
        seen.add(b)
    print(f"[*] {len(blocks)} blocks, {dupes} duplicate block(s)")
    if dupes > 0:
        print("[+] Likely ECB mode (repeated blocks detected)")
    else:
        print("[-] No repeated blocks -- probably CBC/CTR/GCM or short input")
    return dupes > 0


def ecb_byte_at_a_time_skeleton():
    """Skeleton for the classic ECB byte-at-a-time decryption attack.
    Plug in `encrypt_oracle(data)` = the server's `AES-ECB(attacker_input + secret)`."""
    code = '''
def encrypt_oracle(data: bytes) -> bytes:
    """Replace with actual call to the target (local function or network request)."""
    raise NotImplementedError

BLOCK_SIZE = 16

def discover_block_size():
    base_len = len(encrypt_oracle(b""))
    for i in range(1, 64):
        new_len = len(encrypt_oracle(b"A" * i))
        if new_len != base_len:
            return new_len - base_len
    raise RuntimeError("Could not determine block size")

def decrypt_secret():
    block_size = discover_block_size()
    assert detect_ecb_bool(encrypt_oracle(b"A" * block_size * 3))  # confirm ECB first
    secret_len = len(encrypt_oracle(b""))
    known = b""
    for i in range(secret_len):
        pad_len = block_size - 1 - (len(known) % block_size)
        padding = b"A" * pad_len
        target_block_index = len(known) // block_size
        target = encrypt_oracle(padding)[target_block_index*block_size:(target_block_index+1)*block_size]
        found = False
        for byte in range(256):
            guess = padding + known + bytes([byte])
            test_block = encrypt_oracle(guess)[target_block_index*block_size:(target_block_index+1)*block_size]
            if test_block == target:
                known += bytes([byte])
                found = True
                break
        if not found:
            break  # likely hit padding
    return known
'''
    print(code)


def cbc_bitflip(ciphertext: bytes, known_plaintext_block: bytes, target_plaintext: bytes,
                 target_block_offset: int, block_size=16):
    """
    Classic CBC bit-flipping: flipping bits in ciphertext block N flips the
    corresponding bits in plaintext block N+1 after decryption (with garbage
    in block N). Use when you control input that ends up in one block and
    need to flip a later block (e.g. "user=guest" -> "user=admin").
    """
    if len(known_plaintext_block) != len(target_plaintext):
        raise ValueError("known_plaintext_block and target_plaintext must be same length")

    ct = bytearray(ciphertext)
    prev_block_start = target_block_offset - block_size
    if prev_block_start < 0:
        raise ValueError("target_block_offset must be >= block_size (need a previous block to flip)")

    for i in range(len(target_plaintext)):
        ct[prev_block_start + i] ^= known_plaintext_block[i] ^ target_plaintext[i]

    print("[+] Modified ciphertext (hex):", bytes(ct).hex())
    print("[!] Note: the block immediately before the target block will now decrypt to garbage.")
    return bytes(ct)


def padding_oracle_skeleton():
    """Skeleton for a full padding-oracle attack against a live oracle endpoint.
    For real engagements, prefer the battle-tested `padding-oracle-attack` /
    PadBuster / `python-paddingoracle` libraries -- this shows the core loop."""
    code = '''
import requests

BLOCK_SIZE = 16

def oracle(ciphertext: bytes) -> bool:
    """Return True if the server responds indicating VALID padding, False otherwise.
    Replace with actual request to the target (adjust endpoint/param as needed)."""
    r = requests.post("http://target/decrypt", data={"ct": ciphertext.hex()})
    return "padding error" not in r.text.lower()

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    intermediate = bytearray(BLOCK_SIZE)
    for pad_val in range(1, BLOCK_SIZE + 1):
        pos = BLOCK_SIZE - pad_val
        found = False
        for guess in range(256):
            crafted_prev = bytearray(BLOCK_SIZE)
            crafted_prev[pos] = guess
            for i in range(pos + 1, BLOCK_SIZE):
                crafted_prev[i] = intermediate[i] ^ pad_val
            if oracle(bytes(crafted_prev) + target_block):
                intermediate[pos] = guess ^ pad_val
                found = True
                break
        if not found:
            raise RuntimeError(f"No valid byte found at position {pos}")
    plaintext = bytes(a ^ b for a, b in zip(intermediate, prev_block))
    return plaintext

def decrypt_ciphertext(iv: bytes, ciphertext: bytes) -> bytes:
    blocks = [iv] + [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext = b""
    for i in range(1, len(blocks)):
        plaintext += decrypt_block(blocks[i-1], blocks[i])
    return plaintext
'''
    print(code)


def main():
    ap = argparse.ArgumentParser(description="AES CTF attack toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ecb = sub.add_parser("detect-ecb")
    p_ecb.add_argument("hex")

    sub.add_parser("ecb-byte-at-a-time")   # prints skeleton code
    sub.add_parser("padding-oracle")        # prints skeleton code

    p_flip = sub.add_parser("bitflip")
    p_flip.add_argument("--ciphertext-hex", required=True)
    p_flip.add_argument("--known-plaintext-block", required=True, help="the known plaintext at target_block_offset..+len")
    p_flip.add_argument("--target", required=True, help="desired plaintext to flip into that block")
    p_flip.add_argument("--offset", type=int, required=True, help="byte offset of target block (must be multiple of 16, >=16)")

    args = ap.parse_args()

    if args.cmd == "detect-ecb":
        detect_ecb(bytes.fromhex(args.hex))
    elif args.cmd == "ecb-byte-at-a-time":
        ecb_byte_at_a_time_skeleton()
    elif args.cmd == "padding-oracle":
        padding_oracle_skeleton()
    elif args.cmd == "bitflip":
        cbc_bitflip(
            bytes.fromhex(args.ciphertext_hex),
            args.known_plaintext_block.encode(),
            args.target.encode(),
            args.offset,
        )


if __name__ == "__main__":
    main()
