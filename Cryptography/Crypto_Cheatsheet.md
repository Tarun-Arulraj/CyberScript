# Cryptography CTF Cheatsheet — Speed Edition

*Tooling note: built around OpenSSL/LibreSSL, pycryptodome/sympy/gmpy2, RsaCtfTool,
hashcat, John the Ripper, CyberChef (offline), xortool. SageMath is request-only —
only ask for it when you specifically need lattice/Coppersmith attacks (section 3).*

---

```bash
file <cipher_file>                   # sometimes "crypto" challenges are just a disguised file format
strings ciphertext.txt | head -20    # look for obvious hints (base64, hex, key= etc)
python3 -c "print(len('<ciphertext>'))"   # length often reveals block size / encoding
```

**Quick classification cheat table — what am I looking at?**

| Looks like | Likely encoding/cipher |
|---|---|
| `[A-Za-z0-9+/]+=*` | Base64 |
| `[0-9a-fA-F]+` (even length) | Hex |
| Only letters, same length as plaintext | Classical substitution (Caesar/Vigenère/Atbash) |
| `n=`, `e=`, `c=` in the prompt | RSA |
| Long integer(s), no letters | RSA / discrete log / big-int crypto |
| `iv=`, `ct=`, block-aligned (multiple of 16 bytes) | AES (likely CBC/ECB/CTR) |
| Repeating ciphertext blocks | AES-ECB |
| `p=`, `g=`, `A=`, `B=` | Diffie-Hellman |
| Matrix / grid of numbers | Hill cipher |
| `-----BEGIN ... KEY-----` | PEM key material |
| JWT-looking (`eyJ...`) | JSON Web Token |
| `flag{` fragments split across lines with weird spacing | XOR / stream cipher |

---

## 1. Encoding / Data Transforms (do this FIRST, always)

```bash
echo "<data>" | base64 -d                       # base64 decode
echo "<data>" | base64 -d | base64 -d           # double-encoded (common trick)
echo -n "48656c6c6f" | xxd -r -p                # hex -> ascii
python3 -c "print(bytes.fromhex('<hex>'))"      # hex -> ascii, alt
echo "<data>" | rev                             # reversed string
echo "<data>" | tr 'A-Za-z' 'N-ZA-Mn-za-m'      # ROT13
echo "<data>" | tr 'A-Za-z' 'B-ZAb-za'          # ROT1 (adjust shift by changing offset)
python3 -c "import base32; print(base32.b32decode('<data>'))"   # base32
echo "<data>" | basenc --base32 -d              # base32 decode via coreutils
echo "<data>" | basenc --base85 -d              # ascii85 / base85 decode
python3 -c "print(int('<data>', 2))"            # binary string -> int
echo "<data>" | tr -d ' ' | fold -w8 | while read b; do printf "\\$(printf '%03o' "$((2#$b))")"; done   # binary -> ascii, manual
```

**CyberChef is your best friend for chained/unknown encodings** — "Magic" wand icon auto-detects; always try it before writing custom code for a multi-layer encoding puzzle.

---

## 2. Classical Ciphers

```bash
# Caesar - brute force all 26 shifts
for i in $(seq 0 25); do echo "$i: $(echo '<ciphertext>' | tr 'A-Za-z' "$(python3 -c "import string;a=string.ascii_lowercase;print((a[$i:]+a[:$i]).upper()+(a[$i:]+a[:$i]))")")"; done

# or just use CyberChef "ROT13 Brute Force" / "Caesar Cipher Brute Force" recipe

# Vigenere - if key length unknown, use Index of Coincidence to guess length, then crack per-column
# (use classical_ciphers.py --guess-keylen from your toolkit)

# Atbash
echo "<ciphertext>" | tr 'A-Za-z' 'Z-Az-a'

# Substitution cipher - use quipqiup.com or dcode.fr for automated solving via frequency analysis
```

**Frequency analysis reference (English letter frequency, most to least common):**
`E T A O I N S H R D L C U M W F G Y P B V K J X Q Z`

**Common CTF classical-cipher tells:**
- All-caps, no spaces, same length as expected plaintext → substitution family
- Key-length hint given ("5-letter key") → straight to Vigenère per-column crack
- Numbers only, 1–25 or 1–26 range → A1Z26 (letter position cipher)
- Grid/table given in challenge → Playfair or Hill cipher

---

## 3. RSA

**RsaCtfTool — ALWAYS run this first, it automates ~90% of RSA CTF weaknesses in one shot:**
```bash
python3 RsaCtfTool.py --publickey key.pub --uncipherfile cipher.bin
python3 RsaCtfTool.py -n <N> -e <e> --uncipher <c>
python3 RsaCtfTool.py --publickey key.pub --uncipherfile cipher.bin --attack fermat,wiener,commonmodulus
python3 RsaCtfTool.py --publickey key.pub --private              # just recover the private key
python3 RsaCtfTool.py --publickey key.pub --uncipherfile cipher.bin -v   # verbose, shows which attack worked
```
It chains: Fermat, Wiener, Hastad broadcast, common factors/modulus, small-e, factordb lookup,
Pollard p-1/rho, and more — only fall back to manual attacks (below) if it fails or you need
to understand *why* an attack worked for a writeup.

```bash
# Factor small/medium N manually (fallback if RsaCtfTool doesn't have it)
python3 -c "
from sympy import factorint
print(factorint(<N>))
"

# Query factordb.com directly (RsaCtfTool does this too, but useful standalone)
curl "http://factordb.com/api?query=<N>"
```

**Manual attack reference (for understanding / when RsaCtfTool misses something):**

| Weakness in the challenge | Attack |
|---|---|
| Small `e` (e.g. e=3) and no padding | Small-e root attack — `m = c^(1/e)` |
| `p` and `q` are close together | Fermat factorization |
| Small private exponent `d` | Wiener's attack (continued fractions) |
| Same message, same `n`, different `e` | Common modulus attack |
| Same `n` used across multiple users | Common factor via GCD of all N's |
| Partial bits of `p`/`q`/`d` leaked | Coppersmith's attack — **request SageMath** for this one, `fpylll`/`sympy` alone are painful for lattice reduction |
| `n` factors are in factordb | Just factor it and decrypt manually |
| Multiple ciphertexts, same plaintext, different `n` | Hastad's broadcast attack (CRT) |

```bash
# Manual decrypt once you have p, q, e, c
python3 -c "
from Crypto.Util.number import inverse, long_to_bytes
p = <p>; q = <q>; e = <e>; c = <c>
n = p*q
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)))
"

# GCD across multiple N's (common-factor attack, needs multiple public keys)
python3 -c "
from math import gcd
Ns = [<n1>, <n2>, <n3>]
for i in range(len(Ns)):
    for j in range(i+1, len(Ns)):
        g = gcd(Ns[i], Ns[j])
        if g != 1:
            print(f'Shared factor between N{i} and N{j}: {g}')
"
```

---

## 4. AES / Block Ciphers

```bash
# Detect ECB (repeated ciphertext blocks = ECB, 16-byte blocks)
python3 -c "
ct = bytes.fromhex('<hex_ciphertext>')
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
print('ECB likely' if len(blocks) != len(set(blocks)) else 'no repeats found')
"
```

| Mode given | What to look for | Attack |
|---|---|---|
| ECB | Repeated ciphertext blocks | Byte-at-a-time decryption via oracle, or block shuffling |
| CBC | You control plaintext prefix, `IV` reused/known | Bit-flipping attack on the following block |
| CBC | Server leaks "padding valid/invalid" | Padding oracle attack (decrypt without the key) |
| CTR/OFB/stream | Same key/nonce reused across two messages | XOR the ciphertexts together → XOR of plaintexts (crib-drag or known-plaintext) |
| GCM | Nonce reused | Forbidden attack — recover authentication key |
| Any | Key looks like a hash of something guessable (e.g. `md5(username)`) | Just recompute the key yourself |

```bash
# Quick AES decrypt once you have the key (CBC example)
python3 -c "
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
key = bytes.fromhex('<key_hex>')
iv = bytes.fromhex('<iv_hex>')
ct = bytes.fromhex('<ciphertext_hex>')
cipher = AES.new(key, AES.MODE_CBC, iv)
print(unpad(cipher.decrypt(ct), 16))
"
```

---

## 5. XOR

**xortool — automatic key-length detection + key recovery, try this first:**
```bash
xortool ciphertext.bin                          # guesses key length + likely key via frequency analysis
xortool ciphertext.bin -l 4                      # force a specific key length if you know/suspect it
xortool ciphertext.bin -c 20                     # specify the most common plaintext byte (default is space=0x20)
xortool -x ciphertext.bin                        # treat input as hex-encoded rather than raw bytes
```

**Manual fallback (when xortool's guesses don't pan out, or for single-byte cases):**
```bash
# Single-byte XOR brute force
python3 -c "
ct = bytes.fromhex('<hex>')
for k in range(256):
    pt = bytes(b ^ k for b in ct)
    if all(32 <= c < 127 for c in pt):
        print(k, pt)
"

# XOR two equal-length hex strings (e.g. ciphertext vs known plaintext -> recovers key)
python3 -c "
a = bytes.fromhex('<hex1>')
b = bytes.fromhex('<hex2>')
print(bytes(x^y for x,y in zip(a,b)))
"

# Repeating-key XOR (use xor_solver.py --multi from toolkit for keysize guessing)
```

**XOR crib-dragging tip:** if you suspect the plaintext contains `"flag{"` or a common word, XOR that guess against the ciphertext at every offset — wherever the output looks like readable text, you've likely found (part of) the key.

---

## 6. Hashing

```bash
# hashid isn't in your toolset -- identify by length/format instead (see table below),
# or let hashcat/john's auto-detect handle it:
hashcat --identify hash.txt                       # hashcat's built-in mode-guessing (newer versions)
john --format=auto hash.txt --wordlist=rockyou.txt   # john auto-detects format on its own

echo -n "test" | md5sum                           # generate known hash to compare
john --wordlist=rockyou.txt hash.txt
hashcat -m 0 hash.txt rockyou.txt --show          # -m 0=MD5, 100=SHA1, 1400=SHA256, 1700=SHA512

# Length-extension attack (when you can append to a message + its hash, but not the key)
hashpump -s '<known_hash>' -d '<known_message>' -a '<data_to_append>' -k <keylen_guess>
```

**Hash length quick ID (hex chars):** MD5=32, SHA1=40, SHA224=56, SHA256=64, SHA384=96, SHA512=128

---

## 7. Diffie-Hellman / Discrete Log

```bash
# Small prime p -> brute-force discrete log
python3 -c "
p = <p>; g = <g>; A = <A>
for x in range(p):
    if pow(g, x, p) == A:
        print('private key:', x)
        break
"

# Pohlig-Hellman (when p-1 has small factors) - use sympy's discrete_log
python3 -c "
from sympy.ntheory.residue_ntheory import discrete_log
print(discrete_log(<p>, <A>, <g>))
"
```

---

## 8. Elliptic Curve Crypto (ECC)

| Weakness | Attack |
|---|---|
| Small curve order / weak curve params | Brute-force discrete log directly |
| Nonce (`k`) reused across signatures | Recover private key from two ECDSA signatures algebraically |
| Invalid curve points accepted | Invalid curve attack |
| Curve order is smooth (many small factors) | Pohlig-Hellman on the curve group |

```bash
# ECDSA nonce-reuse key recovery (given two sigs (r,s1),(r,s2) with same r, msgs m1,m2, curve order n)
python3 -c "
from Crypto.Util.number import inverse
r, s1, s2, m1_hash, m2_hash, n = <r>, <s1>, <s2>, <h1>, <h2>, <n>
k = ((m1_hash - m2_hash) * inverse(s1 - s2, n)) % n
priv = ((s1*k - m1_hash) * inverse(r, n)) % n
print('private key:', priv)
"
```

---

## 9. PRNG / LCG Attacks (z3-solver)

Common in "predict the next random number" or "guess the seed" crypto challenges.

```python
from z3 import *

# Example: Linear Congruential Generator, state_{n+1} = (a*state_n + c) mod m
# Given a few observed outputs, recover the seed/state to predict future outputs
a, c, m = <a>, <c>, <m>
seed = BitVec('seed', 64)
s = Solver()

state = seed
observed = [<obs1>, <obs2>, <obs3>]   # values you've seen so far
for obs in observed:
    state = (a * state + c) % m
    s.add(state == obs)

if s.check() == sat:
    print(s.model())
```

Also reach for z3 when a challenge gives you a system of modular equations, a
hash-like transform with recoverable structure, or any "find x such that..." puzzle
that isn't a named classical attack — it's often faster than deriving the algebra
by hand.

---

## 10. OpenSSL / LibreSSL (CLI crypto swiss-army knife)

```bash
# Inspect a key/cert given in the challenge
openssl x509 -in cert.pem -text -noout                  # dump a certificate's fields
openssl rsa -in key.pem -text -noout                     # dump an RSA private key's p/q/n/e/d directly
openssl rsa -pubin -in pubkey.pem -text -noout           # dump a public key's n/e
openssl asn1parse -in key.pem                            # low-level ASN.1 structure (when the PEM is malformed/custom)

# Convert formats (challenges sometimes give a weird format)
openssl rsa -in key.pem -pubout -out pubkey.pem          # derive public key from a private key
openssl pkey -in key.der -inform DER -out key.pem -outform PEM   # DER -> PEM

# Try decrypting with a guessed/given key (quick manual attempt before scripting)
openssl enc -d -aes-256-cbc -in ciphertext.bin -out plaintext.bin -K <key_hex> -iv <iv_hex>
openssl enc -d -aes-128-ecb -in ciphertext.bin -out plaintext.bin -K <key_hex> -nopad

# RSA encrypt/decrypt directly from the CLI (no Python needed for a quick check)
openssl pkeyutl -decrypt -inkey key.pem -in ciphertext.bin -out plaintext.bin
openssl rsautl -decrypt -inkey key.pem -in ciphertext.bin      # older syntax, some versions still need this

# Generate a keypair to test your own understanding of an attack before hitting the real target
openssl genrsa -out test_key.pem 512              # deliberately weak/small key for testing small-N attacks locally
```

---

## 11. Important greps / quick checks

```bash
grep -oE "flag\{[^}]{1,100}\}" file                        # bounded flag pattern
strings file | grep -oE "[A-Za-z0-9+/]{20,}={0,2}"          # base64-looking blobs
strings file | grep -A2 "BEGIN.*PRIVATE KEY"                # leaked key material
python3 -c "print(int('<suspicious_number>').bit_length())" # bit length hints RSA key size (1024/2048/4096)
```

---

## 12. Quick Reference — CTF Triage Checklist

**Unknown ciphertext, no context:**
```
Check length/charset → base64/hex decode → CyberChef Magic (offline) →
if looks like letters only: classical cipher → if numbers: RSA/DH (try RsaCtfTool) →
if block-aligned bytes: AES → if garbled but same length as plaintext: try xortool first, then manual XOR
```

**RSA challenge:**
```
Run RsaCtfTool against the pubkey/ciphertext first, always →
if it fails: factordb.com the N manually → check e (small?) → check if p,q close (Fermat) →
check for multiple N's (common factor/common modulus) → Wiener if d looks small →
only then consider Coppersmith/lattice attacks (request SageMath at this point)
```

**AES challenge:**
```
Identify mode (ECB/CBC/CTR/GCM) → check for repeated blocks (ECB) →
check for reused IV/nonce (CTR/GCM) → check if oracle leaks padding validity (CBC) →
check if you control any plaintext (bit-flip / byte-at-a-time)
```

**"Crack this hash" challenge:**
```
hashid → check length-extension possibility (if hash+message, no key visible) →
rockyou.txt via hashcat/john → if salted, check challenge source for salt →
if it's a KDF (bcrypt/scrypt/argon2), don't bother brute-forcing without a small wordlist hint
```

---
