#!/usr/bin/env python3
"""
rsa_toolkit.py -- Common RSA CTF attacks in one place.

Requires: pip install pycryptodome sympy gmpy2 requests

Usage examples:
    python3 rsa_toolkit.py --n <n> --e <e> --c <c> --auto
    python3 rsa_toolkit.py --n <n> --e 3 --c <c> --small-e
    python3 rsa_toolkit.py --n <n> --c1 <c1> --e1 <e1> --c2 <c2> --e2 <e2> --common-modulus
    python3 rsa_toolkit.py --n <n> --e <e> --wiener

Offline / no-internet venues (e.g. InCTF Finals-style rules):
    Add --offline to skip the factordb.com lookup entirely (the only network
    call in this script). Works the same as normal otherwise -- no separate
    file needed.

    python3 rsa_toolkit.py --n <n> --e <e> --c <c> --auto --offline
    python3 rsa_toolkit.py --n <n> --factordb --offline   # explicit factordb request while offline -> clear error, no hang
"""
import argparse

try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False

from Crypto.Util.number import long_to_bytes, inverse


def isqrt(n):
    if HAVE_GMPY2:
        return int(gmpy2.isqrt(n))
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def fermat_factor(n, max_steps=2_000_000):
    """Good when p and q are close together."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def small_e_attack(c, e, n):
    """When e is tiny (e.g. e=3) and m^e < n, plaintext = integer e-th root of c."""
    if HAVE_GMPY2:
        m, exact = gmpy2.iroot(c, e)
        if exact:
            return int(m)
    lo, hi = 0, 1
    while hi ** e < c:
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** e < c:
            lo = mid + 1
        else:
            hi = mid
    if lo ** e == c:
        return lo
    return None


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def common_modulus_attack(n, c1, e1, c2, e2):
    """Same message encrypted twice under same n with coprime exponents."""
    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        raise ValueError("e1, e2 not coprime, attack won't work directly")
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


def wiener_attack(e, n):
    """Wiener's attack for small private exponent d. Requires sympy."""
    from sympy import continued_fraction_convergents, continued_fraction_iterator, Rational

    cf = continued_fraction_iterator(Rational(e, n))
    convergents = continued_fraction_convergents(cf)
    for conv in convergents:
        k = conv.numerator
        d = conv.denominator
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq != disc:
            continue
        p = (b + sq) // 2
        q = (b - sq) // 2
        if p * q == n:
            return d, p, q
    return None


def factordb_lookup(n):
    """Query factordb.com for known factorizations (needs internet)."""
    import requests
    r = requests.get("http://factordb.com/api", params={"query": n}, timeout=10)
    data = r.json()
    factors = [int(f[0]) for f in data.get("factors", [])]
    return factors


def decrypt_with_pq(p, q, e, c):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    return long_to_bytes(m)


def main():
    ap = argparse.ArgumentParser(description="RSA CTF attack toolkit")
    ap.add_argument("--n", type=int)
    ap.add_argument("--e", type=int)
    ap.add_argument("--c", type=int)
    ap.add_argument("--c1", type=int)
    ap.add_argument("--e1", type=int)
    ap.add_argument("--c2", type=int)
    ap.add_argument("--e2", type=int)
    ap.add_argument("--p", type=int)
    ap.add_argument("--q", type=int)
    ap.add_argument("--small-e", action="store_true")
    ap.add_argument("--fermat", action="store_true")
    ap.add_argument("--wiener", action="store_true")
    ap.add_argument("--common-modulus", action="store_true")
    ap.add_argument("--factordb", action="store_true")
    ap.add_argument("--offline", action="store_true",
                     help="skip factordb.com lookup (no internet available) -- everything else is already local")
    ap.add_argument("--auto", action="store_true", help="try everything sensible")
    args = ap.parse_args()

    if args.p and args.q and args.e and args.c:
        print("[*] Decrypting with known p, q ...")
        print(decrypt_with_pq(args.p, args.q, args.e, args.c))
        return

    if args.small_e or (args.auto and args.e and args.e <= 5):
        print("[*] Trying small-e root attack ...")
        m = small_e_attack(args.c, args.e, args.n)
        if m:
            print("[+] Recovered plaintext:", long_to_bytes(m))
            return
        print("[-] Small-e attack failed")

    if args.fermat or args.auto:
        print("[*] Trying Fermat factorization (p, q close) ...")
        res = fermat_factor(args.n)
        if res:
            p, q = res
            print(f"[+] Factors found: p={p} q={q}")
            if args.e and args.c:
                print(decrypt_with_pq(p, q, args.e, args.c))
            return
        print("[-] Fermat factorization failed within step limit")

    if args.wiener or args.auto:
        print("[*] Trying Wiener's attack (small d) ...")
        res = wiener_attack(args.e, args.n)
        if res:
            d, p, q = res
            print(f"[+] Found d={d}, p={p}, q={q}")
            if args.c:
                n = p * q
                print(long_to_bytes(pow(args.c, d, n)))
            return
        print("[-] Wiener's attack failed")

    if args.common_modulus:
        print("[*] Trying common modulus attack ...")
        m = common_modulus_attack(args.n, args.c1, args.e1, args.c2, args.e2)
        print(long_to_bytes(m))
        return

    if args.factordb or args.auto:
        if args.offline:
            if args.factordb:
                print("[!] --factordb requested but --offline is set -- skipping (no internet available).")
            # (--auto with --offline: silently skip, everything else already ran)
        else:
            print("[*] Querying factordb.com ...")
            try:
                factors = factordb_lookup(args.n)
                print("[+] Factors:", factors)
            except Exception as ex:
                print("[-] factordb lookup failed:", ex)


if __name__ == "__main__":
    main()
