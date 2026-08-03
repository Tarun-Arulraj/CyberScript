#!/usr/bin/env python3
"""
dlog_solver.py -- Generic discrete log solver for multiplicative-group
Diffie-Hellman CTF challenges (g^x = A mod p).

This is the missing script for Crypto_Cheatsheet.md section 7 (DH / Discrete
Log) -- the cheatsheet only had inline one-liners; this wraps them into one
tool with three escalating strategies, run in order:

    1. Brute force            -- fine for tiny p (< ~10^6)
    2. Baby-Step Giant-Step   -- O(sqrt(p)), fine up to ~10^12-ish
    3. Pohlig-Hellman         -- when p-1 (the group order) is smooth
                                  (product of small primes); delegates the
                                  per-factor solve to sympy, then CRT-combines

NOTE: this solves discrete log in Z_p^*  (classic textbook/toy DH). For
elliptic-curve discrete log, use ecc_ctf_toolkit.py instead -- the group
arithmetic is different and that script's Pohlig-Hellman skeleton is wired
for EC points, not integers mod p.

Requires: pip install sympy

Usage examples:
    # Auto: picks brute force / BSGS / Pohlig-Hellman based on p-1's factors
    python3 dlog_solver.py --p <p> --g <g> --A <A> --auto

    # Force a specific method
    python3 dlog_solver.py --p <p> --g <g> --A <A> --bruteforce
    python3 dlog_solver.py --p <p> --g <g> --A <A> --bsgs
    python3 dlog_solver.py --p <p> --g <g> --A <A> --pohlig-hellman

    # Once you have the private exponent, derive an ECDH-style shared secret
    python3 dlog_solver.py --p <p> --g <g> --A <A> --auto --derive-shared --peer-pubkey <B>
"""
import argparse
import math


def bruteforce_dlog(p, g, A, limit=None):
    """O(p) search: x such that g^x mod p == A. Only viable for small p."""
    limit = limit or p
    val = 1
    for x in range(limit):
        if val == A:
            return x
        val = (val * g) % p
    return None


def bsgs_dlog(p, g, A, order=None):
    """
    Baby-Step Giant-Step: O(sqrt(order)) time/space.
    order defaults to p-1 (full group order) if not given.
    Solves g^x = A (mod p).
    """
    order = order or (p - 1)
    m = math.isqrt(order) + 1

    # Baby steps: table of g^j -> j for j in [0, m)
    baby = {}
    e = 1
    for j in range(m):
        baby.setdefault(e, j)
        e = (e * g) % p

    # Giant steps: A * (g^-m)^i for i in [0, m)
    g_inv_m = pow(g, -m, p)
    gamma = A
    for i in range(m):
        if gamma in baby:
            x = i * m + baby[gamma]
            if pow(g, x, p) == A % p:
                return x
        gamma = (gamma * g_inv_m) % p
    return None


def pohlig_hellman_dlog(p, g, A):
    """
    Pohlig-Hellman: works when p-1 (the group order) factors into small
    primes. Solves the dlog mod each small prime-power factor (via sympy's
    discrete_log, which itself uses BSGS/Pollard-rho under the hood for
    each small piece), then recombines with CRT.
    """
    from sympy import factorint
    from sympy.ntheory.residue_ntheory import discrete_log
    from sympy.ntheory.modular import crt

    order = p - 1
    factors = factorint(order)

    residues = []
    moduli = []
    for prime, exp in factors.items():
        pe = prime ** exp
        gi = pow(g, order // pe, p)
        Ai = pow(A, order // pe, p)
        if gi == 1:
            # This factor doesn't contribute information (shouldn't normally happen)
            continue
        xi = discrete_log(p, Ai, gi)
        residues.append(xi)
        moduli.append(pe)

    if not moduli:
        return None
    x, mod = crt(moduli, residues)
    return int(x) % (p - 1), int(mod)


def auto_dlog(p, g, A):
    """
    Picks a strategy based on how smooth p-1 is:
      - fully smooth (all small factors)      -> Pohlig-Hellman (fast, exact)
      - largest prime factor still manageable -> BSGS on full group
      - otherwise                              -> brute force as last resort
    """
    from sympy import factorint
    order = p - 1
    factors = factorint(order)
    largest_factor = max(factors.keys())

    if largest_factor < 10**7:
        print(f"[*] p-1 = {order} is smooth (largest factor {largest_factor}) -> Pohlig-Hellman")
        result = pohlig_hellman_dlog(p, g, A)
        if result:
            return result[0]
        return None
    elif order < 10**14:
        print(f"[*] p-1 = {order} not fully smooth -> Baby-Step Giant-Step on full group")
        return bsgs_dlog(p, g, A)
    else:
        print("[!] Group too large for BSGS/brute force without more structure.")
        print("[!] Consider requesting SageMath for index calculus, or check if the")
        print("[!] challenge leaks partial bits / uses a known-weak generator.")
        return None


def derive_shared_secret(p, private_x, peer_pubkey):
    """Once you've recovered your own (or the target's) private exponent x,
    compute the DH shared secret against the other party's public key."""
    return pow(peer_pubkey, private_x, p)


def main():
    ap = argparse.ArgumentParser(description="Discrete log solver for DH-style CTF challenges (Z_p^*)")
    ap.add_argument("--p", type=int, required=True, help="prime modulus")
    ap.add_argument("--g", type=int, required=True, help="generator")
    ap.add_argument("--A", type=int, required=True, help="target value: solve g^x = A (mod p)")
    ap.add_argument("--auto", action="store_true", help="auto-select strategy based on p-1's factorization")
    ap.add_argument("--bruteforce", action="store_true")
    ap.add_argument("--bruteforce-limit", type=int, default=None, help="cap the brute-force search space")
    ap.add_argument("--bsgs", action="store_true")
    ap.add_argument("--pohlig-hellman", action="store_true")
    ap.add_argument("--derive-shared", action="store_true", help="after solving x, compute shared secret with --peer-pubkey")
    ap.add_argument("--peer-pubkey", type=int, help="other party's public key B (for --derive-shared)")
    args = ap.parse_args()

    x = None
    if args.bruteforce:
        x = bruteforce_dlog(args.p, args.g, args.A, args.bruteforce_limit)
    elif args.bsgs:
        x = bsgs_dlog(args.p, args.g, args.A)
    elif args.pohlig_hellman:
        result = pohlig_hellman_dlog(args.p, args.g, args.A)
        x = result[0] if result else None
    else:
        # default to auto if nothing specified
        x = auto_dlog(args.p, args.g, args.A)

    if x is None:
        print("[-] No solution found with the selected method.")
        return

    print(f"[+] Discrete log x = {x}  (verify: g^x mod p == A -> {pow(args.g, x, args.p) == args.A % args.p})")

    if args.derive_shared:
        if args.peer_pubkey is None:
            print("[!] --derive-shared requires --peer-pubkey")
            return
        secret = derive_shared_secret(args.p, x, args.peer_pubkey)
        print(f"[+] Shared secret = {secret}")


if __name__ == "__main__":
    main()
