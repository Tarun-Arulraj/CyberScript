#!/usr/bin/env python3
"""
ecc_ctf_toolkit.py -- Elliptic-curve crypto attacks for CTFs.

Covers: ECDSA nonce reuse (recover private key from two sigs sharing r/k),
ECDSA nonce-bias/LCG-style partial-nonce-leak note, small-subgroup /
Pohlig-Hellman discrete log for small-order curve groups, and invalid-curve
attack scaffolding.

Requires: pip install ecdsa sympy

Usage examples:
    # Nonce reuse: two signatures on the same curve, same r, different messages
    python3 ecc_ctf_toolkit.py --nonce-reuse --n <curve_order> \
        --r <r> --s1 <s1> --z1 <z1_hash_int> --s2 <s2> --z2 <z2_hash_int>

    # Pohlig-Hellman discrete log when the curve's group order is smooth
    # (product of small primes) -- e.g. a deliberately weak toy curve
    python3 ecc_ctf_toolkit.py --pohlig-hellman --order <group_order> \
        --generator-order <known_order_of_point>
        (see module docstring for how to wire this to a concrete curve lib)

    # Invalid-curve attack checklist (no single script covers this generically
    # since it depends on the target's curve-point validation bug)
    python3 ecc_ctf_toolkit.py --invalid-curve-notes
"""
import argparse


def ecdsa_nonce_reuse(n, r, s1, z1, s2, z2):
    """
    Recover the ECDSA private key when the same nonce k (and therefore the
    same r) was used to sign two different messages.

        s1 = k^-1 * (z1 + r*d)  (mod n)
        s2 = k^-1 * (z2 + r*d)  (mod n)

    Subtracting: k = (z1 - z2) / (s1 - s2)  (mod n)
    Then:        d = (s1*k - z1) / r        (mod n)

    n: curve group order
    r: shared signature r value (same for both signatures -- this is the
       reuse signal to look for in a set of signatures)
    s1, z1: first signature's s value and message hash (as an int, e.g.
            int.from_bytes(hashlib.sha256(msg).digest(), 'big') mod n)
    s2, z2: second signature's s value and message hash
    """
    ds = (s1 - s2) % n
    if ds == 0:
        raise ValueError("s1 == s2 -- these are the same signature, not a reuse pair")
    k = ((z1 - z2) % n) * pow(ds, -1, n) % n
    d = ((s1 * k - z1) % n) * pow(r, -1, n) % n
    return d, k


def find_nonce_reuse_pairs(signatures):
    """
    Given a list of (r, s, z) tuples, group by shared r and return every
    pair sharing the same r (candidate nonce-reuse pairs to feed into
    ecdsa_nonce_reuse). Real-world nonce reuse usually comes from a weak
    or predictable RNG rather than a literal repeated call, so scan a full
    batch of collected signatures rather than assuming just two.
    """
    from collections import defaultdict
    by_r = defaultdict(list)
    for sig in signatures:
        r, s, z = sig
        by_r[r].append((s, z))
    pairs = []
    for r, group in by_r.items():
        if len(group) >= 2:
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    (s1, z1), (s2, z2) = group[i], group[j]
                    pairs.append((r, s1, z1, s2, z2))
    return pairs


def pohlig_hellman_dlog(g_order_factors, discrete_log_mod_p_func):
    """
    Skeleton for Pohlig-Hellman: if the curve's group order (or a known
    subgroup order) factors into small primes, the discrete log problem can
    be solved piecewise mod each small prime power and recombined with CRT.

    This is intentionally a skeleton rather than a full generic
    implementation, because a working version needs actual EC point
    arithmetic (add/double/scalar-mult) tied to the specific curve library
    the challenge uses (e.g. `ecdsa`, `fastecdsa`, `pyecm`, or a raw Weierstrass
    implementation from the challenge itself). Wire it up like this:

        from sympy.ntheory.residue_ntheory import discrete_log
        # for each small prime power factor q of the group order:
        #   compute the projected point P_q = (order // q) * P
        #   compute the projected point Q_q = (order // q) * Q  (Q = target)
        #   solve x_q = discrete_log(q, Q_q, P_q)  (sympy can do small q directly,
        #       or Baby-Step-Giant-Step / Pollard's rho for larger-but-still-small q)
        # then CRT-combine all x_q with their moduli q to get the full private scalar

    g_order_factors: list of (prime, exponent) pairs from factoring the
                      group order (use sympy.factorint on the curve order)
    discrete_log_mod_p_func: your callback that does the per-factor dlog
                             (kept abstract since it needs real curve ops)
    """
    from sympy.ntheory.modular import crt
    residues = []
    moduli = []
    for prime, exponent in g_order_factors:
        modulus = prime ** exponent
        residues.append(discrete_log_mod_p_func(modulus))
        moduli.append(modulus)
    x, mod = crt(moduli, residues)
    return int(x), int(mod)


INVALID_CURVE_NOTES = """
Invalid-curve attack checklist (manual -- depends on the target's validation bug):

1. The attack applies when a server does scalar multiplication on a point
   you supply WITHOUT checking the point actually lies on the expected curve.
2. Craft points that lie on a *different*, weaker curve (same a, different b
   in the short-Weierstrass equation y^2 = x^3 + a*x + b) that has a small
   or smooth group order.
3. Send that point as your "public key" / ECDH input; the server computes
   d * P_evil using its private scalar d, on the weak curve's group structure.
4. Because the weak curve's order is smooth, solve the discrete log of the
   server's response with Pohlig-Hellman (see pohlig_hellman_dlog above) to
   recover d mod (small factors).
5. Repeat with several different weak curves/points (different small
   subgroup orders) and CRT-combine partial results to recover d fully, OR
   enough of d to brute-force the rest if the curve is small enough.

Useful tooling: sympy.factorint for order factoring, sagemath's
EllipticCurve(...).order() if you have sage available for curve arithmetic,
or write minimal Weierstrass point-add/double yourself for CTF-sized primes.
"""


def main():
    ap = argparse.ArgumentParser(description="ECC CTF attack toolkit")
    ap.add_argument("--nonce-reuse", action="store_true")
    ap.add_argument("--n", type=int, help="curve group order")
    ap.add_argument("--r", type=int)
    ap.add_argument("--s1", type=int)
    ap.add_argument("--z1", type=int)
    ap.add_argument("--s2", type=int)
    ap.add_argument("--z2", type=int)
    ap.add_argument("--invalid-curve-notes", action="store_true")
    args = ap.parse_args()

    if args.nonce_reuse:
        d, k = ecdsa_nonce_reuse(args.n, args.r, args.s1, args.z1, args.s2, args.z2)
        print(f"[+] Recovered private key d = {d}")
        print(f"[+] Recovered nonce k = {k}")
        return

    if args.invalid_curve_notes:
        print(INVALID_CURVE_NOTES)
        return

    ap.print_help()


if __name__ == "__main__":
    main()
