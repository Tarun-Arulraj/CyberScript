#!/usr/bin/env python3
"""
prng_lcg_solver.py -- LCG (Linear Congruential Generator) seed/state
recovery and prediction for "predict the next random number" CTF challenges.

This is the missing script for Crypto_Cheatsheet.md section 9 (PRNG/LCG,
z3-solver) -- the cheatsheet only had an inline z3 code block; this wraps
that pattern plus a couple of stronger fallbacks into one tool.

State: state_{n+1} = (a * state_n + c) mod m

Three modes, in order of how much you're given:
    --known-params     you know a, c, m -- just recover the seed/state from
                        a few observed outputs (z3, matches the cheatsheet's
                        inline example)
    --recover-modulus   you know a, c but NOT m -- recover m from consecutive
                        outputs via GCD of differences (classic technique,
                        no z3 needed, exact)
    --recover-all       you know NONE of a, c, m -- recover all three from
                        enough consecutive outputs (needs >= 6 outputs for
                        reliable GCD-based recovery), then the seed

Requires: pip install z3-solver
(--recover-modulus and --recover-all use only stdlib math -- z3 only needed
for --known-params, or if you pass --use-z3 to double check with the solver)

Usage examples:
    python3 prng_lcg_solver.py --known-params --a <a> --c <c> --m <m> \\
        --observed 12345 67890 11111 --predict 3

    python3 prng_lcg_solver.py --recover-modulus --a <a> --c <c> \\
        --observed 12345 67890 11111 22222

    python3 prng_lcg_solver.py --recover-all \\
        --observed 12345 67890 11111 22222 33333 44444 55555
"""
import argparse
from math import gcd
from functools import reduce


def known_params_recover_seed(a, c, m, observed, bits=64):
    """
    z3 approach (matches the cheatsheet's inline example): given a, c, m and
    a handful of observed consecutive outputs, solve for the seed such that
    replaying the LCG reproduces them.
    """
    from z3 import BitVec, Solver, sat

    seed = BitVec('seed', bits)
    s = Solver()
    state = seed
    for obs in observed:
        state = (a * state + c) % m
        s.add(state == obs)

    if s.check() == sat:
        model = s.model()
        return model[seed].as_long()
    return None


def recover_modulus(a, c, observed):
    """
    When a and c are known but m isn't: for an LCG, the differences
    T_i = state_{i+1} - a*state_i - c are all multiples of m. GCD enough of
    them together and you very likely recover the exact modulus (or a small
    multiple of it -- sanity check against known moduli like 2**32/2**48).
    Needs >= 3 observed outputs.
    """
    if len(observed) < 3:
        raise ValueError("need at least 3 observed outputs to recover modulus")
    diffs = []
    for i in range(len(observed) - 1):
        t = observed[i + 1] - a * observed[i] - c
        diffs.append(t)
    m = reduce(gcd, diffs)
    return abs(m)


def recover_all_params(observed):
    """
    Full blind recovery: none of a, c, m known. Classic approach (Plumstead/
    'cracking unknown LCG' technique):

      1. Build first differences  T_i  = X_{i+2} - X_{i+1}  and
                                   T_i' = X_{i+1} - X_i
      2. m = gcd of (T_{i+1}*T_{i-1} - T_i^2) terms across several i
         (this cancels out 'a' and isolates a multiple of m)
      3. Once m is known: a = (X_{i+2} - X_{i+1}) * inverse(X_{i+1} - X_i, m) mod m
      4. c = (X_{i+1} - a*X_i) mod m

    Needs >= 6 observed consecutive outputs to be reliable (more is better --
    noisy/insufficient data can recover a wrong multiple of m).
    """
    if len(observed) < 6:
        raise ValueError("need at least 6 observed outputs for reliable blind recovery")

    diffs = [observed[i + 1] - observed[i] for i in range(len(observed) - 1)]

    # zi = diffs[i+1]*diffs[i-1] - diffs[i]^2, gcd across all -> multiple of m
    zs = []
    for i in range(1, len(diffs) - 1):
        z = diffs[i + 1] * diffs[i - 1] - diffs[i] * diffs[i]
        zs.append(z)
    m = reduce(gcd, zs)
    m = abs(m)

    if m == 0:
        return None

    # Recover a using modular inverse of a difference mod m
    a = None
    for i in range(len(diffs) - 1):
        d0, d1 = diffs[i], diffs[i + 1]
        try:
            a = (d1 * pow(d0, -1, m)) % m
            break
        except ValueError:
            continue  # d0 not invertible mod m, try next pair

    if a is None:
        return None

    c = (observed[1] - a * observed[0]) % m
    return a, c, m


def predict_next(a, c, m, seed, count):
    """Replay the LCG forward from a known seed/state to predict future outputs."""
    state = seed
    outputs = []
    for _ in range(count):
        state = (a * state + c) % m
        outputs.append(state)
    return outputs


def main():
    ap = argparse.ArgumentParser(description="LCG seed/state/parameter recovery for CTF PRNG challenges")
    ap.add_argument("--observed", type=int, nargs="+", required=True,
                     help="consecutive observed LCG outputs, in order")

    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--known-params", action="store_true", help="a, c, m all known -- recover seed via z3")
    mode.add_argument("--recover-modulus", action="store_true", help="a, c known, m unknown -- recover m via GCD")
    mode.add_argument("--recover-all", action="store_true", help="none known -- blind recovery of a, c, m")

    ap.add_argument("--a", type=int, help="multiplier (for --known-params / --recover-modulus)")
    ap.add_argument("--c", type=int, help="increment (for --known-params / --recover-modulus)")
    ap.add_argument("--m", type=int, help="modulus (for --known-params)")
    ap.add_argument("--bits", type=int, default=64, help="bitvector width for z3 seed search (default 64)")
    ap.add_argument("--predict", type=int, default=0, help="predict N more outputs after recovery")
    args = ap.parse_args()

    if args.known_params:
        if args.a is None or args.c is None or args.m is None:
            print("[!] --known-params requires --a --c --m")
            return
        seed = known_params_recover_seed(args.a, args.c, args.m, args.observed, bits=args.bits)
        if seed is None:
            print("[-] z3 found no satisfying seed -- double check a/c/m and bitwidth")
            return
        print(f"[+] Recovered seed/initial-state = {seed}")
        if args.predict:
            preds = predict_next(args.a, args.c, args.m, args.observed[-1], args.predict)
            print(f"[+] Next {args.predict} predicted outputs: {preds}")

    elif args.recover_modulus:
        if args.a is None or args.c is None:
            print("[!] --recover-modulus requires --a --c")
            return
        m = recover_modulus(args.a, args.c, args.observed)
        print(f"[+] Recovered modulus m = {m}")
        print("    (sanity check: common moduli are 2**31-1, 2**32, 2**48, 2**64.")
        print("     GCD can return an exact SMALL MULTIPLE of the true m -- if m doesn't")
        print("     match a known constant, try m // 2, m // 3, etc. and re-derive/predict.)")
        if args.predict:
            preds = predict_next(args.a, args.c, m, args.observed[-1], args.predict)
            print(f"[+] Next {args.predict} predicted outputs: {preds}")

    elif args.recover_all:
        result = recover_all_params(args.observed)
        if result is None:
            print("[-] Blind recovery failed -- try more observed outputs (8-10+)")
            return
        a, c, m = result
        print(f"[+] Recovered a = {a}")
        print(f"[+] Recovered c = {c}")
        print(f"[+] Recovered m = {m}")
        print("    (m may be an exact small multiple of the true modulus -- if it doesn't")
        print("     match a known constant like 2**31/2**32/2**48/2**64, try m // 2, m // 3,")
        print("     etc. Predicted outputs below are still correct mod the TRUE m even if")
        print("     the recovered m is a multiple -- reduce further if they look too large.)")
        if args.predict:
            preds = predict_next(a, c, m, args.observed[-1], args.predict)
            print(f"[+] Next {args.predict} predicted outputs: {preds}")


if __name__ == "__main__":
    main()
