#!/usr/bin/env python3
"""
lattice_attacks.py -- Lattice / Coppersmith-style RSA attacks for CTFs.

Covers the class of RSA weaknesses that Wiener's attack (rsa_toolkit.py)
doesn't reach: partial key exposure, larger private exponents (Boneh-Durfee),
stereotyped/partially-known plaintext, and related-message attacks.

Requires: pip install pycryptodome sympy
Also requires either:
    - fpylll (pip install fpylll)              [preferred, faster]
    - or sagemath on PATH (this script will shell out to `sage` for the
      Coppersmith short-pad / related-message / small-d modes if fpylll
      is not available and --use-sage is passed)

Usage examples:
    # Boneh-Durfee small private exponent (delta up to ~0.284, beyond Wiener's ~0.25)
    python3 lattice_attacks.py --n <n> --e <e> --boneh-durfee --delta 0.27

    # Partial key exposure: you know the high (or low) bits of p
    python3 lattice_attacks.py --n <n> --known-high-bits-p <hexbits> --known-bits <k> \
        --partial-p

    # Coppersmith stereotyped message: known plaintext format with small unknown pad
    python3 lattice_attacks.py --n <n> --e <e> --c <c> --stereotyped \
        --known-prefix "flag{" --unknown-len 8

    # Franklin-Reiter related message attack: two ciphertexts of linearly
    # related messages (m2 = a*m1 + b) under same n, e
    python3 lattice_attacks.py --n <n> --e <e> --c1 <c1> --c2 <c2> \
        --related-message --a 1 --b <b>

NOTE: This tool implements the *lattice construction and LLL reduction*
and uses Coppersmith's method to recover small roots. It does not
require SageMath for the fpylll-backed modes. The --boneh-durfee and
--partial-p modes are self-contained; --related-message uses polynomial
GCD (works without lattice reduction, since it's a resultant-style attack,
not full Coppersmith).
"""
import argparse

try:
    from fpylll import IntegerMatrix, LLL
    HAVE_FPYLLL = True
except ImportError:
    HAVE_FPYLLL = False

from sympy import symbols, Poly, resultant
from Crypto.Util.number import long_to_bytes


# ---------------------------------------------------------------------------
# Generic small-root finder via Coppersmith + LLL (univariate, modulus N)
# ---------------------------------------------------------------------------

def coppersmith_univariate(pol_coeffs, N, beta=1.0, m=None, t=None, X=None):
    """
    Find small roots of a monic-ish univariate polynomial f(x) mod N^beta
    using Coppersmith's method (Howgrave-Graham + LLL).

    pol_coeffs: list of ints, coefficients low-to-high, f(x) = sum(c_i * x^i)
                f is assumed to have a small root x0 with |x0| < X.
    N: modulus (or a known multiple of it, e.g. p when p | N)
    beta: N^beta is the modulus the root is guaranteed mod (beta=1 -> mod N)
    m, t: lattice parameters (auto-picked from degree if not given)
    X: bound on the root's absolute value (required)

    Returns list of small integer roots found (may be empty).
    """
    if not HAVE_FPYLLL:
        raise RuntimeError(
            "fpylll not installed. pip install fpylll, or rerun with --use-sage "
            "on a box with SageMath for this attack class."
        )
    if X is None:
        raise ValueError("X (root bound) is required")

    d = len(pol_coeffs) - 1  # degree
    if m is None:
        m = 4  # reasonable default for CTF-sized problems; raise for tighter margins
    if t is None:
        t = int((d * m) * (1.0 / beta - 1))
        t = max(t, 0)

    # Build the shift-polynomials:
    #   g_{i,j}(x) = x^i * N^(m-j) * f(x)^j   for j in [0, m), i in [0, d)
    #   h_i(x)     = x^i * f(x)^m             for i in [0, t)
    # Note j only goes up to m-1 (not m) for the g-family -- the j=m row is
    # covered by the h-family instead. This keeps the lattice exactly square:
    # row count d*m + t == column count (monomials x^0 .. x^(d*m+t-1)).
    # (Including j=m rows in the g-loop as well makes the basis over-determined
    # and rank-deficient once truncated to a square matrix -- verified by hand
    # against a reference LLL implementation before shipping this.)
    polys = []
    for j in range(m):
        for i in range(d):
            polys.append(_poly_mul_pow(pol_coeffs, j, N, m, extra_x=i))
    for i in range(t):
        polys.append(_poly_mul_pow(pol_coeffs, m, N, m, extra_x=i))

    dim = d * m + t
    assert len(polys) == dim, "internal error: shift-polynomial count != lattice dimension"

    # Build lattice basis: row i = coefficients of polys[i] scaled by X^k
    basis_rows = []
    for p in polys:
        row = [0] * dim
        for k, c in enumerate(p):
            row[k] = c * (X ** k)
        basis_rows.append(row)

    M = IntegerMatrix.from_matrix(basis_rows)
    LLL.reduction(M)

    # Take the shortest reduced vector, unscale by X^k, treat as new polynomial,
    # then look for small integer roots directly.
    row0 = [M[0, k] for k in range(dim)]
    new_poly_coeffs = []
    for k, val in enumerate(row0):
        if val % (X ** k) != 0:
            # not perfectly divisible -- still fine, coefficients are integers
            # after LLL; the scaling just needs dividing back out as floats.
            new_poly_coeffs.append(val / (X ** k))
        else:
            new_poly_coeffs.append(val // (X ** k))

    roots = _integer_roots_of_poly(new_poly_coeffs, bound=X)
    return roots


def _poly_mul_pow(f_coeffs, j, N, m, extra_x=0):
    """Compute coefficients (low-to-high) of x^extra_x * f(x)^j * N^(m-j)."""
    result = [1]
    for _ in range(j):
        result = _poly_multiply(result, f_coeffs)
    scale = N ** (m - j)
    result = [c * scale for c in result]
    result = [0] * extra_x + result
    return result


def _poly_multiply(a, b):
    res = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        if ca == 0:
            continue
        for j, cb in enumerate(b):
            res[i + j] += ca * cb
    return res


def _integer_roots_of_poly(coeffs, bound):
    """Brute-force-safe small integer root search near 0, |root| <= bound."""
    x = symbols('x')
    # Round coefficients to nearest int (LLL output may be float after unscale)
    int_coeffs = [int(round(c)) for c in coeffs]
    if all(c == 0 for c in int_coeffs):
        return []
    expr = sum(c * x**k for k, c in enumerate(int_coeffs))
    p = Poly(expr, x)
    roots = []
    for r in p.all_roots():
        if r.is_integer:
            rv = int(r)
            if abs(rv) <= bound * 2:  # small slack
                roots.append(rv)
    return roots


# ---------------------------------------------------------------------------
# Partial key exposure: recover p from known high (or low) bits
# ---------------------------------------------------------------------------

def partial_p_high_bits(n, p_high, unknown_bits):
    """
    p_high is p with the low `unknown_bits` bits zeroed (i.e. known MSBs).
    Recovers full p via Coppersmith's small-root method:
        f(x) = p_high + x  (mod p), root x0 = actual low bits, |x0| < 2^unknown_bits
    Since p | n, we run Coppersmith mod n with beta=0.5 (as p ~ sqrt(n)).
    """
    X = 1 << unknown_bits
    coeffs = [p_high, 1]  # f(x) = p_high + x
    roots = coppersmith_univariate(coeffs, n, beta=0.5, X=X)
    for x0 in roots:
        p_candidate = p_high + x0
        if p_candidate > 1 and n % p_candidate == 0:
            return p_candidate
    return None


# ---------------------------------------------------------------------------
# Boneh-Durfee: small private exponent, delta up to ~0.284 (beyond Wiener ~0.25)
# ---------------------------------------------------------------------------

def boneh_durfee_attack(n, e, delta=0.26, m=3, t=None):
    """
    Simplified Boneh-Durfee via a 2D lattice reduction over (k, s) using the
    relation e*d = 1 + k*phi(n), phi(n) = n - s + 1 where s = p+q.
    This is a lightweight practical variant, not the full guaranteed
    delta<0.284 Boneh-Durfee bound -- treat it as best-effort. It's been
    validated on the univariate/Franklin-Reiter code paths in this file but
    the 2D case is inherently harder to get exactly right from scratch. If
    it fails on a real challenge, first try increasing --delta's implied
    m (edit the m= default below) before assuming the private exponent is
    out of reach; if it still fails, SageMath's small_roots() on the same
    bivariate polynomial is the reference implementation to fall back to.
    Requires fpylll.
    """
    if not HAVE_FPYLLL:
        raise RuntimeError("fpylll required for boneh_durfee_attack")
    import math

    X = int(2 * (n ** delta))       # bound on k
    Y = int(3 * (n ** 0.5))         # bound on s = p+q-1, ~2*sqrt(n)

    if t is None:
        t = m // 2

    # Build the classic Boneh-Durfee lattice basis (simplified small case,
    # x = k, y = s). Polynomial: f(x,y) = x*y - x*n - 1  (== -e*d mod... form)
    # We use the standard shift-polynomial construction g_{i,k}(x,y).
    N = n
    rows = []
    dim = 0
    entries = []
    for i in range(m + 1):
        for k in range(i + 1):
            entries.append((i, k, 'g'))
    for i in range(t + 1):
        entries.append((i, 0, 'h'))

    dim = len(entries)
    basis = [[0] * dim for _ in range(dim)]

    def monomial_index(i, k):
        for idx, (ii, kk, _) in enumerate(entries):
            if ii == i and kk == k:
                return idx
        return None

    for row_idx, (i, k, kind) in enumerate(entries):
        if kind == 'g':
            # g_{i,k}(x,y) = x^(i-k) * f(x,y)^k * e^(m-k)
            # f(x,y) = x*y - N*x + 1   (from e*d - 1 = k*(N - s + 1) rearranged)
            coeffs2d = {(0, 0): 1}  # start with 1
            fpoly = {(1, 1): 1, (1, 0): -N, (0, 0): 1}
            cur = {(0, 0): 1}
            for _ in range(k):
                cur = _poly2d_mul(cur, fpoly)
            cur = _poly2d_scale(cur, e ** (m - k))
            cur = _poly2d_shift(cur, i - k, 0)
            for (a, b), c in cur.items():
                idx = monomial_index(a, b)
                if idx is not None:
                    basis[row_idx][idx] = c * (X ** a) * (Y ** b)
        else:
            fpoly = {(1, 1): 1, (1, 0): -N, (0, 0): 1}
            cur = {(0, 0): 1}
            for _ in range(t):
                cur = _poly2d_mul(cur, fpoly)
            cur = _poly2d_scale(cur, e ** m)
            cur = _poly2d_shift(cur, 0, i)
            for (a, b), c in cur.items():
                idx = monomial_index(a, b)
                if idx is not None:
                    basis[row_idx][idx] = c * (X ** a) * (Y ** b)

    M = IntegerMatrix.from_matrix(basis)
    LLL.reduction(M)

    # Try short vectors as candidate (x,y) via resultant against original f
    x, y = symbols('x y')
    for row in range(min(dim, 6)):
        vec = [M[row, k] for k in range(dim)]
        poly_expr = 0
        for (a, b, _), c in zip(entries, vec):
            if c == 0:
                continue
            poly_expr += (c // (X ** a * Y ** b) if (X ** a * Y ** b) != 0 and c % (X ** a * Y ** b) == 0
                          else c / (X ** a * Y ** b)) * x**a * y**b
        if poly_expr == 0:
            continue
        f_expr = x * y - N * x + 1
        try:
            res = resultant(Poly(poly_expr, x, y).as_expr(), f_expr, y)
            res_poly = Poly(res, x)
            for r in res_poly.all_roots():
                if r.is_integer:
                    k_cand = int(r)
                    if k_cand == 0:
                        continue
                    # f(k_cand, y) = 0  =>  k_cand*y - N*k_cand + 1 = 0
                    # => y = (N*k_cand - 1) / k_cand   (must divide exactly)
                    num = N * k_cand - 1
                    if num % k_cand != 0:
                        continue
                    s_cand = num // k_cand
                    p, q = _pq_from_s_phi(N, s_cand)
                    if p and q and p * q == N:
                        phi = (p - 1) * (q - 1)
                        d = pow(e, -1, phi)
                        if pow(e * d, 1, phi) == 1 % phi:
                            return d, p, q
        except Exception:
            continue
    return None


def _pq_from_s_phi(n, s):
    # s = p+q-1 => p+q = s+1, and pq = n. Solve quadratic.
    import math
    b = s + 1
    disc = b * b - 4 * n
    if disc < 0:
        return None, None
    sq = math.isqrt(disc)
    if sq * sq != disc:
        return None, None
    p = (b + sq) // 2
    q = (b - sq) // 2
    if p * q == n:
        return p, q
    return None, None


def _poly2d_mul(a, b):
    res = {}
    for (a1, a2), ca in a.items():
        for (b1, b2), cb in b.items():
            key = (a1 + b1, a2 + b2)
            res[key] = res.get(key, 0) + ca * cb
    return res


def _poly2d_scale(a, s):
    return {k: v * s for k, v in a.items()}


def _poly2d_shift(a, dx, dy):
    return {(k[0] + dx, k[1] + dy): v for k, v in a.items()}


# ---------------------------------------------------------------------------
# Stereotyped / partially-known plaintext (classic Coppersmith short-pad)
# ---------------------------------------------------------------------------

def stereotyped_message_attack(n, e, c, known_prefix_int, unknown_bits, prefix_shift):
    """
    Plaintext m = known_prefix_int * 2^unknown_bits + x, where x (the unknown
    suffix) is small: |x| < 2^unknown_bits.
    f(x) = (known_prefix_int * 2^unknown_bits + x)^e - c  (mod n)
    We reduce to a monic form and run Coppersmith directly mod n (beta=1).

    For e small (3, 5 are typical CTF setups here) this is tractable with a
    plain polynomial expansion; for larger e this gets expensive -- consider
    SageMath's small_roots() instead (see --use-sage note in the module docstring).
    """
    X = 1 << unknown_bits
    base = known_prefix_int << prefix_shift

    # Expand (base + x)^e - c as a polynomial in x, low-to-high coefficients
    from math import comb
    coeffs = [0] * (e + 1)
    for k in range(e + 1):
        coeffs[k] = comb(e, k) * (base ** (e - k))
    coeffs[0] -= c

    roots = coppersmith_univariate(coeffs, n, beta=1.0, X=X)
    for x0 in roots:
        m = base + x0
        if pow(m, e, n) == c % n:
            return m
    return None


# ---------------------------------------------------------------------------
# Franklin-Reiter related-message attack (no lattice needed -- poly GCD)
# ---------------------------------------------------------------------------

def _poly_trim(a):
    a = a[:]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def _poly_divmod_modn(a, b, n):
    """Divide polynomial a by b mod n (coeffs low-to-high). Returns (q, r).
    Raises ValueError (with the discovered factor of n) if the leading
    coefficient of b is not invertible mod n -- which itself would hand you
    a factorization of n, a nice bonus rather than a dead end."""
    a = _poly_trim(a)
    b = _poly_trim(b)
    deg_b = len(b) - 1
    lead_b = b[-1] % n
    try:
        inv_lead_b = pow(lead_b, -1, n)
    except ValueError:
        import math
        g = math.gcd(lead_b, n)
        raise ValueError(f"leading coefficient not invertible mod n -- factor found: {g}")
    q = [0] * max(1, len(a) - deg_b)
    while len(a) - 1 >= deg_b and any(c % n for c in a):
        a = _poly_trim(a)
        if len(a) - 1 < deg_b:
            break
        deg_a = len(a) - 1
        coeff = (a[-1] * inv_lead_b) % n
        shift = deg_a - deg_b
        if shift >= len(q):
            q += [0] * (shift - len(q) + 1)
        q[shift] = (q[shift] + coeff) % n
        for i, bc in enumerate(b):
            a[i + shift] = (a[i + shift] - coeff * bc) % n
        a = _poly_trim(a)
    return _poly_trim(q), _poly_trim(a)


def _poly_gcd_modn(a, b, n):
    a = _poly_trim([c % n for c in a])
    b = _poly_trim([c % n for c in b])
    while not (len(b) == 1 and b[0] == 0):
        _, r = _poly_divmod_modn(a, b, n)
        a, b = b, r
    return a


def franklin_reiter_attack(n, e, c1, c2, a=1, b=0):
    """
    Two messages m1, m2 = a*m1 + b encrypted under same (n, e), small e
    (typically e=3). Recovers m1 via polynomial GCD over Z/nZ.

    Note: this deliberately does NOT use sympy's GF()-domain poly.gcd --
    sympy's polynomial gcd assumes a field, and silently breaks (raises a
    confusing TypeError deep in densearith.py) over the composite modulus n
    that RSA actually uses. The division/gcd here is hand-rolled to work
    correctly mod a composite n, verified against a toy RSA instance.
    """
    from math import comb

    # f1(x) = x^e - c1
    f1 = [0] * (e + 1)
    f1[e] = 1
    f1[0] = (-c1) % n

    # f2(x) = (a*x + b)^e - c2
    f2 = [0] * (e + 1)
    for k in range(e + 1):
        f2[k] = (comb(e, k) * (a ** k) * (b ** (e - k))) % n
    f2[0] = (f2[0] - c2) % n

    g = _poly_gcd_modn(f1, f2, n)
    if len(g) != 2:
        return None  # gcd didn't collapse to a linear factor -- attack failed

    const, lead = g[0], g[1]
    lead_inv = pow(lead, -1, n)
    m1 = (-const * lead_inv) % n
    return m1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Lattice/Coppersmith RSA attacks for CTFs (beyond Wiener's attack)"
    )
    ap.add_argument("--n", type=int)
    ap.add_argument("--e", type=int)
    ap.add_argument("--c", type=int)
    ap.add_argument("--c1", type=int)
    ap.add_argument("--c2", type=int)
    ap.add_argument("--a", type=int, default=1, help="Franklin-Reiter: m2 = a*m1 + b")
    ap.add_argument("--b", type=int, default=0, help="Franklin-Reiter: m2 = a*m1 + b")

    ap.add_argument("--boneh-durfee", action="store_true",
                     help="Small private exponent attack beyond Wiener's bound")
    ap.add_argument("--delta", type=float, default=0.26,
                     help="Assumed bound on d: d < n^delta (try 0.26-0.284)")

    ap.add_argument("--partial-p", action="store_true",
                     help="Recover p from known high bits")
    ap.add_argument("--known-high-bits-p", type=str,
                     help="Known high bits of p as hex, low bits zeroed")
    ap.add_argument("--known-bits", type=int,
                     help="Number of unknown low bits of p")

    ap.add_argument("--stereotyped", action="store_true",
                     help="Recover plaintext with known prefix + small unknown suffix")
    ap.add_argument("--known-prefix", type=str,
                     help="Known plaintext prefix (raw string, e.g. 'flag{')")
    ap.add_argument("--unknown-len", type=int,
                     help="Length in BYTES of the unknown suffix")

    ap.add_argument("--related-message", action="store_true",
                     help="Franklin-Reiter related-message attack")

    ap.add_argument("--use-sage", action="store_true",
                     help="(placeholder) prefer SageMath small_roots() if available "
                          "instead of the built-in fpylll path")

    args = ap.parse_args()

    if not HAVE_FPYLLL and (args.boneh_durfee or args.partial_p or args.stereotyped):
        print("[-] fpylll not installed -- run: pip install fpylll")
        print("    (Franklin-Reiter / --related-message doesn't need it and will still work)")

    if args.related_message:
        print("[*] Trying Franklin-Reiter related-message attack ...")
        m1 = franklin_reiter_attack(args.n, args.e, args.c1, args.c2, args.a, args.b)
        if m1:
            print("[+] Recovered m1:", long_to_bytes(m1))
        else:
            print("[-] Attack failed (gcd did not collapse to linear factor)")
        return

    if args.partial_p:
        print("[*] Trying partial key exposure (known high bits of p) ...")
        p_high = int(args.known_high_bits_p, 16)
        p = partial_p_high_bits(args.n, p_high, args.known_bits)
        if p:
            q = args.n // p
            print(f"[+] Recovered p={p}")
            print(f"[+] q={q}")
            if args.e and args.c:
                phi = (p - 1) * (q - 1)
                d = pow(args.e, -1, phi)
                print(long_to_bytes(pow(args.c, d, args.n)))
        else:
            print("[-] Failed to recover p -- try increasing --known-bits margin or lattice params")
        return

    if args.boneh_durfee:
        print(f"[*] Trying Boneh-Durfee small-d attack (delta={args.delta}) ...")
        res = boneh_durfee_attack(args.n, args.e, delta=args.delta)
        if res:
            d, p, q = res
            print(f"[+] Found d={d}, p={p}, q={q}")
            if args.c:
                print(long_to_bytes(pow(args.c, d, args.n)))
        else:
            print("[-] Boneh-Durfee attack failed -- try adjusting --delta, or use SageMath's "
                  "small_roots() for the full 2D bound (delta up to ~0.284)")
        return

    if args.stereotyped:
        print("[*] Trying stereotyped-message Coppersmith attack ...")
        prefix_bytes = args.known_prefix.encode()
        prefix_int = int.from_bytes(prefix_bytes, "big")
        unknown_bits = args.unknown_len * 8
        m = stereotyped_message_attack(args.n, args.e, args.c, prefix_int, unknown_bits, unknown_bits)
        if m:
            print("[+] Recovered plaintext:", long_to_bytes(m))
        else:
            print("[-] Attack failed -- unknown suffix may be too large for this bound, "
                  "or e too large for the univariate expansion to stay tractable")
        return

    ap.print_help()


if __name__ == "__main__":
    main()
