"""Cached spherical-average bounds for honestly generated hint banks.

No production/frozen parameters are changed.  ``bank_bound`` proposes a squared
operator-norm cap, or independently certifies it using Sage's 256-bit MPFI
intervals.  CPython without Sage can run the fast search; certification requires
Sage.  Returned certificates concern ONE bank and no other PRE security loss.

Let L be Q by p over Z[X]/(X^d+1), d dyadic >=2. All coefficient variables must
be independent, centered, with E exp(t X) <= exp(tau2*t*t/2). Set
  n=max(Q,p), m=min(Q,p), c=d*tau2, f=d/2.
The proof gives, for 0<u<1,
  Pr(||Gamma(L)||^2 >= B) <= f*(1-u)^(-n)/H_m(u B/c),
where H_m(t)=E exp(t W), W~Beta(1,m-1); H_1(t)=exp(t).
The m-dimensional sphere is auxiliary to the proof, not protocol randomness.
No independence between Fourier frequencies is asserted or needed.

This module caches the dimension-dependent b=B/c and tilt by (Q,p,d,bits).
The float optimization works with excess b-n and uses a cancellation-free
series for -log(1-u)-u, essential for Q up to 2^40. Selected B and the rational
tilt are subsequently checked from the original bound with outward intervals.
"""

from fractions import Fraction
from functools import lru_cache
import math


def _fraction(value):
    if isinstance(value, Fraction):
        return value
    if isinstance(value, float):
        # Most callers use beta*(beta+1)/3 or eta/2 in machine arithmetic.
        # Recover those small exact rationals without enormous float denominators.
        return Fraction(value).limit_denominator(10**9)
    return Fraction(value)


def uniform(beta):
    """Exact descriptor of integer uniform [-beta,beta], beta >=1."""
    beta = int(beta)
    if beta < 1:
        raise ValueError("beta must be >=1")
    pmf = {x: Fraction(1, 2*beta+1) for x in range(-beta,beta+1)}
    return {"kind": "uniform", "parameter": beta, "support_radius": beta,
            "tau2": Fraction(beta*(beta+1),3),
            "variance": Fraction(beta*(beta+1),3), "pmf": pmf,
            "fourth_moment": sum(prob*x**4 for x,prob in pmf.items())}


def cbd(eta):
    """Exact descriptor of sum of eta independent Ber(1/2)-Ber(1/2)."""
    eta = int(eta)
    if eta < 1:
        raise ValueError("eta must be >=1")
    pmf = {x: Fraction(math.comb(2*eta, eta+x),4**eta)
           for x in range(-eta,eta+1)}
    return {"kind": "cbd", "parameter": eta, "support_radius": eta,
            "tau2": Fraction(eta,2), "variance": Fraction(eta,2), "pmf": pmf,
            "fourth_moment": Fraction(3*eta*eta-eta,4)}


def _golden(f, lo, hi, iterations=90):
    ratio = (math.sqrt(5)-1)/2
    x, y = hi-ratio*(hi-lo), lo+ratio*(hi-lo)
    fx, fy = f(x), f(y)
    for _ in range(iterations):
        if fx < fy:
            hi, y, fy = y, x, fx
            x = hi-ratio*(hi-lo)
            fx = f(x)
        else:
            lo, x, fx = x, y, fy
            y = lo+ratio*(hi-lo)
            fy = f(y)
    return (lo+hi)/2


def _minus_log1p_minus(u):
    """-log(1-u)-u with no small-u subtraction."""
    if u > 0.05:
        return -math.log1p(-u)-u
    term = u*u/2
    total = term
    for k in range(3,100):
        term *= u*(k-1)/k
        total += term
        if term < total*1e-17:
            break
    return total


def _log_h(m,x):
    if m == 1:
        return x
    if x < 40:
        term = total = 1.0
        for j in range(10000):
            term *= x/(m+j)
            total += term
            if term < total*1e-16:
                break
        return math.log(total)
    term = total = 1.0
    for j in range(1,m-1):
        term *= x/j
        total += term
    log_tail = math.log(total)-x
    log_rem = math.log1p(-math.exp(log_tail)) if log_tail > -745 else 0.0
    return x+math.lgamma(m)-(m-1)*math.log(x)+log_rem


def _log_probability_without_frequency(n,m,excess,u):
    """Stable equivalent of -n*log(1-u)-log H_m(u*(n+excess))."""
    x = u*(n+excess)
    if m == 1:
        return n*_minus_log1p_minus(u)-u*excess
    if x < 40:
        return -n*math.log1p(-u)-_log_h(m,x)
    term = total = 1.0
    for j in range(1,m-1):
        term *= x/j
        total += term
    log_tail = math.log(total)-x
    log_rem = math.log1p(-math.exp(log_tail)) if log_tail > -745 else 0.0
    return (n*_minus_log1p_minus(u)-u*excess-math.lgamma(m)
            +(m-1)*math.log(x)-log_rem)


@lru_cache(maxsize=4096)
def sphere_shape(Q,p,d=256,bits=160):
    """Float proposal only; dimension-dependent normalized B and tilt.

    A public fixed small slack in the excess prevents roundoff/flat-minimum
    noise from systematically producing caps just below the requested level.
    This slack is NOT a substitute for a final interval certificate.
    """
    Q,p,d,bits = int(Q),int(p),int(d),int(bits)
    if min(Q,p,bits) < 1 or d < 2 or d & (d-1):
        raise ValueError("Q,p,bits positive; d a power of two >=2")
    n,m = max(Q,p), min(Q,p)
    target = -math.log(d//2)-bits*math.log(2)

    def optimize(excess):
        fn = lambda u: _log_probability_without_frequency(n,m,excess,u)
        u = _golden(fn,1e-24,1-1e-10)
        return fn(u),u

    lo = 0.0
    hi = 100*math.sqrt(n)+2000+10*m
    while optimize(hi)[0] > target:
        hi *= 2
    for _ in range(60):
        mid = (lo+hi)/2
        if optimize(mid)[0] <= target:
            hi = mid
        else:
            lo = mid
    # Roughly 1e-8 * (b-n), not 1e-8*b: negligible even for Q=2^40.
    excess = hi*(1+1e-8)+1e-6
    _,u = optimize(excess)
    denominator = 2**64
    numerator = max(1,min(denominator-1,round(u*denominator)))
    return {"shape_factor": n+excess, "shape_excess": excess,
            "n": n, "m": m, "tilt_numerator": numerator,
            "tilt_denominator": denominator}


def _interval_certificate(Q,p,d,tau2,bits,B,tilt_num,tilt_den,precision=256):
    try:
        from sage.all import RealIntervalField
    except ImportError as exc:
        raise RuntimeError("certify=True requires Sage Python (256-bit MPFI)") from exc
    RI = RealIntervalField(precision)
    n,m = max(Q,p), min(Q,p)
    c = RI(d*tau2.numerator)/tau2.denominator
    u = RI(tilt_num)/tilt_den
    x = u*B/c
    if m == 1:
        log_h = x
    else:
        term = total = RI(1)
        for j in range(1,m-1):
            term *= x/j
            total += term
        rem = 1-(-x).exp()*total
        if rem.lower() <= 0:
            return {"passed": False, "reason": "spherical remainder not positive"}
        log_h = x+RI(math.factorial(m-1)).log()-(m-1)*x.log()+rem.log()
    log2_prob = (RI(d//2).log()-n*(1-u).log()-log_h)/RI(2).log()
    return {"passed": bool(log2_prob.upper() <= -bits),
            "log2_bad_probability_upper": str(log2_prob.upper()),
            "arithmetic": f"{precision}-bit outward MPFI intervals",
            "scope": "one honest iid coefficient bank"}


def bank_bound(Q,p,d,tau2,bits=160,certify=False):
    """Return squared norm cap B; certify=True validates original tail formula.

    tau2 may be Fraction, rational text, integer, or a float representing a
    small rational.  Use exact Fraction for a genuinely nonstandard tau2.
    Every returned dict is fresh; the underlying dimension search is cached.
    """
    Q,p,d,bits = int(Q),int(p),int(d),int(bits)
    tau2 = _fraction(tau2)
    if tau2 <= 0:
        raise ValueError("positive subgaussian variance proxy required")
    shape = sphere_shape(Q,p,d,bits)
    c = d*tau2
    # Fraction.from_float preserves the chosen proposal exactly; avoids a
    # second floating multiply before ceiling at Q=2^40.
    raw = c*Fraction.from_float(shape["shape_factor"])
    B = (raw.numerator+raw.denominator-1)//raw.denominator
    cert = {"passed": False, "reason": "float search proposal; not yet certified"}
    if certify:
        for _ in range(100):
            cert = _interval_certificate(Q,p,d,tau2,bits,B,
                                        shape["tilt_numerator"],
                                        shape["tilt_denominator"])
            if cert["passed"]:
                break
            B += max(1,math.ceil(float(c)*shape["shape_excess"]*1e-9))
        else:
            raise ArithmeticError(f"No certified cap near shape proposal: {cert}")
    return {"method": "spherical_average", "Q": Q, "p": p, "d": d,
            "tau2": str(tau2), "bank_bad_event_bits": bits, "B": int(B),
            "norm": math.sqrt(B), **shape, "certificate": cert}
