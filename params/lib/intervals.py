"""Directed Decimal interval arithmetic used by the spectral certificate."""
from decimal import Decimal as D, localcontext, ROUND_FLOOR, ROUND_CEILING
PRECISION=80

def ln_interval(x: D) -> tuple[D, D]:
    """Enclose ln(x) using Decimal's correctly rounded logarithm."""
    value = x.ln()
    return value.next_minus(), value.next_plus()

def iadd(a, b):
    with localcontext() as ctx:
        ctx.prec, ctx.rounding = PRECISION, ROUND_FLOOR
        low = a[0] + b[0]
        ctx.rounding = ROUND_CEILING
        high = a[1] + b[1]
    return low, high

def isub(a, b):
    return iadd(a, (-b[1], -b[0]))

def imul(a, b):
    assert a[0] >= 0 and b[0] >= 0
    with localcontext() as ctx:
        ctx.prec, ctx.rounding = PRECISION, ROUND_FLOOR
        low = a[0] * b[0]
        ctx.rounding = ROUND_CEILING
        high = a[1] * b[1]
    return low, high

def idiv(a, b):
    assert a[0] >= 0 and b[0] > 0
    with localcontext() as ctx:
        ctx.prec, ctx.rounding = PRECISION, ROUND_FLOOR
        low = a[0] / b[1]
        ctx.rounding = ROUND_CEILING
        high = a[1] / b[0]
    return low, high

def point(x):
    return D(x), D(x)
