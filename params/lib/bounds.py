"""Verify frozen spectral witnesses and Gaussian-reduction inequalities."""
import math
from fractions import Fraction
from decimal import Decimal as D, localcontext, ROUND_FLOOR, ROUND_CEILING
from intervals import PRECISION, ln_interval, iadd, isub, imul, idiv, point
PI=(D("3.1415926535897932384626433832795028841971693993751058209749445923078164"), D("3.1415926535897932384626433832795028841971693993751058209749445923078165"))

def verify_gaussian_and_sphere(row, runtime):
    """Check a rational witness and the current theorem's SUM condition."""
    original = row['correctness_certificate']['bank']['original_bank']
    Q, p, B = original['Q'], original['p'], original['B']
    assert (Q, p, original['d'], original['tau2']) == (row['Q'], row['k'] + row['ell'], 256, '1/2')
    assert B == row['B_original'] and row['B_QM'] == row['M'] * B
    with localcontext() as ctx:
        ctx.prec = PRECISION
        r = D(original['tilt_numerator']) / D(original['tilt_denominator'])
        t = r * B / D(128)
        assert Fraction(r) == Fraction(original['tilt_numerator'], original['tilt_denominator'])
        assert Fraction(t) == Fraction(original['tilt_numerator'] * B, original['tilt_denominator'] * 128)
        assert 0 < r < 1
        lt, lo = ln_interval(t), ln_interval(1-r)
        lf = ln_interval(D(math.factorial(p-1)))
        terms = []
        with localcontext() as upper:
            upper.rounding = ROUND_CEILING
            for j in range(p-1):
                terms.append(D(j)*lt[1]-ln_interval(D(math.factorial(j)))[0])
            log_remainder = ln_interval(D(p-1))[1] + max(terms) - t
        with localcontext() as lower:
            lower.rounding = ROUND_FLOOR
            remainder_limit = -D(101)*ln_interval(D(10))[1]
        assert log_remainder < remainder_limit
        with localcontext() as upper:
            upper.rounding = ROUND_CEILING
            log_tail = ln_interval(D(128))[1] + D(Q)*(-lo[0]) - t - lf[0] + D(p-1)*lt[1] + D('1e-100')
            log2_tail = log_tail / ln_interval(D(2))[1]
        with localcontext() as lower:
            lower.rounding = ROUND_FLOOR
            tail_limit = -D(160)*ln_interval(D(2))[1]
        assert log_tail < tail_limit
        dim = 256*p
        eta2 = idiv(iadd(ln_interval(D(2*dim)), ln_interval(D(1 + 2**150))), PI)
        delta0 = idiv(ln_interval(D(2*dim+4)), PI)
        h2 = imul(point(row['sigma_H']), point(row['sigma_H']))
        source2 = imul(point(runtime['sigma_source']), point(runtime['sigma_source']))
        pad2 = imul(point(runtime['sigma_pad']), point(runtime['sigma_pad']))
        posterior = idiv(point(1), iadd(idiv(point(1), source2), idiv(point(row['B_QM']), pad2)))
        required = iadd(imul(point('1.9'), h2), delta0)
        sampling_margin = isub(posterior, required)
        convolution_lhs = imul(idiv(point('0.9'), point('1.9')), h2)
        convolution_margin = isub(convolution_lhs, eta2)
        assert sampling_margin[0] > 0, (row['profile'], 'current theorem sampling condition')
        assert convolution_margin[0] > 0, (row['profile'], 'current theorem convolution condition')
        # Runtime widths must represent the EXACT archived decimal SDs times sqrt(2pi).
        for name in ['source', 'pad']:
            proxy = point(runtime[name+'_std'])
            target2 = imul(imul(point(2), PI), imul(proxy, proxy))
            actual2 = imul(point(runtime['sigma_'+name]), point(runtime['sigma_'+name]))
            relative = idiv(actual2, target2)
            assert relative[0] <= 1 <= relative[1], (name, 'runtime width conversion')
        return {
            'profile': row['profile'], 'Q': Q, 'M': row['M'], 'p': p,
            'B_single': B, 'B_QM': row['B_QM'],
            'tilt_numerator': original['tilt_numerator'], 'tilt_denominator': original['tilt_denominator'],
            'log2_spectral_failure_upper': str(log2_tail), 'delta_spec': '2^-160',
            'epsilon_g': '2^-150', 'delta': '0.9', 'sigma_H': row['sigma_H'],
            'sigma_source_exact_runtime': runtime['sigma_source'], 'sigma_pad_exact_runtime': runtime['sigma_pad'],
            'posterior_parameter_interval': list(map(str, posterior)),
            'current_theorem_required_parameter_interval': list(map(str, required)),
            'current_theorem_sampling_margin_lower': str(sampling_margin[0]),
            'current_theorem_convolution_margin_lower': str(convolution_margin[0]),
            'arithmetic': '80-digit directed Decimal, exact rational Chernoff witness, enclosed pi/logarithms',
            'verified': True,
        }
