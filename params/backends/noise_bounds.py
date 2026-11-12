"""Shared-secret-safe PRE correctness envelopes for the new sphere search.

Gaussian standard deviations below mean width / sqrt(2*pi). For an explicit
bounded terminal law, terminal_std reports sqrt(variance), and its exact MGF
proxy is used without Gaussian replacement. The broad search uses floats
only to choose tilts and compression candidates.  certify()
re-evaluates a fixed positive tilt with 512-bit directed interval arithmetic.
This is an unconditional MGF/CDF upper bound, NOT a full-noise PMF convolution.
Source u is exact.  The scope is one fixed pair and one honest source/RE.
"""
import math


def distribution(kind, parameter):
    parameter = int(parameter)
    if parameter < 1:
        raise ValueError("Positive distribution parameter required")
    kind = kind.lower()
    if kind in ("uniform", "u"):
        kind = "uniform"
        den = 2 * parameter + 1
        weights = [(a, 1, den) for a in range(-parameter, parameter + 1)]
        variance = parameter * (parameter + 1) / 3
    elif kind in ("cbd", "binomial"):
        kind = "cbd"
        den = 4 ** parameter
        weights = [(a, math.comb(2 * parameter, parameter + a), den)
                   for a in range(-parameter, parameter + 1)]
        variance = parameter / 2
    else:
        raise ValueError("Supported distributions: uniform and cbd")
    return dict(kind=kind, parameter=parameter, bound=parameter,
                variance=variance, pmf=weights)


def noise_model(k, ell, d, base, gadget_length, source_std, terminal_std,
                pad_std, source_dist, internal_dist, terminal_dist=None):
    k, ell, d, base, gadget_length = map(int, (k, ell, d, base, gadget_length))
    if min(k, ell, gadget_length) < 1 or d < 2 or d & (d - 1):
        raise ValueError("Positive dimensions and power-of-two even degree required")
    if base < 3 or base % 2 != 1:
        raise ValueError("This search uses exact balanced odd-base gadgets")
    if terminal_dist is not None:
        if terminal_dist['kind'] not in ('uniform','cbd'):
            raise ValueError('Terminal law must be Gaussian or centered uniform/CBD')
        terminal_std=math.sqrt(terminal_dist['variance'])
    if min(source_std, terminal_std, pad_std) <= 0:
        raise ValueError("Positive Gaussian widths required")
    for dist in (source_dist, internal_dist):
        if dist["kind"] not in ("uniform", "cbd"):
            raise ValueError("Centered uniform/CBD coins required")
    digit_bound = (base - 1) // 2
    w = k * gadget_length
    # One-unit upward cushion makes float ceiling unambiguous.  Final
    # certification also verifies this integer against an interval sine.
    trig_cap = math.ceil(1 / math.sin(math.pi / (2 * d)) ** 2) + 1
    cap = 1 + w * digit_bound ** 2 * trig_cap
    d2 = 1 + w * d * digit_bound ** 2
    mass = (d // 2) * (d2 - 1)
    full, remainder = divmod(mass, cap - 1)
    count_rest = d // 2 - full - int(remainder != 0)
    if count_rest < 0:
        raise ArithmeticError("Invalid spectral trace budget")
    spectrum = [(full, cap), (int(remainder != 0), 1 + remainder),
                (count_rest, 1)]
    squares = {}
    for a, num, den in source_dist["pmf"]:
        squares[a * a] = squares.get(a * a, 0.0) + num / den
    return dict(k=k, ell=ell, d=d, p=k+ell, base=base,
                gadget_length=gadget_length, gadget_columns=w,
                digit_bound=digit_bound, D2=d2, Op2=cap,
                trig_cap=trig_cap, spectrum=spectrum,
                source_std=float(source_std), terminal_std=float(terminal_std),
                pad_std=float(pad_std), vs=float(source_std)**2,
                vt=(float(terminal_dist['variance']) if terminal_dist is not None
                    else float(terminal_std)**2), vp=float(pad_std)**2,
                vi=float(internal_dist["variance"]), source_dist=source_dist,
                internal_dist=internal_dist, terminal_dist=terminal_dist,
                square_pmf=sorted(squares.items()),
                _source_cache={}, _re_cache={})


def budgets(round_bits=130, failure_bits=128, source_bits=256):
    # Reserve a finite, explicit allowance for pad discretization; certify
    # checks that the actual theta allowance is below this reservation.
    theta_bits = max(250, failure_bits + 100)
    fraction = (2.0**(failure_bits-round_bits)
                + 2.0**(failure_bits-source_bits)
                + 2.0**(failure_bits-theta_bits))
    if not 0 < fraction < 1:
        raise ValueError("Failure budget is exhausted")
    # Upward slack covers the floating log; exact final union is certified.
    main_bits = failure_bits - math.log1p(-fraction)/math.log(2) + 1e-10
    return dict(round_bits=round_bits, failure_bits=failure_bits,
                source_bits=source_bits, theta_bits=theta_bits,
                main_bits=main_bits)


def rounding_bound(q, bits):
    q, bits = int(q), int(bits)
    if bits < 1:
        raise ValueError("At least one retained bit required")
    return 0 if bits >= q.bit_length() else (q + 2**bits) // 2**(bits+1)


def rounding_multiplier(model, round_bits=130):
    return math.sqrt(2 * model["vt"] * model["k"] * model["d"]
                     * (math.log(2 * model["d"]) + round_bits * math.log(2)))


def _source_log_derivative(model, t):
    z = model["vs"] * t*t / 2
    pairs = model["square_pmf"]
    high = pairs[-1][0] * z
    values = [(a2, weight * math.exp(a2*z-high)) for a2, weight in pairs]
    total = math.fsum(v for _, v in values)
    mean_square = math.fsum(a2*v for a2, v in values) / total
    # logsumexp is stable even for a broad support.
    log_average = high + math.log(total)
    count = model["p"] * model["d"]
    return count*log_average, count*model["vs"]*t*mean_square


def _rest_log_derivative(model, t):
    val, derivative = _source_log_derivative(model, t)
    linear = model["vi"] * model["D2"]
    val += linear*t*t/2
    derivative += linear*t
    h = model["vt"] * model["vi"]
    for count, lam in model["spectrum"]:
        if not count:
            continue
        z = h * lam * t*t
        if z >= 1:
            return math.inf, math.inf
        val -= model["p"] * count * math.log1p(-z)
        derivative += 2*model["p"]*count*h*lam*t/(1-z)
    return val, derivative


def _quantile(model, bits, reenc):
    cache = model["_re_cache" if reenc else "_source_cache"]
    key = float(bits)
    if key in cache:
        return cache[key]
    logmass = math.log(2 * model["d"]) + bits * math.log(2)
    if reenc:
        variance = (model["vs"]*model["source_dist"]["variance"]
                    *model["p"]*model["d"] + model["vi"]*model["D2"]
                    + model["vt"]*model["vi"]*model["p"]*model["d"]*model["D2"]
                    + model["vp"])
        pole = 1/math.sqrt(model["vt"]*model["vi"]*model["Op2"])
        upper = pole*(1-1e-12)
        fn = _rest_log_derivative
    else:
        variance = (model["vs"]*model["source_dist"]["variance"]
                    *model["p"]*model["d"])
        upper = math.inf
        fn = _source_log_derivative

    def objective_derivative(t):
        val, derivative = fn(model, t)
        if reenc:
            a = t*model["pad_std"]
            val += a*a/2 - math.log(a*math.sqrt(2*math.pi))
            derivative += model["vp"]*t - 1/t
        return t*derivative - val - logmass, val

    hi = min(math.sqrt(2*logmass/variance), upper)
    while objective_derivative(hi)[0] < 0:
        nxt = min(2*hi, upper)
        if nxt == hi:
            raise ArithmeticError("Unable to bracket a valid tilt below MGF pole")
        hi = nxt
    lo = 0.0
    for _ in range(58):
        mid = (lo+hi)/2
        if objective_derivative(mid)[0] < 0:
            lo = mid
        else:
            hi = mid
    tilt = (lo+hi)/2
    _, val = objective_derivative(tilt)
    quantile = (val+logmass)/tilt + model["source_dist"]["bound"] + int(reenc)
    # Screening cushion.  Final selected tuples are independently certified.
    quantile = quantile*(1+2e-10)+1e-8
    result = dict(quantile=quantile, tilt=tilt, bits=float(bits),
                  method="paired spectral MGF + Gaussian CDF" if reenc
                  else "finite source PMF square average")
    cache[key] = result
    return result


def source_quantile(model, bits=256, details=False):
    result = _quantile(model, bits, False)
    return result if details else result["quantile"]


def re_quantile(model, main_bits, details=False):
    result = _quantile(model, main_bits, True)
    return result if details else result["quantile"]


def certify(model, q, source_v_bits, re_u_bits, re_v_bits, round_bits=130,
            failure_bits=128, source_bits=256):
    from sage.all import RealIntervalField
    I = RealIntervalField(512)
    log2 = I(2).log()
    bd = budgets(round_bits, failure_bits, source_bits)
    n = model["d"]
    if int(q) != q or q < 3 or int(q) % 2 != 1:
        raise ValueError("Odd integer modulus required")
    base, length = model["base"], model["gadget_length"]
    if not base**(length-1) < q <= base**length:
        raise ValueError("Gadget length does not match the selected modulus")
    if not model["trig_cap"] >= (1/(I.pi()/(2*n)).sin()**2).upper():
        raise ArithmeticError("Fourier cap was rounded down")
    vs, vt, vp = [I(str(model[name]))**2 for name in
                  ("source_std", "terminal_std", "pad_std")]
    terminal = model.get('terminal_dist')
    if terminal is not None:
        z=int(terminal['parameter'])
        vt=I(z*(z+1))/3 if terminal['kind']=='uniform' else I(z)/2
    dist = model["internal_dist"]
    param = int(dist["parameter"])
    vi = I(param*(param+1))/3 if dist["kind"] == "uniform" else I(param)/2

    def source_mgf(t):
        avg = I(0)
        for a, num, den in model["source_dist"]["pmf"]:
            avg += I(num)/den * (vs*(a*a)*t*t/2).exp()
        return model["p"]*n*avg.log()

    def rest_mgf(t):
        val = source_mgf(t) + vi*model["D2"]*t*t/2
        for count, lam in model["spectrum"]:
            if count:
                pole = 1-vt*vi*t*t*lam
                if pole.lower() <= 0:
                    raise ArithmeticError("Certification reached an MGF pole")
                val -= model["p"]*count*pole.log()
        return val

    rs = rounding_bound(q, source_v_bits)
    ru = rounding_bound(q, re_u_bits)
    rv = rounding_bound(q, re_v_bits)
    multiplier = (2*vt*model["k"]*n*(I(2*n).log()+round_bits*log2)).sqrt()
    radius = I(int(q)-1)/4
    beta = model["source_dist"]["bound"]
    ts = radius-beta-rs
    tr = radius-beta-rs-rv-ru*multiplier
    if ts.lower() <= 0 or tr.lower() <= 1:
        return dict(passed=False, reason="nonpositive decoding threshold")
    st = I(str(source_quantile(model, source_bits, details=True)["tilt"]))
    rt = I(str(re_quantile(model, bd["main_bits"], details=True)["tilt"]))
    if st.lower() <= 0 or rt.lower() <= 0:
        raise ArithmeticError("Nonpositive tilt")
    source_log = (I(2*n).log()+source_mgf(st)-st*ts)/log2
    # Analytic normal-CDF exponential majorant, valid for every positive tilt.
    re_log = (I(2*n).log()+rest_mgf(rt)+vp*rt*rt/2
              -(rt*(2*I.pi()*vp).sqrt()).log()-rt*(tr-1))/log2
    # eps_theta <= 4 exp(-pi sigma_pad²); union over 2*n signed events.
    theta_log = (I(8*n).log()-2*I.pi()**2*vp)/log2
    if theta_log.upper() > -bd["theta_bits"]:
        raise ArithmeticError("Pad too narrow for reserved theta budget")
    total = I(2)**source_log + I(2)**re_log + I(2)**theta_log
    if ru:
        total += I(2)**(-round_bits)
    joint = total.log()/log2

    def up(x):
        # Decimal string is for report; passed is evaluated on the interval.
        return str(x.upper())

    return dict(passed=bool(joint.upper() <= -failure_bits),
                source_log2_upper=up(source_log), reenc_log2_upper=up(re_log),
                round_log2_upper=-round_bits if ru else None,
                theta_log2_upper=up(theta_log), joint_log2_upper=up(joint),
                source_threshold_lower=str(ts.lower()),
                reenc_threshold_lower=str(tr.lower()),
                source_tilt=str(st), reenc_tilt=str(rt), budgets=bd,
                rounding=dict(source_v=rs, re_u=ru, re_v=rv,
                              terminal_multiplier_upper=up(multiplier)),
                precision=512, exact_pmf=False,
                scope="fixed pair; one honest Enc and RE; ideal sampling; source u exact")
