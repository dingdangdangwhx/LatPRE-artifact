"""C-PMF-assisted unconditional PRE correctness certificate.

The shared-secret MGF/CDF proof is inherited verbatim from the sphere branch.
Only its terminal-u rounding multiplier changes: C performs actual 512-bit
fixed-point CBD PMF convolution, bounds the convex stop-loss moment including
all missing mass, and certifies a two-sided, d-coefficient union probability.
This is not a full PRE joint-noise PMF. No sampled outer profile is used.
"""
import hashlib
import json
import math
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
from noise_bounds import budgets, rounding_bound, source_quantile, re_quantile

ROUNDING_DIRECTORY=HERE.parent/'evidence'/'rounding'
_CACHE={}


def set_rounding_directory(directory):
    """Select current mathematical rounding certificates, clearing the cache."""
    global ROUNDING_DIRECTORY
    ROUNDING_DIRECTORY=Path(directory).resolve()
    _CACHE.clear()


def get_rounding_certificate(model, round_bits):
    terminal=model.get('terminal_dist')
    if not terminal or terminal['kind']!='cbd':
        raise ValueError('C rounding backend requires actual CBD terminal secrets')
    if int(round_bits)!=round_bits:
        raise ValueError('C PMF cache uses integer failure budgets')
    eta=int(terminal['parameter']);k=int(model['k']);d=int(model['d']);rb=int(round_bits)
    key=(eta,k,d,rb)
    if key not in _CACHE:
        path=ROUNDING_DIRECTORY/f'eta{eta}_k{k}_d{d}_rb{rb}.json'
        raw=path.read_bytes();c=json.loads(raw)
        assert c['certified'] and not c['full_PRE_PMF'] and not c['normal_approximation']
        assert (c['eta'],c['k'],c['degree'],c['round_bits'])==key
        assert c['N']==eta*k*d and c['precision_bits']>=256
        assert c['probability_bound']==f'2^-{rb}'
        # Validate the mathematical certificate, not a historical executable:
        # binaries legitimately differ across compilers and platforms.
        assert c['stoploss_power'] in (1,2,3) and 0<=c['stoploss_shift']<=c['N']
        assert math.isfinite(float(c['multiplier_upper'])) and float(c['multiplier_upper'])>0
        c=dict(c,certificate_file=path.name,
               certificate_sha256=hashlib.sha256(raw).hexdigest())
        _CACHE[key]=c
    return _CACHE[key]


def rounding_multiplier(model,round_bits=130):
    # Upward screening cushion; certify uses the original outward decimal.
    return math.nextafter(float(get_rounding_certificate(model,round_bits)['multiplier_upper']),math.inf)*(1+1e-14)


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
    rounding_certificate = get_rounding_certificate(model, round_bits)
    multiplier = I(rounding_certificate["multiplier_upper"])
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
                c_rounding_certificate=rounding_certificate,
                method="C CBD PMF convex-order rounding + shared-secret spectral MGF/CDF",
                scope="fixed pair; one honest Enc and RE; ideal sampling; source u exact")
