#!/usr/bin/env python3
"""Optional full MATZOV/GSA attack-cost recomputation for frozen profiles.

Run with SageMath: sage -python security.py --profile L --role terminal.
This may take substantial time. No preliminary screen is reported as a pass.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
ESTIMATOR = HERE / "vendor" / "lattice-estimator"
COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
ATTACKS = {"arora-gb", "bkw", "usvp", "bdd", "bdd_hybrid",
           "bdd_mitm_hybrid", "dual", "dual_hybrid"}
ROLES = ("hint", "terminal", "source", "internal")


def load_estimator():
    source = json.loads((ESTIMATOR / "SOURCE.json").read_text())
    if source["commit"] != COMMIT:
        raise ValueError("Unexpected lattice-estimator commit")
    actual = {str(p.relative_to(ESTIMATOR)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted((ESTIMATOR / "estimator").rglob("*.py"))}
    if actual != source["source_sha256"]:
        raise ValueError("Vendored lattice-estimator sources differ from the pin")
    sys.path.insert(0, str(ESTIMATOR))
    from sage.all import RealField, ZZ
    from estimator import LWE, ND
    from estimator.io import Logging
    from estimator.reduction import MATZOV
    from estimator.cost import Cost
    Logging.set_level(Logging.ERROR)
    # Eagerly evaluated optimizer log strings otherwise format huge symbolic
    # costs even in quiet mode. Only diagnostic repr text changes; arithmetic,
    # comparisons, Cost.__str__, and the vendored sources remain unchanged.
    Cost.__repr__ = lambda self: "Cost(<optimizer debug formatting suppressed>)"
    return LWE, ND, MATZOV, RealField(256), ZZ


def specification(row, role):
    r, c = row["runtime"], row["candidate"]
    d, k, ell = c["degree"], r["k"], r["ell"]
    if role == "hint":
        law = {"kind": "gaussian", "width": str(c["sigma_H"])}
    else:
        law = {"kind": "cbd", "eta": r[role + "_eta"]}
    n, m = (k*d, ell*d) if role in ("hint", "terminal") else (ell*d, (k+1)*d)
    return {"n": n, "m": m, "q": r["q"], "distribution": law, "tag": role}


def estimate(spec, mode, api):
    LWE, ND, MATZOV, RF, ZZ = api
    law = spec["distribution"]
    if law["kind"] == "gaussian":
        distribution = ND.DiscreteGaussian(RF(law["width"]) / (2*RF.pi()).sqrt())
    else:
        # Sage integer arithmetic preserves the exact CBD density. The frozen
        # suite uses eta <= 22 and needs no large-eta density adapter.
        distribution = ND.CenteredBinomial(ZZ(law["eta"]))
    params = LWE.Parameters(n=ZZ(spec["n"]), m=ZZ(spec["m"]), q=ZZ(spec["q"]),
                            Xs=distribution, Xe=distribution, tag=spec["tag"])
    model = MATZOV(nn=mode)
    start = time.monotonic()
    costs = LWE.estimate(params, red_cost_model=model, red_shape_model="gsa",
                         deny_list=tuple(), jobs=1, catch_exceptions=False, quiet=True)

    def summarize(cost):
        bits = float(RF(cost["rop"]).log2())
        if math.isnan(bits) or bits == -math.inf:
            raise ArithmeticError("Invalid attack cost")
        return {"bits": bits if math.isfinite(bits) else "infinity",
                "beta": int(cost["beta"]) if "beta" in cost else None,
                "details": str(cost)}

    attacks = {name: summarize(cost) for name, cost in costs.items()}
    if set(attacks) != ATTACKS:
        raise ArithmeticError("Incomplete attack set: " + str(sorted(attacks)))
    # The upstream local GSA optimizer can miss a cheaper valid block size.
    # Retain the exhaustive finite scan used for the frozen evidence.
    from estimator.lwe_primal import PrimalUSVP
    from estimator.lwe_parameters import LWEParameters
    normalized = LWEParameters.normalize(params)
    embed_m = normalized.m + normalized.n if normalized.Xs <= normalized.Xe else normalized.m
    native = deepcopy(attacks["usvp"])
    maximum = min(int(embed_m), 600)
    for beta in range(40, maximum + 1):
        cost = PrimalUSVP.cost_gsa(beta, normalized, m=embed_m, red_cost_model=model)
        candidate = summarize(cost)
        bits = candidate["bits"]
        if isinstance(bits, (int, float)) and (
                not isinstance(attacks["usvp"]["bits"], (int, float))
                or bits < attacks["usvp"]["bits"]):
            attacks["usvp"] = candidate
    finite = [a["bits"] for a in attacks.values() if isinstance(a["bits"], (int, float))]
    if not finite:
        raise ArithmeticError("No finite attack cost")
    return {"instance": spec, "mode": mode, "method": "full", "status": "ok",
            "reduction_cost_model": "MATZOV", "shape": "gsa", "estimator_commit": COMMIT,
            "quantum_model": "list_decoding-dw" if mode == "quantum" else None,
            "attacks": attacks, "min_bits": min(finite), "full_gate_passed": min(finite) >= 128,
            "seconds": time.monotonic() - start,
            "usvp_block_scan": {"min_beta": 40, "max_beta": maximum,
                                "embedding_sample_limit": int(embed_m), "native_usvp": native,
                                "result": deepcopy(attacks["usvp"])}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("L", "M", "H", "all"), default="all")
    parser.add_argument("--role", choices=ROLES + ("all",), default="all")
    parser.add_argument("--mode", choices=("classical", "quantum"), default="classical")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-imports", action="store_true", help="validate pin and import Sage/estimator only")
    args = parser.parse_args()
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                 "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS"):
        os.environ[name] = "1"
    api = load_estimator()
    if args.check_imports:
        print(json.dumps({"status": "ok", "estimator_commit": COMMIT,
                          "required_attacks": sorted(ATTACKS)}))
        return
    data = json.loads((HERE / "profiles.json").read_text())
    if data["estimator_commit"] != COMMIT:
        raise ValueError("Profile and estimator pins differ")
    selected = list(data["profiles"]) if args.profile == "all" else [args.profile]
    roles = ROLES if args.role == "all" else (args.role,)
    results, cache = {}, {}
    for name in selected:
        results[name] = {}
        for role in roles:
            spec = specification(data["profiles"][name], role)
            key = json.dumps({k: v for k, v in spec.items() if k != "tag"}, sort_keys=True)
            print("Estimating " + name + "/" + role + " (all eight attacks)", file=sys.stderr, flush=True)
            if key not in cache:
                cache[key] = estimate(spec, args.mode, api)
            result = deepcopy(cache[key])
            result["instance"] = spec
            results[name][role] = result
    report = {"schema": "latpre-security-rerun-v1", "profile_id": data["profile_id"],
              "mode": args.mode, "results": results,
              "passed": all(v["full_gate_passed"] for row in results.values() for v in row.values()),
              "scope": "underlying lattice attack-cost estimates; not a concrete multi-user PRE bound"}
    encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
