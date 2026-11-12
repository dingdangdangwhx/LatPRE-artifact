#!/usr/bin/env python3
"""Recompute frozen-profile correctness with C PMFs and Sage 512-bit intervals.

Run with SageMath: sage -python certify.py --profile L --output results/dfr-L.json.
The default reruns the C rounding backend. --reuse-rounding-evidence instead
uses the archived mathematical certificates, without claiming a new PMF run.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BACKENDS = HERE / "backends"


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def rounding(row, binary, directory):
    r, b = row["runtime"], row["dfr"]["budgets"]
    command = [str(binary), "--eta", str(r["terminal_eta"]), "--k", str(r["k"]),
               "--degree", str(row["candidate"]["degree"]), "--round-bits", str(b["round_bits"]),
               "--precision", "512"]
    certificate = json.loads(subprocess.check_output(command, text=True))
    certificate["backend_source_sha256"] = {
        name: hashlib.sha256((BACKENDS / name).read_bytes()).hexdigest()
        for name in ("cbd_rounding.c", "lbpre_dist.c", "lbpre_dist.h", "crt_ntt.c", "crt_ntt.h")}
    path = directory / ("eta%d_k%d_d%d_rb%d.json" % (
        r["terminal_eta"], r["k"], row["candidate"]["degree"], b["round_bits"]))
    write(path, certificate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("L", "M", "H", "all"), default="all")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reuse-rounding-evidence", action="store_true")
    parser.add_argument("--rounding-binary", type=Path, default=HERE / "build" / "cbd_rounding")
    parser.add_argument("--check-imports", action="store_true", help="check Sage and bound helpers only")
    args = parser.parse_args()
    from sage.all import RealIntervalField
    sys.path.insert(0, str(BACKENDS))
    from noise_bounds import distribution, noise_model
    import cbd_noise_bounds
    if args.check_imports:
        RealIntervalField(512)
        print(json.dumps({"status": "ok", "precision_bits": 512}))
        return
    data = json.loads((HERE / "profiles.json").read_text())
    selected = list(data["profiles"]) if args.profile == "all" else [args.profile]
    if not args.reuse_rounding_evidence and not args.rounding_binary.is_file():
        subprocess.run(["make", "-C", str(HERE), "rounding"], check=True)
    results = {}
    # Generated certificates are used during this run and embedded in the
    # output; no compiler-specific binary digest is used as a validity test.
    with tempfile.TemporaryDirectory(prefix="latpre-rounding-") as temporary:
        directory = HERE / "evidence" / "rounding" if args.reuse_rounding_evidence else Path(temporary)
        cbd_noise_bounds.set_rounding_directory(directory)
        for name in selected:
            row = data["profiles"][name]
            r, c, b = row["runtime"], row["candidate"], row["dfr"]["budgets"]
            if not args.reuse_rounding_evidence:
                rounding(row, args.rounding_binary.resolve(), directory)
            model = noise_model(r["k"], r["ell"], c["degree"], r["base"], r["length"],
                                float(r["source_std"]), math.sqrt(r["terminal_eta"]/2),
                                float(r["pad_std"]), distribution("cbd", r["source_eta"]),
                                distribution("cbd", r["internal_eta"]),
                                terminal_dist=distribution("cbd", r["terminal_eta"]))
            print("Certifying " + name + " correctness at 512 bits", file=sys.stderr, flush=True)
            result = cbd_noise_bounds.certify(model, r["q"], r["source_v_bits"],
                                             r["re_u_bits"], r["re_v_bits"],
                                             round_bits=b["round_bits"], failure_bits=b["failure_bits"],
                                             source_bits=b["source_bits"])
            result["frozen_joint_log2_upper"] = row["dfr"]["joint_log2_upper"]
            results[name] = result
    report = {"schema": "latpre-correctness-rerun-v1", "profile_id": data["profile_id"],
              "precision_bits": 512, "rounding_recomputed": not args.reuse_rounding_evidence,
              "results": results, "passed": all(x["passed"] for x in results.values()),
              "scope": "one honest encryption/re-encryption pair; ideal Gaussian sampling; source u exact"}
    if args.output:
        write(args.output, report)
    else:
        print(json.dumps(report, indent=2, allow_nan=False))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
