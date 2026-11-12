#!/usr/bin/env python3
"""Build, test, and run the paper's single-threaded measurements in sequence."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
THREAD_ENV = {
    name: "1" for name in (
        "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS", "GOMAXPROCS")
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--samples", type=int, default=1000)
    p.add_argument("--warmup", type=int, default=10)
    p.add_argument("--jobs", type=int, default=2, help="Build jobs only")
    p.add_argument("--mode", choices=("all", "build", "test", "bench"), default="all")
    p.add_argument("--components", default="latpre,cic25,hybrid")
    p.add_argument("--cmake", default=os.environ.get("CMAKE", "cmake"))
    p.add_argument("--go", default=os.environ.get("GO", "go"))
    p.add_argument("--openfhe-dir", type=Path, help="Explicit matching patched OpenFHE package")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    components = set(args.components.split(","))
    if not components or components - {"latpre", "cic25", "hybrid"}:
        p.error("--components must select latpre,cic25,hybrid")
    if args.samples < 1 or args.warmup < 0 or args.jobs < 1:
        p.error("Invalid sample, warmup, or build count")
    if "hybrid" in components and args.samples + args.warmup + 1 > 1024:
        p.error("Hybrid Light requires samples + warmup + 1 <= M=1024")
    requirements = ["make", "cc"]
    if "cic25" in components:
        requirements += [args.cmake]
        if args.openfhe_dir is None:
            requirements += ["git"]
    if "hybrid" in components:
        requirements += [args.go]
    for binary in requirements:
        if not shutil.which(binary):
            p.error("Required program not found: " + binary + "; see README.md")
    # Child builds change directory; keep explicit relative tool overrides valid.
    if "cic25" in components:
        args.cmake = str(Path(shutil.which(args.cmake)).resolve())
    if "hybrid" in components:
        args.go = str(Path(shutil.which(args.go)).resolve())
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = (args.output or ROOT / "results/local" / ("run-" + now)).resolve()
    if out.exists() and any(out.iterdir()):
        p.error("Output directory must be new or empty: " + str(out))
    (out / "logs").mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, **THREAD_ENV, GO=args.go, CMAKE=args.cmake)
    manifest = {
        "samples": args.samples, "warmup": args.warmup,
        "components": sorted(components), "mode": args.mode,
        "platform": platform.system(), "architecture": platform.machine(),
        "python": platform.python_version(), "single_thread_environment": THREAD_ENV,
        "steps": [], "status": "running",
    }

    def save():
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def run(name, command):
        print("\n[" + name + "]", flush=True)
        start = time.monotonic()
        with (out / "logs" / (name + ".log")).open("w") as log:
            result = subprocess.run([str(x) for x in command], cwd=ROOT,
                                    env=env, stdout=log, stderr=subprocess.STDOUT)
        manifest["steps"].append({
            "name": name, "returncode": result.returncode,
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "log": "logs/" + name + ".log",
        })
        save()
        if result.returncode:
            print((out / "logs" / (name + ".log")).read_text()[-12000:], file=sys.stderr)
            raise RuntimeError(name + " failed; raw log retained")
        print("PASS", flush=True)

    try:
        run("parameters", [sys.executable, "params/verify.py", "--output", out / "parameters.json"])
        if "latpre" in components or "hybrid" in components:
            run("latpre-build", ["make", "-C", "latpre", "-j" + str(args.jobs), "all"])
        if "cic25" in components:
            command = [sys.executable, "baseline/cic25/build.py",
                       "--cmake", args.cmake, "--jobs", args.jobs]
            if args.openfhe_dir:
                command += ["--openfhe-dir", args.openfhe_dir.resolve()]
            run("cic25-build", command)
        if "hybrid" in components:
            run("hybrid-build", ["make", "-C", "hybrid-mail", "build"])
        if args.mode in ("all", "test"):
            if "latpre" in components or "hybrid" in components:
                run("latpre-tests", ["make", "-C", "latpre", "test"])
            if "hybrid" in components:
                run("hybrid-tests", ["make", "-C", "hybrid-mail", "test"])
                run("proton-official-test", ["make", "-C", "hybrid-mail", "proton-test"])
                run("offline-forwarding-demo", ["make", "-C", "hybrid-mail", "demo"])
        if args.mode in ("all", "bench"):
            # No concurrent benchmark processes: do not change to a parallel map.
            if "latpre" in components:
                run("latpre-benchmark", ["latpre/build/bench_lbpre",
                    "--samples", args.samples, "--warmup", args.warmup,
                    "--logQ", "20,30,40", "--csv", out / "latpre.csv",
                    "--json", out / "latpre.json"])
            if "cic25" in components:
                run("cic25-benchmark", [sys.executable, "baseline/cic25/run_bench.py",
                    "--samples", args.samples, "--warmup", args.warmup,
                    "--output", out / "cic25"])
            if "hybrid" in components:
                run("hybrid-benchmark", ["hybrid-mail/bin/hybrid-bench",
                    "-n", args.samples, "-warmup", args.warmup,
                    "-out", out / "hybrid.json"])
                run("hybrid-wire-sizes", ["hybrid-mail/bin/hybrid-wire-size",
                    "-out", out / "hybrid-wire-sizes.json"])
            run("report", [sys.executable, "scripts/report.py", out])
            print((out / "summary.txt").read_text(), flush=True)
        manifest["status"] = "passed"
        save()
        print("Output: " + str(out), flush=True)
    except Exception:
        manifest["status"] = "failed"
        save()
        raise


if __name__ == "__main__":
    main()
