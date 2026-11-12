#!/usr/bin/env python3
"""Run the fixed single-hop comparison; output raw CSV and JSON with medians."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--samples", type=int, default=1000)
    p.add_argument("--warmup", type=int, default=10)
    p.add_argument("--output", type=Path, default=HERE / "results/cic25")
    p.add_argument("--build-dir", type=Path, default=HERE / "build")
    a = p.parse_args()
    binary = a.build_dir.resolve() / "bench_cic25"
    if not binary.is_file():
        raise SystemExit("Run configure.sh first: " + str(binary))
    a.output = a.output.resolve()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    for variable in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                     "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS"):
        env[variable] = "1"
    subprocess.run([str(binary), "--samples", str(a.samples), "--warmup", str(a.warmup),
                    "--output", str(a.output)], env=env, check=True)
    result = json.loads(Path(str(a.output) + ".json").read_text())
    if result["status"] != "ok" or result["openmp_compiled"]:
        raise SystemExit("Benchmark failed or is not single-threaded")
    params = result["parameters"]
    if (params["ring_dimension"], params["Q"]["product_bits"], params["P"]["product_bits"]) != (4096, 54, 55):
        raise SystemExit("Benchmark does not match the frozen comparison profile")
    print("CiC25 single-hop HRA, median milliseconds")
    for name in ("Setup", "KeyGen", "ReKeyGen", "Enc", "DecSource", "ReEnc", "DecTerminal"):
        operation = result["operations"][name]
        raw = operation["raw_ns"]
        if len(raw) != a.samples or operation["status"] != "ok":
            raise SystemExit("Missing raw measurements: " + name)
        if statistics.median(raw) != operation["median_ns"]:
            raise SystemExit("Median does not match the raw samples: " + name)
        print(f"{name:12s} {operation['median_ns'] / 1e6:.6f}")
    print("Public-key b native payload (bytes):", params["public_key_b_native_payload_bytes"])
    for name in ("public_key", "secret_key", "rekey", "source_ciphertext", "re_ciphertext"):
        print(name + " serialized bytes:", result["sizes_bytes"][name]["standalone"])
    print("Raw output:", str(a.output) + ".json / .csv")


if __name__ == "__main__":
    main()
