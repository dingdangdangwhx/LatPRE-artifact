#!/usr/bin/env python3
"""Verify the three fixed parameter sets without Sage or a network connection."""
import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "lib"))
from bounds import verify_gaussian_and_sphere

ATTACKS = {"arora-gb", "bkw", "usvp", "bdd", "bdd_hybrid",
           "bdd_mitm_hybrid", "dual", "dual_hybrid"}


def load(path):
    return json.loads(path.read_text(), parse_float=Decimal)


def validate_security(item, commit):
    row, result = item["candidate"], {}
    for role, spec in item["security"].items():
        path = HERE / spec["record"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == spec["sha256"]
        record = load(path)
        assert record["mode"] == "classical" and record["method"] == "full"
        assert record["reduction_cost_model"] == "MATZOV"
        assert record["shape"] == "gsa" and record["estimator_commit"] == commit
        assert record["status"] == "ok" and record["full_gate_passed"]
        assert ATTACKS <= record["attacks"].keys()
        inst = record["canonical_instance"]
        n, m = ((row["ell"] * 256, (row["k"] + 1) * 256)
                if role in ("source", "internal")
                else (row["k"] * 256, row["ell"] * 256))
        assert (inst["n"], inst["m"], inst["q"]) == (n, m, row["q"])
        for name in ("secret_distribution", "error_distribution"):
            if role == "hint":
                assert inst[name]["kind"] == "gaussian"
                assert Decimal(inst[name]["width"]) == Decimal(row["sigma_H"])
            else:
                law = row["terminal_distribution"] if role == "terminal" else row[role + "_distribution"]
                assert inst[name]["kind"] == law["kind"] == "cbd"
                assert inst[name]["eta"] == law["eta"]
        costs = [Decimal(str(v["bits"])) for v in record["attacks"].values()]
        minimum = min(costs)
        assert minimum == record["min_bits"] == spec["min_bits"] >= 128
        result[role] = str(minimum)
    return result


def validate_sizes(runtime):
    k, ell, d, bits = runtime["k"], runtime["ell"], 256, runtime["q_bits"]
    w = k * runtime["length"]
    values = {
        "public_key_bytes": 2 * ell * d * bits // 8,
        "secret_key_bytes": 2 * k * d * bits // 8,
        "source_ct_bytes": d * (k * bits + runtime["source_v_bits"]) // 8,
        "reenc_ct_bytes": d * (k * runtime["re_u_bits"] + runtime["re_v_bits"]) // 8,
        "rekey_bytes": (k + 1) * w * d * bits // 8 + 32,
    }
    for name, value in values.items():
        assert value == runtime["sizes_bytes"][name], name
    assert runtime["sizes_bytes"]["rekey_seed_bytes"] == 32
    assert runtime["source_eta"] == runtime["internal_eta"] == 1
    assert runtime["base"] % 2 == 1
    assert runtime["base"] ** (runtime["length"] - 1) < runtime["q"] <= runtime["base"] ** runtime["length"]
    assert runtime["q_bits"] == runtime["q"].bit_length()
    assert runtime["q"] % 512 == 1
    return values


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    data = load(HERE / "profiles.json")
    runtime_manifest = load(HERE.parent / "latpre" / "PARAMETER_SOURCE.json")
    assert data["profile_id"] == runtime_manifest["profile_id"]
    manifest_rows = {row["name"]: row for row in runtime_manifest["generated_parameters"]}
    assert len(manifest_rows) == len(runtime_manifest["generated_parameters"])
    assert set(data["profiles"]) == set(runtime_manifest["profiles"]) == set(manifest_rows)
    results = {}
    for label, item in data["profiles"].items():
        runtime, row = item["runtime"], item["candidate"]
        assert runtime == manifest_rows[label], label + ": runtime manifest mismatch"
        assert (runtime["logQ"], runtime["logM"]) == {
            "L": (20, 10), "M": (30, 15), "H": (40, 20)}[label]
        bounds = verify_gaussian_and_sphere(row, runtime)
        costs = validate_security(item, data["estimator_commit"])
        assert item["dfr"]["passed"]
        assert Decimal(item["dfr"]["joint_log2_upper"]) < -128
        results[label] = {
            "sizes_bytes": validate_sizes(runtime),
            "minimum_lattice_cost_bits": costs, "spectral_and_gaussian": bounds,
            "archived_ideal_dfr_log2_upper": item["dfr"]["joint_log2_upper"],
        }
        print(label + ": PASS (packed sizes, all MLWE records, spectral witness, Gaussian widths)")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2, default=str) + "\n")


if __name__ == "__main__":
    main()
