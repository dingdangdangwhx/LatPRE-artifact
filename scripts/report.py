#!/usr/bin/env python3
"""Validate saved measurements and produce compact communication/runtime tables."""
import argparse
import csv
import json
from pathlib import Path
import statistics

OPS = ("Setup", "KeyGen", "ReKeyGen", "Enc", "DecTerminal", "ReEnc")
SIZES = ("PK_B", "SK_B", "RK_B", "S_CT_B", "R_CT_B")


def median(raw, reported, tolerance_ns=0.5):
    if not raw:
        raise ValueError("Missing samples")
    value = statistics.median(raw)
    if abs(value - reported) > tolerance_ns:
        raise ValueError("Reported median disagrees with saved samples")
    return value / 1e6


def write_csv(path, fields, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    root = args.run
    manifest = json.loads((root / "manifest.json").read_text())
    count = manifest["samples"]
    times, sizes, hybrid = [], [], []
    if (root / "latpre.json").exists():
        data = json.loads((root / "latpre.json").read_text())
        assert data["proxy_secret"] is False and data["rekey_seed_bytes"] == 32
        assert not data["reenc_default_pad_memoization"]
        records = {(r["profile"], r["operation"]): r for r in data["results"]}
        assert len(records) == 18
        for profile in ("L", "M", "H"):
            row = {"Scheme": "LatPRE-" + profile}
            for op in OPS:
                record = records[(profile, op)]
                assert record["samples"] == len(record["samples_ns"]) == count
                row[op] = median(record["samples_ns"], record["median_ns"])
            times.append(row)
            r = records[(profile, "Enc")]
            assert r["RK_seed_bytes"] == 32
            sizes.append({
                "Scheme": row["Scheme"], "PK_B": r["PK_bytes"], "SK_B": r["SK_bytes"],
                "RK_B": r["RK_bytes"], "S_CT_B": r["source_bytes"], "R_CT_B": r["RE_bytes"],
            })
    if (root / "cic25.json").exists():
        data = json.loads((root / "cic25.json").read_text())
        assert data["status"] == "ok" and not data["openmp_compiled"]
        row = {"Scheme": "CiC25"}
        for op in OPS:
            record = data["operations"][op]
            assert len(record["raw_ns"]) == count and record["status"] == "ok"
            row[op] = median(record["raw_ns"], record["median_ns"])
        times.append(row)
        fields = data["sizes_bytes"]
        sizes.append({
            "Scheme": "CiC25", "PK_B": data["parameters"]["public_key_b_native_payload_bytes"],
            "SK_B": fields["secret_key"]["standalone"],
            "RK_B": fields["rekey"]["standalone"],
            "S_CT_B": fields["source_ciphertext"]["standalone"],
            "R_CT_B": fields["re_ciphertext"]["standalone"],
        })
    if (root / "hybrid.json").exists():
        data = json.loads((root / "hybrid.json").read_text())
        assert data["measurements"] == count and data["gomaxprocs"] == 1
        assert data["warmup"] == manifest["warmup"]
        assert {suite["Suite"] for suite in data["results"]} == {"classical", "hybrid-light"}
        for suite in data["results"]:
            expected_overheads = (246, 246) if suite["Suite"] == "classical" else (4054, 2070)
            expected_rekey = 0 if suite["Suite"] == "classical" else 53792
            assert suite["Sizes"]["latpre_rekey_including_32B_seed"] == expected_rekey
            assert {p["PlaintextBytes"] for p in suite["Payloads"]} == {10240, 102400, 1048576}
            for operation, sample in suite["Setup"].items():
                assert len(sample["SamplesNS"]) == count
                hybrid.append({
                    "Suite": suite["Suite"], "Payload_B": 0, "Operation": operation,
                    "Median_ms": median(sample["SamplesNS"], sample["MedianMS"] * 1e6, 1.1),
                    "Source_B": 0, "Forwarded_B": 0,
                })
            for payload in suite["Payloads"]:
                assert (payload["SourceBytes"] - payload["PlaintextBytes"],
                        payload["ForwardedBytes"] - payload["PlaintextBytes"]) == expected_overheads
                assert set(payload["Operations"]) == {
                    "seal", "open_source", "forward_prepared", "open_receiver"}
                for operation, sample in payload["Operations"].items():
                    assert len(sample["SamplesNS"]) == count
                    hybrid.append({
                        "Suite": suite["Suite"], "Payload_B": payload["PlaintextBytes"],
                        "Operation": operation,
                        "Median_ms": median(sample["SamplesNS"], sample["MedianMS"] * 1e6, 1.1),
                        "Source_B": payload["SourceBytes"], "Forwarded_B": payload["ForwardedBytes"],
                    })
    write_csv(root / "runtime.csv", ("Scheme", *OPS), times)
    write_csv(root / "communication.csv", ("Scheme", *SIZES), sizes)
    if hybrid:
        write_csv(root / "hybrid-summary.csv",
                  ("Suite", "Payload_B", "Operation", "Median_ms", "Source_B", "Forwarded_B"), hybrid)
    summary = {
        "samples_per_operation": count, "warmup": manifest["warmup"],
        "timing_unit": "milliseconds", "size_unit": "bytes",
        "runtime": times, "communication": sizes, "hybrid": hybrid,
        "rekey_seed_bytes": 32,
        "conventions": {
            "latpre_rekeygen": "wire rekey generation; NTT preparation separate",
            "latpre_reenc": "prepared rekey, mask recomputed, no pad memoization",
            "dec": "re-encrypted ciphertext decryption",
            "cic_public_key": "native b payload; raw JSON also retains serialized public key",
        },
    }
    if any(r["Scheme"] == "CiC25" for r in times):
        base = next(r for r in times if r["Scheme"] == "CiC25")
        for row in times:
            row["ReEnc_speedup"] = base["ReEnc"] / row["ReEnc"]
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = [
        "Median runtime (ms), " + str(count) + " measurements after " + str(manifest["warmup"]) + " warmups",
        "Scheme         Setup     KeyGen   ReKeyGen        Enc        Dec      ReEnc",
    ]
    for row in times:
        lines.append(f"{row['Scheme']:12s}" + "".join(f" {row[op]:10.4f}" for op in OPS))
    lines += ["", "Communication (bytes; rekey includes its 32-byte seed)",
              "Scheme           PK          SK          RK        S CT        R CT"]
    for row in sizes:
        lines.append(f"{row['Scheme']:12s}" + "".join(f" {row[key]:10d}" for key in SIZES))
    if hybrid:
        lines += ["", "Hybrid email forwarding: see hybrid-summary.csv for all payloads and operations."]
        for row in hybrid:
            if row["Payload_B"] == 1048576 and row["Operation"] in ("seal", "forward_prepared", "open_receiver"):
                lines.append(f"{row['Suite']:14s} 1 MB {row['Operation']:18s} {row['Median_ms']:.4f} ms")
    (root / "summary.txt").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
