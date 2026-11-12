#!/usr/bin/env python3
"""Export completed measurements, omitting machine paths and build logs."""
import argparse
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
FILES = ("manifest.json", "parameters.json", "latpre.json", "latpre.csv",
         "cic25.json", "cic25.csv", "hybrid.json", "hybrid-wire-sizes.json",
         "runtime.csv", "communication.csv", "hybrid-summary.csv",
         "summary.json", "summary.txt")


def scrub(value, run):
    if isinstance(value, dict):
        return {key: scrub(item, run) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, run) for item in value]
    if isinstance(value, str):
        value = value.replace(str(run), "results")
        value = value.replace(str(ROOT) + "/", "")
        if value.startswith("/") or re.search(r"/(?:Users|home)/", value):
            return "<local-path-omitted>"
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    manifest = json.loads((run / "manifest.json").read_text())
    if manifest["status"] != "passed":
        parser.error("Only completed, passing runs can be exported")
    dest = ROOT / "results"
    dest.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        source = run / name
        if not source.exists():
            continue
        if source.suffix == ".json":
            data = scrub(json.loads(source.read_text()), run)
            if name == "manifest.json":
                for step in data["steps"]:
                    step.pop("log", None)
                data["export_note"] = "Build logs omitted; timing samples and numeric values retained."
            (dest / name).write_text(json.dumps(data, indent=2) + "\n")
        else:
            shutil.copyfile(source, dest / name)
    (dest / "README.md").write_text(
        "# Benchmark results\n\n"
        f"Completed sequential run on {manifest['platform']} {manifest['architecture']}: "
        f"{manifest['samples']} measurements per operation after {manifest['warmup']} warmups.\n\n"
        "| Files | Contents |\n"
        "| --- | --- |\n"
        "| `summary.txt`, `summary.json` | Combined runtime and communication summaries |\n"
        "| `runtime.csv`, `communication.csv` | LatPRE L/M/H and CiC25 runtime and byte-count tables |\n"
        "| `latpre.json`, `latpre.csv`, `cic25.json`, `cic25.csv` | Component measurements; JSON retains individual timing samples |\n"
        "| `hybrid.json`, `hybrid-summary.csv` | Classical/hybrid forwarding measurements for 10 KB, 100 KB, and 1 MB payloads |\n"
        "| `hybrid-wire-sizes.json` | Key, authorization, and envelope sizes for the email prototype |\n"
        "| `manifest.json`, `parameters.json` | Run status and frozen-parameter verification |\n\n"
        "Paths were normalized for publication; numeric measurements were not "
        "modified. Build logs and demo secret keys are excluded. New runs are "
        "saved separately under `local/`.\n\n"
        "These are reproducibility measurements, not replacements for the "
        "paper's frozen timing table. Runtime differences depend on the host "
        "and measurement conditions. See the root README for accounting conventions.\n")
    print("Exported to results/")


if __name__ == "__main__":
    main()
