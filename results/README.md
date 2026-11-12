# Benchmark results

Completed sequential run on Darwin arm64: 1000 measurements per operation after 10 warmups.

| Files | Contents |
| --- | --- |
| `summary.txt`, `summary.json` | Combined runtime and communication summaries |
| `runtime.csv`, `communication.csv` | LatPRE L/M/H and CiC25 runtime and byte-count tables |
| `latpre.json`, `latpre.csv`, `cic25.json`, `cic25.csv` | Component measurements; JSON retains individual timing samples |
| `hybrid.json`, `hybrid-summary.csv` | Classical/hybrid forwarding measurements for 10 KB, 100 KB, and 1 MB payloads |
| `hybrid-wire-sizes.json` | Key, authorization, and envelope sizes for the email prototype |
| `manifest.json`, `parameters.json` | Run status and frozen-parameter verification |

Paths were normalized for publication; numeric measurements were not modified. Build logs and demo secret keys are excluded. New runs are saved separately under `local/`.

These are reproducibility measurements, not replacements for the paper's frozen timing table. Runtime differences depend on the host and measurement conditions. See the root README for accounting conventions.
