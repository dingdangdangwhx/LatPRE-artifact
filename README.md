# LatPRE artifact

Source code and reproducibility scripts for **LatPRE: Compact Lattice-Based
Proxy Re-Encryption with Security against Honest Re-Encryption Attacks**.

| Directory | Contents |
| --- | --- |
| `params/` | L/M/H parameters and verification scripts |
| `latpre/` | LatPRE C implementation, tests and benchmarks |
| `baseline/cic25/` | CiC25 single-hop comparison |
| `hybrid-mail/` | Classical and hybrid Proton forwarding prototype |
| `results/` | Saved results from 1,000 measurements, including raw samples |

## Reproduce

Requirements (macOS/Linux): Python 3.9+, Make, Git, C11/C++17 with unsigned
128-bit integer support, CMake 3.15+, Go 1.23+, and MPFR/GMP with `pkg-config`
for tests.
The first build downloads pinned OpenFHE and Go dependencies.

```sh
./run_all.sh
```

This builds and tests the code, then benchmarks LatPRE L/M/H, CiC25 single hop,
and classical/hybrid email forwarding. Benchmarks run sequentially on one
thread, reporting medians from **1,000 measurements after 10 warmups** per operation.

Outputs are saved under `results/local/run-.../`:

- `summary.txt`, `runtime.csv`, `communication.csv`: runtime and size tables.
- `hybrid-summary.csv`: email-forwarding results.
- Component JSON/CSV files and logs: raw samples, parameters and test records.

Use `./run_all.sh --help` for component selection and other options. Set `GO`
or `CMAKE` if these tools are not on `PATH`.

## Parameters and measurements

The classical-128 profiles are L `(Q,M)=(2^20,2^10)`, M `(2^30,2^15)`, and H
`(2^40,2^20)`. Exact constants are in `params/profiles.json`. See
`params/README.md` for optional parameter recomputation, which requires SageMath.
The default run checks saved evidence without rerunning the lattice estimator.

LatPRE uses the OpenFHE-style Gaussian sampler. Rekey sizes include the 32-byte
seed, and key sizes include both key roles. `ReKeyGen` excludes NTT preparation;
`ReEnc` uses a prepared rekey and recomputes its mask. `Dec` in the summary
decrypts re-encrypted ciphertexts.

CiC25 uses the local single-hop patch documented in `baseline/cic25/README.md`;
its comparison PK counts the native `b` payload. The hybrid prototype combines
Proton's classical forwarding with LatPRE Light; see `hybrid-mail/README.md`.
