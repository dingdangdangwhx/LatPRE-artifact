# Parameter verification and recomputation

`profiles.json` contains the frozen classical-128 Light, Middle and Heavy
profiles, including exact implementation constants and references to retained
security/rounding evidence. These profiles are not changed by the scripts.

## Fast verification (Python standard library)

```sh
python3 params/verify.py --output results/local/parameters.json
```

Run this from the artifact root. It checks the recorded lattice instances and
attack costs, spectral witnesses, Gaussian-width conditions, byte counts and
retained correctness bounds. This verifies saved evidence; it does not rerun
the estimator or the C probability-mass-function calculation.

## Optional fresh calculations

Requires SageMath, a C11 compiler with unsigned 128-bit integers, MPFR, GMP,
and `pkg-config`. From the artifact root:

```sh
make -C params rounding
sage -python params/certify.py --profile L --output results/local/correctness-L.json
sage -python params/security.py --profile L --role terminal --output results/local/security-L-terminal.json
```

Use `--profile all` for all profiles and `--role all` for all lattice instances.
`params/security.py` uses the vendored lattice-estimator commit `53da598` with
the MATZOV classical cost model and GSA, including primal, dual, hybrid, BKW
and algebraic attacks. Full estimator runs can be slow; they are separate from
the 1,000-measurement implementation benchmark. `--mode quantum` is an optional
assessment of the same frozen parameters, not a quantum-128 parameter search.

`certify.py` rebuilds the C CBD rounding calculation and evaluates the
correctness bound with 512-bit interval arithmetic. Use
`--reuse-rounding-evidence` to check the retained rounding record instead.
The C/MPFR code is parameter-analysis code, not a high-precision runtime
Gaussian sampler. See each script's `--help` and `backends/README.md`.

`evidence/security/` retains the original per-attack records; `evidence/rounding/`
contains the certified rounding envelopes. The spectral and Gaussian checks
in `lib/` use directed decimal interval calculations and rational witnesses.
Vendored source licenses and pinned hashes are included under `vendor/`.
