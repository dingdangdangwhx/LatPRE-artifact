# CiC 2025 single-hop comparison

This component reproduces the local single-hop comparison for Cohen et al.,
*HRA-Secure Homomorphic Lattice-Based Proxy Re-Encryption with Tight Security*,
CiC 2025, DOI [10.62056/ab0l5wol7](https://doi.org/10.62056/ab0l5wol7).
It uses OpenFHE v1.2.0 at the exact revision in `upstream.json`.

## Run

Requires Python 3, Git, CMake >= 3.15, and a C++17 compiler on macOS or Linux.
The first build downloads OpenFHE and its pinned cereal submodule. It installs
only below this directory; no system installation is performed.

```sh
sh configure.sh
sh run_bench.sh --samples 1000 --warmup 10 --output results/cic25
```

`sh configure.sh --cmake PATH --jobs 2` selects CMake and compilation parallelism.
An explicitly selected existing, matching patched installation can be reused:

```sh
sh configure.sh --openfhe-dir /path/to/install/lib/OpenFHE
```

Benchmarks run sequentially with OpenMP disabled. JSON contains raw nanosecond
samples and medians; CSV contains one row per measured operation. Correctness
checks and serialization are outside the timing intervals. Setup measures
context generation after warmup, including the library's retained public NTT
caches. Every encryption and re-encryption is checked by decrypting all 4096
plaintext coefficients, including the zero padding after the 256-bit message.

## Fixed profile and included patch

The profile is single-hop HRA/HYBRID with ring degree 4096, plaintext modulus 2,
Q54/P55, classical-128 OpenFHE checks, statistical parameter 48, and query
budget 2^18. `patches/openfhe-v1.2.0-single-hop.patch` contains the exact local
changes used for the comparison: the small-Gaussian CDF cutoff correction and a
narrowly guarded single-hop parameter-generation adjustment. The flooding
width and library security checks are retained. This is a local reproduction,
not the authors' original benchmark binary or published timing table.

`reference.json` retains the selected parameters, byte counts and reference
medians. Raw standalone serialization is 66,493 bytes for a source ciphertext,
66,533 bytes for a re-encrypted ciphertext and 132,077 bytes for a rekey. The
reported comparison public-key size is the 65,536-byte b-only native payload;
the full serialized public key is separately reported. Neither is an invented
compressed serialization.

Upstream OpenFHE and cereal licenses are retained in `licenses/`. Their complete
source is fetched at the pinned revisions; build products and source histories
are excluded from the release repository.
