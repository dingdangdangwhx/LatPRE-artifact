# LatPRE C implementation

Portable, single-threaded scalar C for the frozen classical-128 L/M/H parameters.
The only Gaussian sampler is the self-contained OpenFHE-style CDF/Karney port.
No OpenFHE C++ library, high-precision Gaussian sampler, or SIMD backend is used.

    make
    make test
    ./build/bench_lbpre --samples 1000 --warmup 10 --csv timings.csv --json timings.json

The library and benchmark require a C11 compiler with unsigned 128-bit integers,
Make, and the C math library. The test suite additionally needs MPFR, GMP, and
pkg-config; these libraries check the frozen decimal width constants and are
not linked into the implementation or benchmarks.

The default benchmark reports Setup, KeyGen, Enc, ReKeyGen, ReEnc, and
DecTerminal for all three profiles. Use --logQ 20, 30, or 40 for one profile.
Each operation has ten untimed warmups and 1,000 timed measurements by default.
JSON retains the individual nanosecond samples; reported summaries are medians.
RNG construction is outside the timed region; cryptographic sampling and
serialization are inside it. ReKeyGen measures wire-key generation without NTT
preparation; ReEnc uses a prepared rekey, recomputes its mask, and samples fresh
randomness for every call. The --all-operations option adds diagnostic preparation,
registration, source-decryption, and cached-pad measurements.

The public API is in include/lbpre.h. The named profiles L, M, and H correspond
to logQ 20, 30, and 40. Each serialized rekey includes its independent 32-byte
seed. Both public- and secret-key sizes include source and terminal key roles.

Supplementary profiles are `E20_10`, `E20_15`, `E20_20`, `E25_15`, `E30_20`,
`E50_25` and `E60_30`, where the two numbers are log2(Q) and log2(M). Use
`lbpre_setup_named(name, seed)` or benchmark `--profiles E20_15,E20_20` to
distinguish sets sharing Q. `lbpre_setup(logQ, seed)` and the default benchmark
still select the original L/M/H sets. E20_10 repeats Light. Exact supplementary
constants are in `EXTENDED_PARAMETER_SOURCE.json`; their measurements and
candidate-selection evidence are in `../results/extended-classical128/`.
The widest mask uses the same Karney sampler with integer-assisted proposal
arithmetic; frozen L/M/H sampling streams are unchanged.

Mask derivation depends on the seed, public context, user identities, and source
record. It does not depend on the rekey matrix. The sampler's stable internal
context identifier is retained to preserve frozen deterministic streams.
The implementation is variable-time; finite-precision Gaussian sampling is not
accompanied by a certified statistical-distance bound.

PARAMETER_SOURCE.json records the exact profiles and original manifest digest.
The top-level params/ component contains the parameter-analysis evidence.
The tests check ring arithmetic, encodings, CBD and Gaussian known-answer
vectors, quotas, stable masks, and source/terminal decryption.

Third-party notices are retained in licenses/: the SHA3/Keccak files derive
from mmCipher/Kyber, and the Gaussian port derives from OpenFHE. No third-party
copyright or license notice has been removed.
