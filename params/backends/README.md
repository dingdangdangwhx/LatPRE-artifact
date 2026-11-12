These optional recomputation backends support the frozen parameter profiles.

- noise_bounds.py implements the dependency-aware spectral MGF/CDF noise
  envelopes and selects positive tilts using floating point.
- cbd_noise_bounds.py verifies those tilts with SageMath 512-bit directed
  intervals. Its formulas are retained from the frozen correctness analysis.
- cbd_rounding.c constructs the CBD component PMF using integer CRT/NTT
  convolution and bounds its stop-loss moments with outward MPFR arithmetic.
  lbpre_dist and crt_ntt are its supporting arithmetic implementation.

The C PMF covers the terminal ciphertext rounding component, not the entire
PRE noise distribution. The remaining source, shared-secret, and Gaussian
terms use analytic bounds. No normal approximation or independence of shared
terminal-secret terms is assumed. The reported failure bound concerns one
honest encryption/re-encryption pair under ideal Gaussian sampling.

The helper formulas and C arithmetic derive from the mmCipher artifact and
the LatPRE parameter analysis. See LICENSE-MIT. No high-precision runtime
Gaussian sampler is included here; MPFR is used only for parameter analysis.
