#ifndef LBPRE_SAMPLING_H
#define LBPRE_SAMPLING_H
#include "lbpre.h"
#include "sha3_t.h"
struct lbpre_rng { sha3_t xof; };
typedef struct lbpre_gaussian lbpre_gaussian;
void lbpre_rng_bytes(lbpre_rng *rng, uint8_t *out, size_t len);
void lbpre_xof_begin(sha3_t *s, const char *domain);
void lbpre_uniform_poly(uint64_t out[LBPRE_D], uint64_t q, lbpre_rng *rng);
void lbpre_ternary_poly(uint64_t out[LBPRE_D], uint64_t q, lbpre_rng *rng);
/* Exact CBD_eta coefficients, using 2*eta fresh independent SHAKE bits each.
 * Var=eta/2; CBD_1 probabilities are (1/4,1/2,1/4), NOT uniform ternary.
 * Consumes exactly 64*eta bytes. eta must be positive, q must be nonzero.
 * Binomial halves are streamed in 64-bit chunks; eta may exceed 64. */
void lbpre_cbd_poly(uint64_t out[LBPRE_D], uint64_t q, unsigned eta,
                    lbpre_rng *rng);
/* OpenFHE-style C adaptation of finite-precision discrete Gaussian sampling.
 * Converts width sigma to stddev sigma/sqrt(2*pi); CDF for stddev<300,
 * Karney otherwise. Requires C numeric locale, FE_TONEAREST, IEEE binary32/
 * binary64, finite positive representable variance, and width<=2^40.
 * Variable-time; no certified full statistical-distance bound is claimed.
 * CDF radius is its support endpoint; Karney radius INT64_MAX is a checked
 * representation bound, not a tail cutoff. No global PRNG or spare state.
 * Scalar/poly calls consume the same stream. Invalid constructor inputs
 * return NULL; later fenv/range failures abort. */
lbpre_gaussian *lbpre_gaussian_new(const char *sigma);
void lbpre_gaussian_free(lbpre_gaussian *g);
int64_t lbpre_gaussian_sample(lbpre_gaussian *g, lbpre_rng *rng);
void lbpre_gaussian_poly(uint64_t out[LBPRE_D], uint64_t q,
                         lbpre_gaussian *g, lbpre_rng *rng);
uint64_t lbpre_gaussian_radius(const lbpre_gaussian *g);
/* Display name for benchmark metadata. */
const char *lbpre_gaussian_backend(void);
/* Stable historical protocol identifier, independent of the display name. */
const char *lbpre_gaussian_context_id(void);
int lbpre_gaussian_is_approximate(void);
const char *lbpre_gaussian_target(void);
int lbpre_gaussian_has_certified_error_bound(void);
void lbpre_secure_zero(void *ptr, size_t len);
#endif
