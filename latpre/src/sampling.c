/* OpenFHE-style discrete Gaussian sampling. The adapted implementation and
 * its BSD license are in sampling_openfhe.inc. */
#include "lbpre_sampling.h"
#include <assert.h>
#include <errno.h>
#include <fenv.h>
#include <fcntl.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__FAST_MATH__) || (defined(__FINITE_MATH_ONLY__) && __FINITE_MATH_ONLY__ > 0)
#error "The OpenFHE sampler requires finite checks; do not use -ffast-math"
#endif
#if DBL_MANT_DIG != 53 || FLT_RADIX != 2 || DBL_MAX_EXP != 1024
#error "The OpenFHE sampler requires IEEE binary64 double"
#endif

struct lbpre_gaussian {
    double stddev, zero_probability;
    uint64_t radius;
    size_t cdf_size;
    double *cdf;
};

void lbpre_secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

/* Begin absorption only: callers append their data and apply SHAKE_PAD. */
void lbpre_xof_begin(sha3_t *s, const char *domain)
{
    static const uint8_t prefix[] = "LBPRE-C-REF-v1";
    uint8_t length[8];
    size_t n, i;
    assert(s != NULL && domain != NULL);
    n = strlen(domain);
    for (i = 0; i < sizeof(length); i++)
        length[i] = (uint8_t)((uint64_t)n >> (8 * i));
    sha3_init(s, SHAKE256_RATE);
    sha3_absorb(s, prefix, sizeof(prefix)); /* includes terminating zero */
    sha3_absorb(s, length, sizeof(length));
    sha3_absorb(s, (const uint8_t *)domain, n);
}

lbpre_rng *lbpre_rng_new(const uint8_t seed[LBPRE_SEED_BYTES])
{
    lbpre_rng *rng;
    if (seed == NULL) return NULL;
    rng = (lbpre_rng *)calloc(1, sizeof(*rng));
    if (rng == NULL) return NULL;
    lbpre_xof_begin(&rng->xof, "RNG");
    sha3_absorb(&rng->xof, seed, LBPRE_SEED_BYTES);
    sha3_pad(&rng->xof, SHAKE_PAD);
    return rng;
}

void lbpre_rng_free(lbpre_rng *rng)
{
    if (rng != NULL) {
        lbpre_secure_zero(rng, sizeof(*rng));
        free(rng);
    }
}

void lbpre_rng_bytes(lbpre_rng *rng, uint8_t *out, size_t len)
{
    assert(rng != NULL && (out != NULL || len == 0));
    if (len != 0) sha3_squeeze(&rng->xof, out, len);
}

int lbpre_random_seed(uint8_t seed[LBPRE_SEED_BYTES])
{
    int fd, flags = O_RDONLY;
    size_t done = 0;
    if (seed == NULL) return LBPRE_ERR_ARGUMENT;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    do { fd = open("/dev/urandom", flags); } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        lbpre_secure_zero(seed, LBPRE_SEED_BYTES);
        return LBPRE_ERR_RANDOM;
    }
    while (done < LBPRE_SEED_BYTES) {
        ssize_t n = read(fd, seed + done, LBPRE_SEED_BYTES - done);
        if (n > 0) done += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else {
            (void)close(fd);
            lbpre_secure_zero(seed, LBPRE_SEED_BYTES);
            return LBPRE_ERR_RANDOM;
        }
    }
    /* A close EINTR is not retried: its descriptor state is platform-dependent. */
    if (close(fd) != 0) {
        lbpre_secure_zero(seed, LBPRE_SEED_BYTES);
        return LBPRE_ERR_RANDOM;
    }
    return LBPRE_OK;
}

static uint64_t random_u64(lbpre_rng *rng)
{
    uint8_t b[8];
    uint64_t value = 0;
    unsigned i;
    lbpre_rng_bytes(rng, b, sizeof(b));
    for (i = 0; i < 8; i++) value |= (uint64_t)b[i] << (8 * i);
    lbpre_secure_zero(b, sizeof(b));
    return value;
}

/* Exact rejection of the incomplete residue block in the 64-bit range.
 * This uses the full SHAKE word even when the modulus exceeds 32 bits. */
static uint64_t uniform_below(lbpre_rng *rng, uint64_t modulus)
{
    uint64_t x, boundary;
    assert(modulus != 0);
    boundary = (UINT64_C(0) - modulus) % modulus;
    do { x = random_u64(rng); } while (x < boundary);
    return x % modulus;
}

void lbpre_uniform_poly(uint64_t out[LBPRE_D], uint64_t q, lbpre_rng *rng)
{
    size_t i;
    assert(out != NULL && rng != NULL && q != 0);
    for (i = 0; i < LBPRE_D; i++) out[i] = uniform_below(rng, q);
}

void lbpre_ternary_poly(uint64_t out[LBPRE_D], uint64_t q, lbpre_rng *rng)
{
    size_t i = 0;
    assert(out != NULL && rng != NULL && q != 0);
    while (i < LBPRE_D) {
        uint8_t b;
        unsigned j;
        lbpre_rng_bytes(rng, &b, 1);
        if (b >= 243) continue;
        /* Five independent base-3 digits, without modulo bias. */
        for (j = 0; j < 5 && i < LBPRE_D; j++, i++) {
            unsigned digit = b % 3;
            b = (uint8_t)(b / 3);
            out[i] = digit == 0 ? q - 1 : (uint64_t)(digit - 1) % q;
        }
    }
}

/* Canonical signed reduction without negating INT64_MIN. */
static uint64_t signed_residue(int64_t value, uint64_t q)
{
    uint64_t magnitude = value < 0 ? UINT64_C(0) - (uint64_t)value
                                   : (uint64_t)value;
    magnitude %= q;
    return value < 0 && magnitude ? q - magnitude : magnitude;
}

static unsigned cbd_popcount64(uint64_t value)
{
    value -= (value >> 1) & UINT64_C(0x5555555555555555);
    value = (value & UINT64_C(0x3333333333333333)) +
            ((value >> 2) & UINT64_C(0x3333333333333333));
    value = (value + (value >> 4)) & UINT64_C(0x0f0f0f0f0f0f0f0f);
    return (unsigned)((value * UINT64_C(0x0101010101010101)) >> 56);
}

/* Count the next n independent bits from an explicit little-endian SHAKE
 * word stream. Branches and loop lengths depend only on the public eta.
 * A full-word chunk is special-cased to avoid every shift-by-64 operation. */
static unsigned cbd_count_bits(lbpre_rng *rng, unsigned n,
                               uint64_t *word, unsigned *remaining)
{
    unsigned count = 0;
    while (n != 0) {
        unsigned take;
        uint64_t chunk;
        if (*remaining == 0) {
            *word = random_u64(rng);
            *remaining = 64;
        }
        take = n < *remaining ? n : *remaining;
        if (take == 64) {
            chunk = *word;
            *word = 0;
        } else {
            chunk = *word & ((UINT64_C(1) << take) - 1);
            *word >>= take;
        }
        count += cbd_popcount64(chunk);
        *remaining -= take;
        n -= take;
    }
    return count;
}

/* eta<=32: extract one binomial half without generic chunk loops.
 * The retained word always has exactly remaining low-order valid bits. */
static inline uint64_t cbd_take_small(lbpre_rng *rng, unsigned n,
                                      uint64_t *word, unsigned *remaining)
{
    uint64_t mask=(UINT64_C(1)<<n)-1, chunk;
    if (*remaining >= n) {
        chunk=*word & mask;
        *word >>= n; *remaining -= n;
    } else {
        unsigned need=n-*remaining;
        uint64_t next=random_u64(rng);
        chunk=*word | ((next & ((UINT64_C(1)<<need)-1)) << *remaining);
        *word=next>>need; *remaining=64-need;
        lbpre_secure_zero(&next,sizeof(next));
    }
    return chunk;
}

/* No bit is reused between coefficients or between the two binomial halves.
 * D=256 makes the total draw exactly 64*eta bytes, ending on a word boundary.
 * Chunking removes the old eta<=10 and machine-word-width restrictions. */
void lbpre_cbd_poly(uint64_t out[LBPRE_D], uint64_t q, unsigned eta,
                    lbpre_rng *rng)
{
    uint64_t word = 0;
    unsigned remaining = 0;
    size_t i;
    assert(out != NULL && rng != NULL && q != 0 && eta >= 1);
    /* eta=1 consumes adjacent bit pairs from the same
     * little-endian words as the generic path. No modular division or
     * generic popcount/chunk dispatch is needed for the support {-1,0,1}.
     * Keep q=1 on the generic path; q>1 includes all uint64 moduli. */
    if (eta == 1 && q > 1) {
        for (i = 0; i < LBPRE_D; i += 32) {
            word = random_u64(rng);
            for (unsigned j = 0; j < 32; ++j) {
                uint64_t positive = word & ~(word >> 1) & UINT64_C(1);
                uint64_t negative = (word >> 1) & ~word & UINT64_C(1);
                out[i+j] = positive | ((q-1) & (UINT64_C(0)-negative));
                word >>= 2;
            }
        }
        lbpre_secure_zero(&word, sizeof(word));
        return;
    }
    /* For the selected terminal eta=12/16/22, halves fit at most 32 bits
     * and |a-b|<=eta<q. Preserve exact stream order, without a per-value mod. */
    if (eta <= 32 && q > eta) {
        for (i=0; i<LBPRE_D; ++i) {
            unsigned a=cbd_popcount64(cbd_take_small(rng,eta,&word,&remaining));
            unsigned b=cbd_popcount64(cbd_take_small(rng,eta,&word,&remaining));
            int64_t value=(int64_t)a-(int64_t)b;
            out[i]=value<0?q-(uint64_t)(-value):(uint64_t)value;
        }
        assert(remaining == 0);
        lbpre_secure_zero(&word,sizeof(word));
        return;
    }
    for (i = 0; i < LBPRE_D; ++i) {
        unsigned a = cbd_count_bits(rng, eta, &word, &remaining);
        unsigned b = cbd_count_bits(rng, eta, &word, &remaining);
        int64_t value = (int64_t)a - (int64_t)b;
        out[i] = signed_residue(value, q);
    }
    assert(remaining == 0);
    lbpre_secure_zero(&word, sizeof(word));
}

#include "sampling_openfhe.inc"

const char *lbpre_gaussian_backend(void)
{
    return "openfhe-cdf-karney-v1";
}

const char *lbpre_gaussian_context_id(void)
{
    /* Preserve the frozen protocol context: the display-name change must not
     * change the public matrix, serialized keys/ciphertexts, or pad inputs. */
    return "cic-cdf-karney-v1";
}

int lbpre_gaussian_is_approximate(void) { return 1; }
const char *lbpre_gaussian_target(void) { return "discrete-gaussian"; }
int lbpre_gaussian_has_certified_error_bound(void) { return 0; }
