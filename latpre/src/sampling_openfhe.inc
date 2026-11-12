/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
 * All rights reserved.
 * Author TPOC: contact@openfhe.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * C adaptation of OpenFHE v1.6.1 discretegaussiangenerator-impl.h, commit
 * b59e1f291965f14fbee5172cd83a20f5b856204f. Corrected CDF truncation constant;
 * explicit SHAKE RNG injection; defined 24/53-bit uniform grids; int64 guards.
 *
 * This variable-time implementation targets a DISCRETE Gaussian. Its floating
 * CDF/Karney implementation has NO certified MPFR statistical-distance bound.
 * No continuous-normal rounding, global PRNG, or cached spare samples are used.
 */
#if FLT_MANT_DIG != 24 || FLT_MAX_EXP != 128
#error "The OpenFHE-style sampler requires IEEE binary32 float"
#endif

#define OPENFHE_MAX_WIDTH 0x1p40
#define OPENFHE_SQRT_2PI 0x1.40d931ff62706p+1
#define OPENFHE_CDF_CUTOFF 12.00610553538285
#define OPENFHE_KARNEY_THRESHOLD 300.0

static int openfhe_decimal_syntax(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    unsigned digits = 0;
    if (!p || !*p) return 0;
    if (*p == '+' || *p == '-') ++p;
    while (*p >= '0' && *p <= '9') { ++p; ++digits; }
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') { ++p; ++digits; }
    }
    if (!digits) return 0;
    if (*p == 'e' || *p == 'E') {
        ++p; if (*p == '+' || *p == '-') ++p;
        digits = 0;
        while (*p >= '0' && *p <= '9') { ++p; ++digits; }
        if (!digits) return 0;
    }
    return *p == '\0';
}

/* One U53 consumes eight little-endian bytes, discarding the low eleven bits.
 * One U24 consumes four little-endian bytes, discarding the low eight bits.
 * Both grids include zero and exclude one. Integer draws use uniform_below,
 * whose eight-byte rejection-modulo mapping is unbiased for its bound. */
static double openfhe_uniform_double(lbpre_rng *rng)
{
    return (double)(random_u64(rng)>>11)*0x1p-53;
}

static float openfhe_uniform_float(lbpre_rng *rng)
{
    uint8_t bytes[4];
    uint32_t value;
    lbpre_rng_bytes(rng,bytes,sizeof(bytes));
    value = (uint32_t)bytes[0] | (uint32_t)bytes[1]<<8 |
            (uint32_t)bytes[2]<<16 | (uint32_t)bytes[3]<<24;
    lbpre_secure_zero(bytes,sizeof(bytes));
    return (float)(value>>8)*0x1p-24f;
}

lbpre_gaussian *lbpre_gaussian_new(const char *sigma)
{
    lbpre_gaussian *g;
    char *end;
    double width, stddev, variance;
    if (!openfhe_decimal_syntax(sigma) || fegetround() != FE_TONEAREST) return NULL;
    errno = 0; width = strtod(sigma,&end);
    if (errno || *end || !isfinite(width) || width <= 0 || width > OPENFHE_MAX_WIDTH)
        return NULL;
    stddev = width/OPENFHE_SQRT_2PI;
    variance = 2*stddev*stddev;
    if (!isfinite(stddev) || !isfinite(variance) || stddev <= 0 || variance <= 0)
        return NULL;
    g = calloc(1,sizeof(*g));
    if (!g) return NULL;
    g->stddev = stddev;
    if (stddev < OPENFHE_KARNEY_THRESHOLD) {
        double bound = ceil(stddev*OPENFHE_CDF_CUTOFF), sum = 0;
        size_t i;
        if (!isfinite(bound) || bound < 1 || bound > 3602) {
            free(g); return NULL;
        }
        g->cdf_size = (size_t)bound; g->radius = (uint64_t)g->cdf_size;
        g->cdf = calloc(g->cdf_size,sizeof(*g->cdf));
        if (!g->cdf) { free(g); return NULL; }
        for (i = 0; i < g->cdf_size; ++i) {
            double x = (double)(i+1);
            sum += exp(-(x*x/variance));
            g->cdf[i] = sum;
        }
        g->zero_probability = 1/(2*sum+1);
        for (i = 0; i < g->cdf_size; ++i) g->cdf[i] *= g->zero_probability;
    } else {
        /* Karney's ideal target has no finite tail cutoff. This is a checked
         * representation guard, not clipping or rejection of a normal tail. */
        g->radius = (uint64_t)INT64_MAX;
    }
    return g;
}

void lbpre_gaussian_free(lbpre_gaussian *g)
{
    if (!g) return;
    if (g->cdf) {
        lbpre_secure_zero(g->cdf,g->cdf_size*sizeof(*g->cdf)); free(g->cdf);
    }
    lbpre_secure_zero(g,sizeof(*g)); free(g);
}

/* Factored for white-box endpoint tests without a new public API. top53 is
 * the exact integer indexing the U53 grid. The final CDF bucket is completed
 * to cover any residual finite-grid mass at the normalized table endpoint.
 * In particular legal U53=0 never triggers OpenFHE's lower_bound(end) throw.
 * This is an explicit finite-precision endpoint convention; no TV certificate
 * or byte-identical C++ std::uniform_real_distribution stream is claimed. */
static int64_t openfhe_cdf_from_u53(const lbpre_gaussian *g, uint64_t top53)
{
    double seed, value;
    size_t lo = 0, hi = g->cdf_size;
    assert(top53 < (UINT64_C(1)<<53) && hi > 0);
    seed = (double)top53*0x1p-53-0.5;
    value = fabs(seed)-g->zero_probability/2;
    if (value <= 0) return 0;
    while (lo < hi) {
        size_t mid = lo+(hi-lo)/2;
        if (g->cdf[mid] < value) lo = mid+1;
        else hi = mid;
    }
    if (lo == g->cdf_size) lo = g->cdf_size-1;
    return seed > 0 ? (int64_t)(lo+1) : -(int64_t)(lo+1);
}

static int openfhe_h_double(lbpre_rng *rng)
{
    double a = openfhe_uniform_double(rng), b;
    if (!(a < 0.5)) return 1;
    for (;;) {
        b = openfhe_uniform_double(rng);
        if (!(b < a)) return 0;
        a = openfhe_uniform_double(rng);
        if (!(a < b)) return 1;
    }
}

static int openfhe_h(lbpre_rng *rng)
{
    float a = openfhe_uniform_float(rng), b;
    if (a > 0.5f) return 1;
    if (a == 0.5f) return openfhe_h_double(rng);
    for (;;) {
        b = openfhe_uniform_float(rng);
        if (b > a) return 0;
        if (b == a) return openfhe_h_double(rng);
        a = openfhe_uniform_float(rng);
        if (a > b) return 1;
        if (a == b) return openfhe_h_double(rng);
    }
}

static uint32_t openfhe_g(lbpre_rng *rng)
{
    uint32_t n = 0;
    while (openfhe_h(rng)) { if (n == UINT32_MAX) abort(); ++n; }
    return n;
}

static int openfhe_p(lbpre_rng *rng, uint64_t n)
{
    while (n) { if (!openfhe_h(rng)) return 0; --n; }
    return 1;
}

static int openfhe_b_double(lbpre_rng *rng, uint32_t k, double x)
{
    double y = x, z, r, m = 2.0*k+2;
    uint64_t n = 0;
    for (;;) {
        z = openfhe_uniform_double(rng);
        if (!(z < y)) break;
        r = openfhe_uniform_double(rng);
        if (!(r < (2.0*k+x)/m)) break;
        y = z;
        if (n == UINT64_MAX) abort();
        ++n;
    }
    return (n&1) == 0;
}

static int openfhe_b(lbpre_rng *rng, uint32_t k, double x)
{
    float y = (float)x, z, r, threshold;
    double m = 2.0*k+2;
    uint64_t n = 0;
    for (;;) {
        z = openfhe_uniform_float(rng);
        if (z > y) break;
        if (z == y) return openfhe_b_double(rng,k,x);
        r = openfhe_uniform_float(rng);
        threshold = (float)((2.0*k+x)/m);
        if (r > threshold) break;
        if (r == threshold) return openfhe_b_double(rng,k,x);
        y = z;
        if (n == UINT64_MAX) abort();
        ++n;
    }
    return (n&1) == 0;
}

static int64_t openfhe_karney(const lbpre_gaussian *g, lbpre_rng *rng)
{
    uint64_t j_bound = (uint64_t)ceil(g->stddev);
    for (;;) {
        uint32_t k = openfhe_g(rng);
        uint64_t trials = k > 1 ? (uint64_t)k*(k-1) : 0;
        uint64_t j, h, magnitude, i0;
        int sign, accepted = 1;
        double di0, x;
        if (!openfhe_p(rng,trials)) continue;
        sign = uniform_below(rng,2) ? 1 : -1;
        di0 = g->stddev*k;
        /* Avoid undefined float-to-int conversion and signed negation. A
         * mathematically unrepresentable proposal terminates fail-closed;
         * it is never silently clipped/resampled into a different tail law. */
        if (!isfinite(di0) || di0 < 0 || di0 >= 0x1p62) abort();
        i0 = (uint64_t)ceil(di0);
        j = uniform_below(rng,j_bound);
        x = ((double)i0-di0)/g->stddev+(double)j/g->stddev;
        if (!isfinite(x)) abort();
        if (!(x < 1) || (x == 0 && sign < 0 && k == 0)) continue;
        for (h = 0; h < (uint64_t)k+1; ++h) {
            if (!openfhe_b(rng,k,x)) { accepted = 0; break; }
        }
        if (!accepted) continue;
        if (i0 > (uint64_t)INT64_MAX-j) abort();
        magnitude = i0+j;
        return sign < 0 ? -(int64_t)magnitude : (int64_t)magnitude;
    }
}

int64_t lbpre_gaussian_sample(lbpre_gaussian *g, lbpre_rng *rng)
{
    assert(g && rng);
    if (fegetround() != FE_TONEAREST) abort();
    if (g->cdf) return openfhe_cdf_from_u53(g,random_u64(rng)>>11);
    return openfhe_karney(g,rng);
}

void lbpre_gaussian_poly(uint64_t out[LBPRE_D], uint64_t q,
                         lbpre_gaussian *g, lbpre_rng *rng)
{
    size_t i;
    assert(out && q && g && rng);
    for (i = 0; i < LBPRE_D; ++i) {
        int64_t x = lbpre_gaussian_sample(g,rng);
        out[i] = signed_residue(x, q);
    }
}

uint64_t lbpre_gaussian_radius(const lbpre_gaussian *g)
{
    return g ? g->radius : 0;
}
