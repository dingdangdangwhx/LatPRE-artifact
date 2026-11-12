#include "lbpre_dist.h"
#include "crt_ntt.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

static char error_message[256];

const char *lbpre_dist_error(void) { return error_message; }

static lbpre_dist *allocate_distribution(size_t length,
    unsigned long precision, int exact)
{
    lbpre_dist *d = calloc(1, sizeof(*d));
    if (!d) { snprintf(error_message, sizeof(error_message), "allocation failed"); return NULL; }
    d->numerator = calloc(length, sizeof(mpz_t));
    if (!d->numerator) { free(d); snprintf(error_message, sizeof(error_message), "allocation failed"); return NULL; }
    d->length = length;
    d->precision = precision;
    d->exact = exact;
    mpz_init_set_ui(d->denominator, 1);
    if (!exact) mpz_mul_2exp(d->denominator, d->denominator, precision);
    for (size_t i = 0; i < length; ++i) mpz_init(d->numerator[i]);
    return d;
}

void lbpre_dist_free(lbpre_dist *d)
{
    if (!d) return;
    for (size_t i = 0; i < d->length; ++i) mpz_clear(d->numerator[i]);
    free(d->numerator);
    mpz_clear(d->denominator);
    free(d);
}

lbpre_dist *lbpre_dist_point(unsigned long precision, int exact)
{
    lbpre_dist *d = allocate_distribution(1, precision, exact);
    if (d) mpz_set(d->numerator[0], d->denominator);
    return d;
}

static lbpre_dist *copy_distribution(const lbpre_dist *a)
{
    lbpre_dist *d = allocate_distribution(a->length, a->precision, a->exact);
    if (!d) return NULL;
    d->offset = a->offset;
    mpz_set(d->denominator, a->denominator);
    for (size_t i = 0; i < a->length; ++i)
        mpz_set(d->numerator[i], a->numerator[i]);
    return d;
}

lbpre_dist *lbpre_dist_uniform_weight(uint64_t weight, unsigned long beta,
    unsigned long precision, int exact, size_t max_support)
{
    if (weight == 0 || beta == 0) return lbpre_dist_point(precision, exact);
    if (beta > 10000 || weight > INT64_MAX / beta ||
        weight * beta > (max_support - 1) / 2) {
        snprintf(error_message, sizeof(error_message),
            "primitive weighted support exceeds max-support=%zu", max_support);
        return NULL;
    }
    size_t radius = (size_t)weight * beta;
    lbpre_dist *d = allocate_distribution(2 * radius + 1, precision, exact);
    if (!d) return NULL;
    d->offset = -(int64_t) radius;
    mpz_t value;
    mpz_init(value);
    if (exact) {
        mpz_set_ui(d->denominator, 2 * beta + 1);
        mpz_set_ui(value, 1);
    } else mpz_fdiv_q_ui(value, d->denominator, 2 * beta + 1);
    for (unsigned long j = 0; j <= 2 * beta; ++j)
        mpz_set(d->numerator[j * (size_t)weight], value);
    mpz_clear(value);
    return d;
}

static void trim_zero_ends(lbpre_dist *d)
{
    size_t lo = 0, hi = d->length;
    while (lo < hi && mpz_sgn(d->numerator[lo]) == 0) ++lo;
    while (hi > lo && mpz_sgn(d->numerator[hi - 1]) == 0) --hi;
    if (lo == hi) { lo = 0; hi = 1; d->offset = 0; }
    size_t new_length = hi - lo;
    for (size_t i = 0; i < new_length; ++i)
        if (lo) mpz_set(d->numerator[i], d->numerator[i + lo]);
    for (size_t i = new_length; i < d->length; ++i)
        mpz_clear(d->numerator[i]);
    if (lo) d->offset += (int64_t)lo;
    d->length = new_length;
}

lbpre_dist *lbpre_dist_convolve(const lbpre_dist *a, const lbpre_dist *b,
    size_t max_support)
{
    if (a->exact != b->exact || a->precision != b->precision) {
        snprintf(error_message, sizeof(error_message), "incompatible PMF modes");
        return NULL;
    }
    if (a->length > max_support || b->length > max_support ||
        a->length > max_support - b->length + 1) {
        snprintf(error_message, sizeof(error_message),
            "convolution support %zu+%zu-1 exceeds max-support=%zu",
            a->length, b->length, max_support);
        return NULL;
    }
    if ((b->offset < 0 && a->offset < INT64_MIN - b->offset) ||
        (b->offset > 0 && a->offset > INT64_MAX - b->offset)) {
        snprintf(error_message, sizeof(error_message), "coordinate overflow");
        return NULL;
    }
    mpz_t product_denominator;
    mpz_init(product_denominator);
    mpz_mul(product_denominator, a->denominator, b->denominator);
    size_t bits = mpz_sizeinbase(product_denominator, 2) + 1;
    /* Existing CRT has 32 approximately 64-bit primes. Keep a conservative
       explicit guard instead of permitting its unguarded prime-base loop. */
    if (bits > 1900) {
        snprintf(error_message, sizeof(error_message),
            "exact numerator product requires %zu bits; CRT safety cap is 1900", bits);
        mpz_clear(product_denominator);
        return NULL;
    }
    lbpre_dist *d = allocate_distribution(a->length + b->length - 1,
        a->precision, a->exact);
    if (!d) { mpz_clear(product_denominator); return NULL; }
    d->offset = a->offset + b->offset;
    if (a->exact) mpz_set(d->denominator, product_denominator);
    crt_ntt_convol(d->numerator, a->numerator, a->length,
        b->numerator, b->length, bits);
    if (!a->exact) {
        for (size_t i = 0; i < d->length; ++i)
            mpz_fdiv_q_2exp(d->numerator[i], d->numerator[i], a->precision);
    }
    mpz_clear(product_denominator);
    trim_zero_ends(d);
    return d;
}

lbpre_dist *lbpre_dist_power(const lbpre_dist *base, uint64_t count,
    size_t max_support)
{
    lbpre_dist *result = lbpre_dist_point(base->precision, base->exact);
    lbpre_dist *power = copy_distribution(base);
    if (!result || !power) {
        lbpre_dist_free(result); lbpre_dist_free(power); return NULL;
    }
    while (count) {
        if (count & 1) {
            lbpre_dist *next = lbpre_dist_convolve(result, power, max_support);
            lbpre_dist_free(result);
            result = next;
            if (!result) { lbpre_dist_free(power); return NULL; }
        }
        count >>= 1;
        if (count) {
            lbpre_dist *next = lbpre_dist_convolve(power, power, max_support);
            lbpre_dist_free(power);
            power = next;
            if (!power) { lbpre_dist_free(result); return NULL; }
        }
    }
    lbpre_dist_free(power);
    return result;
}

void lbpre_dist_mass_bounds(mpfr_t lower, mpfr_t upper,
    mpfr_t deficit_upper, const lbpre_dist *d)
{
    mpz_t sum, deficit;
    mpz_inits(sum, deficit, NULL);
    for (size_t i = 0; i < d->length; ++i) mpz_add(sum, sum, d->numerator[i]);
    mpz_sub(deficit, d->denominator, sum);
    mpfr_set_z(lower, sum, MPFR_RNDD);
    mpfr_div_z(lower, lower, d->denominator, MPFR_RNDD);
    mpfr_set_z(upper, sum, MPFR_RNDU);
    mpfr_div_z(upper, upper, d->denominator, MPFR_RNDU);
    mpfr_set_z(deficit_upper, deficit, MPFR_RNDU);
    mpfr_div_z(deficit_upper, deficit_upper, d->denominator, MPFR_RNDU);
    mpz_clears(sum, deficit, NULL);
}
