#ifndef LBPRE_DIST_H
#define LBPRE_DIST_H

#include <gmp.h>
#include <mpfr.h>
#include <stddef.h>
#include <stdint.h>

/* Nonnegative lower sub-PMF: p_i >= numerator[i]/denominator.
 * Fixed precision mode always has denominator 2^precision and rounds DOWN
 * after multiplication. Exact mode preserves the rational denominator.
 * No normalization or unaccounted tail pruning is performed. */
typedef struct {
    int64_t offset;
    size_t length;
    unsigned long precision;
    int exact;
    mpz_t denominator;
    mpz_t *numerator;
} lbpre_dist;

const char *lbpre_dist_error(void);
void lbpre_dist_free(lbpre_dist *distribution);
lbpre_dist *lbpre_dist_point(unsigned long precision, int exact);
lbpre_dist *lbpre_dist_uniform_weight(uint64_t weight, unsigned long beta,
    unsigned long precision, int exact, size_t max_support);
lbpre_dist *lbpre_dist_convolve(const lbpre_dist *a, const lbpre_dist *b,
    size_t max_support);
lbpre_dist *lbpre_dist_power(const lbpre_dist *base, uint64_t count,
    size_t max_support);
void lbpre_dist_mass_bounds(mpfr_t lower, mpfr_t upper,
    mpfr_t deficit_upper, const lbpre_dist *distribution);

#endif
