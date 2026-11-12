#ifndef LBPRE_RING_H
#define LBPRE_RING_H
#include "lbpre.h"
typedef struct {
    uint64_t q, qinv, r2, one, psi, omega, ninv;
    uint64_t twist[LBPRE_D], untwist[LBPRE_D];
    uint64_t roots[8], invroots[8];
    /* Exact public stage twiddles, precomputed once at setup. */
    uint64_t powers[LBPRE_D-1], invpowers[LBPRE_D-1];
} lbpre_ring;
/* Initialization requires a prime 3 <= q < 2^62 with q = 1 mod 512.
 * All arithmetic inputs must be canonical residues in [0,q).
 * Forward input and inverse output are canonical normal residues;
 * forward output / inverse input are twisted cyclic NTT in Montgomery representation.
 * Forward and inverse operate in-place. Products/adds accept aliasing. */
int lbpre_ring_init(lbpre_ring *r, uint64_t q);
void lbpre_ntt(const lbpre_ring *r, uint64_t a[LBPRE_D]);
void lbpre_intt(const lbpre_ring *r, uint64_t a[LBPRE_D]);
void lbpre_pointwise(const lbpre_ring *r, uint64_t out[LBPRE_D],
                     const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D]);
void lbpre_pointwise_acc(const lbpre_ring *r, uint64_t out[LBPRE_D],
                         const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D]);
void lbpre_poly_add(const lbpre_ring *r, uint64_t out[LBPRE_D],
                    const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D]);
void lbpre_poly_sub(const lbpre_ring *r, uint64_t out[LBPRE_D],
                    const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D]);
void lbpre_poly_mul(const lbpre_ring *r, uint64_t out[LBPRE_D],
                    const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D]);
void lbpre_poly_mul_schoolbook(const lbpre_ring *r, uint64_t out[LBPRE_D],
                               const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D]);
const char *lbpre_ring_backend(void);
#endif
