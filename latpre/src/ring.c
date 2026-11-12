/* Exact arithmetic in Z_q[X]/(X^256+1), for odd prime q < 2^62.
 *
 * The transformed representation is canonical Montgomery (R=2^64).
 * No floating-point arithmetic or approximate reduction is used here.
 * Montgomery products use scalar uint128 operations.
 */
#include "lbpre_ring.h"

#include <string.h>


typedef __uint128_t u128;

static uint64_t add_mod(uint64_t a, uint64_t b, uint64_t q)
{
    uint64_t x = a + b;
    return x - (q & (uint64_t)-(x >= q));
}

static uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t q)
{
    uint64_t x = a + q - b;
    return x - (q & (uint64_t)-(x >= q));
}

static uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t q)
{
    return (uint64_t)(((u128)a * b) % q);
}

static uint64_t pow_mod(uint64_t a, uint64_t e, uint64_t q)
{
    uint64_t x = 1;
    while (e) {
        if (e & 1) x = mul_mod(x, a, q);
        a = mul_mod(a, a, q);
        e >>= 1;
    }
    return x;
}

/* Deterministic Miller--Rabin bases valid for every uint64 integer. */
static int prime_u64(uint64_t q)
{
    static const uint64_t small[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    static const uint64_t bases[] = {2,325,9375,28178,450775,9780504,1795265022};
    uint64_t odd;
    unsigned shifts = 0;
    size_t i;
    if (q < 2) return 0;
    for (i = 0; i < sizeof(small)/sizeof(small[0]); ++i) {
        if (q == small[i]) return 1;
        if (q % small[i] == 0) return 0;
    }
    odd = q - 1;
    while (!(odd & 1)) { odd >>= 1; ++shifts; }
    for (i = 0; i < sizeof(bases)/sizeof(bases[0]); ++i) {
        uint64_t a = bases[i] % q;
        uint64_t x;
        unsigned j;
        if (!a) continue;
        x = pow_mod(a, odd, q);
        if (x == 1 || x == q-1) continue;
        for (j = 1; j < shifts; ++j) {
            x = mul_mod(x, x, q);
            if (x == q-1) break;
        }
        if (j == shifts) return 0;
    }
    return 1;
}

static uint64_t montgomery(const lbpre_ring *r, uint64_t a, uint64_t b)
{
    u128 t = (u128)a*b;
    uint64_t m = (uint64_t)t*r->qinv;
    uint64_t x = (uint64_t)((t+(u128)m*r->q) >> 64);
    /* a,b<q<2^62: t<2^124 and m*q<2^126, hence their sum
     * fits uint128. Montgomery reduction gives x<2q<2^63. */
    return x - (r->q & (uint64_t)-(x >= r->q));
}


static void bit_reverse(uint64_t *a)
{
    unsigned i, j = 0;
    for (i = 1; i < LBPRE_D; ++i) {
        unsigned bit = LBPRE_D >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            uint64_t t = a[i]; a[i] = a[j]; a[j] = t;
        }
    }
}

static void cyclic(const lbpre_ring *r, uint64_t *a, const uint64_t *table)
{
    size_t length;
    bit_reverse(a);
    for (length = 2; length <= LBPRE_D; length <<= 1) {
        size_t j, start, half = length/2;
        const uint64_t *powers = table + half - 1;
        for (start = 0; start < LBPRE_D; start += length) {
            for (j = 0; j < half; ++j) {
                uint64_t u = a[start+j];
                uint64_t v = montgomery(r, a[start+j+half], powers[j]);
                a[start+j] = add_mod(u, v, r->q);
                a[start+j+half] = sub_mod(u, v, r->q);
            }
        }
    }
}

int lbpre_ring_init(lbpre_ring *r, uint64_t q)
{
    uint64_t inverse = 1, root, root_inverse, twist = 1, untwist = 1;
    unsigned i;
    if (!r) return LBPRE_ERR_ARGUMENT;
    memset(r, 0, sizeof(*r));
    if (q < 3 || q >= (UINT64_C(1)<<62) || q % (2*LBPRE_D) != 1 || !prime_u64(q))
        return LBPRE_ERR_ARGUMENT;
    r->q = q;
    for (i = 0; i < 6; ++i) inverse *= 2-q*inverse;
    r->qinv = 0-inverse;
    r->one = (uint64_t)(((u128)1<<64) % q);
    r->r2 = mul_mod(r->one, r->one, q);
    for (root = 2; root < q; ++root) {
        r->psi = pow_mod(root, (q-1)/(2*LBPRE_D), q);
        if (pow_mod(r->psi, LBPRE_D, q) == q-1) break;
    }
    if (root == q) { memset(r, 0, sizeof(*r)); return LBPRE_ERR_ARGUMENT; }
    r->omega = mul_mod(r->psi, r->psi, q);
    r->ninv = pow_mod(LBPRE_D, q-2, q);
    root_inverse = pow_mod(r->psi, q-2, q);
    for (i = 0; i < LBPRE_D; ++i) {
        /* Fused normal-to-Montgomery twist and inverse normal conversion. */
        r->twist[i] = mul_mod(twist, r->r2, q);
        r->untwist[i] = mul_mod(untwist, r->ninv, q);
        twist = mul_mod(twist, r->psi, q);
        untwist = mul_mod(untwist, root_inverse, q);
    }
    root_inverse = pow_mod(r->omega, q-2, q);
    for (i = 0; i < 8; ++i) {
        unsigned length = 2u << i;
        r->roots[i] = mul_mod(pow_mod(r->omega, LBPRE_D/length, q),r->one,q);
        r->invroots[i] = mul_mod(pow_mod(root_inverse, LBPRE_D/length, q),r->one,q);
        {
            unsigned half = length/2, offset = half-1, j;
            r->powers[offset] = r->one;
            r->invpowers[offset] = r->one;
            for (j = 1; j < half; ++j) {
                r->powers[offset+j] = montgomery(r,r->powers[offset+j-1],r->roots[i]);
                r->invpowers[offset+j] = montgomery(r,r->invpowers[offset+j-1],r->invroots[i]);
            }
        }
    }
    return LBPRE_OK;
}

void lbpre_ntt(const lbpre_ring *r, uint64_t a[LBPRE_D])
{
    size_t i;
    for (i = 0; i < LBPRE_D; ++i) a[i] = montgomery(r,a[i],r->twist[i]);
    cyclic(r,a,r->powers);
}

void lbpre_intt(const lbpre_ring *r, uint64_t a[LBPRE_D])
{
    size_t i;
    cyclic(r,a,r->invpowers);
    for (i = 0; i < LBPRE_D; ++i) a[i] = montgomery(r,a[i],r->untwist[i]);
}

void lbpre_pointwise(const lbpre_ring *r, uint64_t out[LBPRE_D],
                     const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D])
{
    size_t i;
    for (i = 0; i < LBPRE_D; ++i) out[i] = montgomery(r,a[i],b[i]);
}

void lbpre_pointwise_acc(const lbpre_ring *r, uint64_t out[LBPRE_D],
                         const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D])
{
    size_t i;
    for (i = 0; i < LBPRE_D; ++i)
        out[i] = add_mod(out[i],montgomery(r,a[i],b[i]),r->q);
}

void lbpre_poly_add(const lbpre_ring *r, uint64_t out[LBPRE_D],
                    const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D])
{
    size_t i;
    for (i = 0; i < LBPRE_D; ++i) out[i] = add_mod(a[i],b[i],r->q);
}

void lbpre_poly_sub(const lbpre_ring *r, uint64_t out[LBPRE_D],
                    const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D])
{
    size_t i;
    for (i = 0; i < LBPRE_D; ++i) out[i] = sub_mod(a[i],b[i],r->q);
}

void lbpre_poly_mul(const lbpre_ring *r, uint64_t out[LBPRE_D],
                    const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D])
{
    uint64_t x[LBPRE_D], y[LBPRE_D];
    memcpy(x,a,sizeof(x)); memcpy(y,b,sizeof(y));
    lbpre_ntt(r,x); lbpre_ntt(r,y);
    lbpre_pointwise(r,x,x,y); lbpre_intt(r,x);
    memcpy(out,x,sizeof(x));
}

void lbpre_poly_mul_schoolbook(const lbpre_ring *r, uint64_t out[LBPRE_D],
                               const uint64_t a[LBPRE_D], const uint64_t b[LBPRE_D])
{
    uint64_t c[LBPRE_D] = {0};
    size_t i, j;
    /* Independent division-based oracle: no NTT or Montgomery helper. */
    for (i = 0; i < LBPRE_D; ++i) {
        for (j = 0; j < LBPRE_D; ++j) {
            uint64_t t = (uint64_t)(((u128)a[i]*b[j]) % r->q);
            size_t target = i+j;
            if (target < LBPRE_D) c[target] = (c[target]+t) % r->q;
            else {
                target -= LBPRE_D;
                c[target] = (c[target]+r->q-t) % r->q;
            }
        }
    }
    memcpy(out,c,sizeof(c));
}

const char *lbpre_ring_backend(void)
{
    return "scalar uint128 Montgomery NTT";
}
