#include "lbpre.h"
#include "lbpre_ring.h"
#include <mpfr.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Independently transcribed frozen L/M/H constants and wire-size expectations.
 * Exact decimals are standard-deviation proxies; MPFR checks width conversion. */
typedef struct {
    const char *name;
    unsigned logQ, logM, k, ell, bits, base, length, sv, ru, rv;
    uint64_t q;
    unsigned terminal_eta;
    const char *source_std, *pad_std;
    size_t pk_bytes, sk_bytes, src_bytes, re_bytes, rk_bytes;
} expected_params;
static const expected_params EXPECTED[] = {
    {"L", 20, 10, 4, 5, 28, 643, 3, 7, 13, 5, UINT64_C(265753601), 12,
     "14.753136145925044", "1951876.069544714", 8960, 7168, 3808, 1824, 53792},
    {"M", 30, 15, 5, 6, 35, 3241, 3, 6, 13, 5, UINT64_C(34016143361), 16,
     "24.609035968580166", "337219778.8550402", 13440, 11200, 5792, 2240, 100832},
    {"H", 40, 20, 6, 7, 42, 2086641, 2, 8, 14, 7, UINT64_C(4354066046977), 22,
     "35.7644675891657", "60407946156.77607", 18816, 16128, 8320, 2912, 112928},
};
static unsigned current_logQ;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL logQ=%u %s:%d: %s\n", current_logQ, __FILE__, __LINE__, #condition); \
    exit(EXIT_FAILURE); } } while (0)

static void seed_for(uint8_t seed[LBPRE_SEED_BYTES], unsigned domain) {
    size_t i;
    for (i = 0; i < LBPRE_SEED_BYTES; i++)
        seed[i] = (uint8_t)(17U * i + 29U * domain + current_logQ);
}

static lbpre_rng *new_rng(unsigned domain) {
    uint8_t seed[LBPRE_SEED_BYTES];
    lbpre_rng *rng;
    seed_for(seed, domain);
    rng = lbpre_rng_new(seed);
    CHECK(rng != NULL);
    return rng;
}

static uint8_t *allocate(size_t len) {
    uint8_t *result = malloc(len);
    CHECK(result != NULL);
    memset(result, 0xa5, len);
    return result;
}

static uint64_t coefficient(const uint8_t *wire, size_t index, unsigned bits) {
    uint64_t value = 0;
    unsigned j;
    for (j = 0; j < bits; j++) {
        size_t bit = index * bits + j;
        value |= (uint64_t)((wire[bit / 8] >> (bit % 8)) & 1U) << j;
    }
    return value;
}

static void set_coefficient(uint8_t *wire, size_t index, unsigned bits, uint64_t value) {
    unsigned j;
    for (j = 0; j < bits; j++) {
        size_t bit = index * bits + j;
        uint8_t mask = (uint8_t)(1U << (bit % 8));
        wire[bit / 8] = (uint8_t)((wire[bit / 8] & (uint8_t)~mask)
            | (((value >> j) & 1U) ? mask : 0U));
    }
}

static void canonical(const uint8_t *wire, size_t count, unsigned bits, uint64_t q) {
    size_t i;
    for (i = 0; i < count; i++) CHECK(coefficient(wire, i, bits) < q);
}

static void fill_message(uint8_t message[LBPRE_MESSAGE_BYTES], unsigned domain) {
    size_t i;
    for (i = 0; i < LBPRE_MESSAGE_BYTES; i++)
        message[i] = (uint8_t)(i * 37U + domain * 11U + current_logQ);
}

static void check_terminal(const lbpre_ctx *ctx, const uint8_t *ct, size_t ctlen,
                           const uint8_t *sk, size_t sklen,
                           const uint8_t expected[LBPRE_MESSAGE_BYTES]) {
    uint8_t message[LBPRE_MESSAGE_BYTES];
    CHECK(lbpre_decrypt_terminal(ctx, message, ct, ctlen, sk, sklen) == LBPRE_OK);
    CHECK(memcmp(message, expected, LBPRE_MESSAGE_BYTES) == 0);
}

/* Verify generator width = frozen decimal std * sqrt(2*pi), without
 * comparing to binary64 widths recorded only for display in the JSON. */
static void check_width(const char *width, const char *stddev) {
    mpfr_t expected, got, error, tolerance;
    mpfr_inits2(512, expected, got, error, tolerance, (mpfr_ptr)0);
    CHECK(mpfr_set_str(got,width,10,MPFR_RNDN) == 0);
    mpfr_const_pi(expected,MPFR_RNDN);
    mpfr_mul_ui(expected,expected,2,MPFR_RNDN);
    mpfr_sqrt(expected,expected,MPFR_RNDN);
    CHECK(mpfr_set_str(error,stddev,10,MPFR_RNDN) == 0);
    mpfr_mul(expected,expected,error,MPFR_RNDN);
    mpfr_sub(error,expected,got,MPFR_RNDN);
    mpfr_abs(error,error,MPFR_RNDN);
    mpfr_mul_2si(tolerance,expected,-475,MPFR_RNDN);
    CHECK(mpfr_cmp(error,tolerance) < 0);
    mpfr_clears(expected,got,error,tolerance,(mpfr_ptr)0);
}

static void check_params(const expected_params *e, const lbpre_params *p) {
    size_t polynomial;
    CHECK(p != NULL);
    CHECK(strcmp(p->name,e->name) == 0 && p->logM == e->logM);
    CHECK(lbpre_params_named(e->name) == p);
    CHECK(p->logQ == e->logQ && p->k == e->k && p->ell == e->ell);
    CHECK(p->q == e->q && p->q_bits == e->bits);
    CHECK(p->base == e->base && p->length == e->length);
    CHECK(p->source_v_bits == e->sv && p->re_u_bits == e->ru && p->re_v_bits == e->rv);
    CHECK(p->base % 2 == 1 && p->base >= 3);
    polynomial = (size_t)LBPRE_D * e->bits / 8;
    CHECK(lbpre_public_key_bytes(p) == 2 * e->ell * polynomial);
    CHECK(lbpre_secret_key_bytes(p) == 2 * e->k * polynomial);
    CHECK(lbpre_public_matrix_bytes(p) == e->k * e->ell * polynomial);
    CHECK(lbpre_source_bytes(p) == (size_t)LBPRE_D * (e->k * e->bits + e->sv) / 8);
    CHECK(lbpre_terminal_bytes(p) == (size_t)LBPRE_D * (e->k * e->ru + e->rv) / 8);
    CHECK(lbpre_rekey_body_bytes(p) == (size_t)(e->k + 1) * e->k * e->length * polynomial);
    CHECK(lbpre_rekey_bytes(p) == lbpre_rekey_body_bytes(p) + LBPRE_SEED_BYTES);
    CHECK(lbpre_public_key_bytes(p) == e->pk_bytes);
    CHECK(lbpre_secret_key_bytes(p) == e->sk_bytes);
    CHECK(lbpre_source_bytes(p) == e->src_bytes);
    CHECK(lbpre_terminal_bytes(p) == e->re_bytes);
    CHECK(lbpre_rekey_bytes(p) == e->rk_bytes);
    CHECK(p->source_eta == 1 && p->internal_eta == 1);
    CHECK(p->terminal_eta == e->terminal_eta);
    CHECK(p->sigma_source != NULL && p->sigma_terminal == NULL && p->sigma_pad != NULL);
    CHECK(strcmp(p->source_std, e->source_std) == 0);
    CHECK(strcmp(p->pad_std, e->pad_std) == 0);
    check_width(p->sigma_source,e->source_std);
    check_width(p->sigma_pad,e->pad_std);
}

/* Recover terminal E from the serialized A, PK and SK with an independent
 * schoolbook product. Both terminal secret and error must have CBD support. */
static void check_terminal_key(const lbpre_params *p, const uint8_t *matrix,
                               const uint8_t *pk, const uint8_t *sk) {
    lbpre_ring ring;
    uint64_t a[LBPRE_D], sec[LBPRE_D], product[LBPRE_D], acc[LBPRE_D];
    unsigned row,col,i;
    CHECK(lbpre_ring_init(&ring,p->q) == LBPRE_OK);
    for (col = 0; col < p->k; ++col) {
        for (i = 0; i < LBPRE_D; ++i) {
            uint64_t x = coefficient(sk,((size_t)p->k+col)*LBPRE_D+i,p->q_bits);
            CHECK(x <= p->terminal_eta || x >= p->q-p->terminal_eta);
        }
    }
    for (row = 0; row < p->ell; ++row) {
        memset(acc,0,sizeof(acc));
        for (col = 0; col < p->k; ++col) {
            for (i = 0; i < LBPRE_D; ++i) {
                a[i] = coefficient(matrix,((size_t)row*p->k+col)*LBPRE_D+i,p->q_bits);
                sec[i] = coefficient(sk,((size_t)p->k+col)*LBPRE_D+i,p->q_bits);
            }
            lbpre_poly_mul_schoolbook(&ring,product,a,sec);
            for (i = 0; i < LBPRE_D; ++i) acc[i] = (acc[i]+product[i])%p->q;
        }
        for (i = 0; i < LBPRE_D; ++i) {
            uint64_t x = coefficient(pk,((size_t)p->ell+row)*LBPRE_D+i,p->q_bits);
            x = (x+p->q-acc[i])%p->q;
            CHECK(x <= p->terminal_eta || x >= p->q-p->terminal_eta);
        }
    }
}

static void test_one(const expected_params *e) {
    const lbpre_params *p;
    lbpre_ctx *ctx, *same_ctx;
    lbpre_rng *rng, *rng1, *rng2;
    lbpre_proxy *proxy, *replica_proxy, *variant_proxy, *cached_pad_proxy;
    lbpre_rekey_cache *ab, *ac, *aa, *ab_variant;
    uint8_t matrix_seed[LBPRE_SEED_BYTES];
    uint8_t message[LBPRE_MESSAGE_BYTES], other_message[LBPRE_MESSAGE_BYTES], decoded[LBPRE_MESSAGE_BYTES];
    uint8_t *pk_a, *pk_b, *pk_c, *sk_a, *sk_b, *sk_c;
    uint8_t *src, *unregistered, *re1, *re2, *re3, *rk_ab, *rk_ac, *rk_aa, *rk_ab_variant, *bad, *matrix, *matrix2;
    size_t pklen, sklen, srclen, relen, rklen, alen, maxlen;
    current_logQ = e->logQ;
    p = lbpre_params_get(e->logQ);
    check_params(e, p);
    seed_for(matrix_seed, 1);
    ctx = lbpre_setup(e->logQ, matrix_seed);
    CHECK(ctx != NULL);
    check_params(e, lbpre_ctx_params(ctx));
    pklen = lbpre_public_key_bytes(p); sklen = lbpre_secret_key_bytes(p);
    srclen = lbpre_source_bytes(p); relen = lbpre_terminal_bytes(p);
    rklen = lbpre_rekey_bytes(p); alen = lbpre_public_matrix_bytes(p);
    CHECK(srclen != relen);
    pk_a = allocate(pklen); pk_b = allocate(pklen); pk_c = allocate(pklen);
    sk_a = allocate(sklen); sk_b = allocate(sklen); sk_c = allocate(sklen);
    src = allocate(srclen); unregistered = allocate(srclen);
    re1 = allocate(relen); re2 = allocate(relen); re3 = allocate(relen);
    rk_ab = allocate(rklen); rk_ac = allocate(rklen); rk_aa = allocate(rklen);
    rk_ab_variant = allocate(rklen);
    matrix = allocate(alen); matrix2 = allocate(alen);
    maxlen = rklen > alen ? rklen : alen;
    if (pklen > maxlen) maxlen = pklen;
    if (sklen > maxlen) maxlen = sklen;
    if (srclen > maxlen) maxlen = srclen;
    bad = allocate(maxlen + 1);
    rng = new_rng(2);
    CHECK(lbpre_export_matrix(ctx, matrix, alen) == LBPRE_OK);
    canonical(matrix, (size_t)p->k * p->ell * LBPRE_D, p->q_bits, p->q);
    CHECK(lbpre_export_matrix(ctx, matrix, alen - 1) != LBPRE_OK);
    same_ctx = lbpre_setup(e->logQ, matrix_seed);
    CHECK(same_ctx != NULL);
    CHECK(lbpre_export_matrix(same_ctx, matrix2, alen) == LBPRE_OK);
    CHECK(memcmp(matrix, matrix2, alen) == 0);
    lbpre_ctx_free(same_ctx);
    CHECK(lbpre_keygen(ctx, pk_a, pklen, sk_a, sklen, rng) == LBPRE_OK);
    CHECK(lbpre_keygen(ctx, pk_b, pklen, sk_b, sklen, rng) == LBPRE_OK);
    CHECK(lbpre_keygen(ctx, pk_c, pklen, sk_c, sklen, rng) == LBPRE_OK);
    canonical(pk_a, (size_t)2 * p->ell * LBPRE_D, p->q_bits, p->q);
    canonical(sk_a, (size_t)2 * p->k * LBPRE_D, p->q_bits, p->q);
    CHECK(memcmp(pk_a, pk_b, pklen) != 0 && memcmp(sk_a, sk_b, sklen) != 0);
    check_terminal_key(p,matrix,pk_a,sk_a);
    check_terminal_key(p,matrix,pk_b,sk_b);
    check_terminal_key(p,matrix,pk_c,sk_c);
    rng1 = new_rng(2);
    CHECK(lbpre_keygen(ctx,bad,pklen,sk_c,sklen,rng1) == LBPRE_OK);
    CHECK(memcmp(pk_a,bad,pklen) == 0 && memcmp(sk_a,sk_c,sklen) == 0);
    lbpre_rng_free(rng1);
    /* Restore C's original independently generated key after replay. */
    CHECK(lbpre_keygen(ctx,pk_c,pklen,sk_c,sklen,rng) == LBPRE_OK);
    fill_message(message, 3); fill_message(other_message, 4);
    CHECK(lbpre_encrypt(ctx, src, srclen, pk_a, pklen, message, rng) == LBPRE_OK);
    CHECK(lbpre_decrypt_source(ctx, decoded, src, srclen, sk_a, sklen) == LBPRE_OK);
    CHECK(memcmp(decoded, message, sizeof(message)) == 0);
    canonical(src, (size_t)p->k * LBPRE_D, p->q_bits, p->q);
    CHECK(lbpre_encrypt(ctx, unregistered, srclen, pk_a, pklen, other_message, rng) == LBPRE_OK);
    CHECK(memcmp(src, unregistered, srclen) != 0);
    CHECK(lbpre_rekeygen(ctx, rk_ab, rklen, sk_a, sklen, pk_b, pklen, rng) == LBPRE_OK);
    CHECK(lbpre_rekeygen(ctx, rk_ac, rklen, sk_a, sklen, pk_c, pklen, rng) == LBPRE_OK);
    CHECK(lbpre_rekeygen(ctx, rk_aa, rklen, sk_a, sklen, pk_a, pklen, rng) == LBPRE_OK);
    canonical(rk_ab, (size_t)(p->k + 1) * p->k * p->length * LBPRE_D, p->q_bits, p->q);
    ab = lbpre_rekey_prepare(ctx, rk_ab, rklen, pk_a, pklen, pk_b, pklen);
    ac = lbpre_rekey_prepare(ctx, rk_ac, rklen, pk_a, pklen, pk_c, pklen);
    aa = lbpre_rekey_prepare(ctx, rk_aa, rklen, pk_a, pklen, pk_a, pklen);
    CHECK(ab != NULL && ac != NULL && aa != NULL);
    CHECK(lbpre_rekey_cache_memory_bytes(ab) > 0);
    /* Hold the matrix fixed and vary only the independent rekey seed. */
    memcpy(rk_ab_variant,rk_ab,rklen);
    memset(rk_ab_variant+lbpre_rekey_body_bytes(p),0xff,LBPRE_SEED_BYTES);
    CHECK(memcmp(rk_ab_variant+lbpre_rekey_body_bytes(p),
                 rk_ab+lbpre_rekey_body_bytes(p),LBPRE_SEED_BYTES) != 0);
    ab_variant = lbpre_rekey_prepare(ctx,rk_ab_variant,rklen,pk_a,pklen,pk_b,pklen);
    CHECK(ab_variant != NULL);
    proxy = lbpre_proxy_new(ctx);
    replica_proxy = lbpre_proxy_new(ctx);
    variant_proxy = lbpre_proxy_new(ctx);
    CHECK(proxy != NULL && replica_proxy != NULL && variant_proxy != NULL);
    CHECK(lbpre_registered_records(proxy) == 0);
    CHECK(lbpre_registered_rekeys(proxy) == 0);
    CHECK(lbpre_register_rekey(proxy,ab) == LBPRE_OK);
    CHECK(lbpre_register_rekey(proxy,ab) == LBPRE_OK);
    CHECK(lbpre_registered_rekeys(proxy) == 1);
    CHECK(lbpre_register(proxy, pk_a, pklen, src, srclen) == LBPRE_OK);
    CHECK(lbpre_register(proxy, pk_a, pklen, src, srclen) == LBPRE_OK);
    CHECK(lbpre_registered_records(proxy) == 1);
    CHECK(lbpre_proxy_memory_bytes(proxy) > 0);
    CHECK(lbpre_reencrypt(proxy, re1, relen, ab, pk_a, pklen, pk_b, pklen,
                         unregistered, srclen, rng) == LBPRE_ERR_UNREGISTERED);
    CHECK(lbpre_reencrypt(proxy, re1, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng) == LBPRE_OK);
    CHECK(lbpre_reencrypt(proxy, re2, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng) == LBPRE_OK);
    CHECK(memcmp(re1, re2, relen) != 0); /* Fresh shield coins, fixed RK and pad. */
    check_terminal(ctx, re1, relen, sk_b, sklen, message);
    check_terminal(ctx, re2, relen, sk_b, sklen, message);
    CHECK(lbpre_reencrypt(proxy, re3, relen, ac, pk_a, pklen, pk_c, pklen, src, srclen, rng) == LBPRE_OK);
    check_terminal(ctx, re3, relen, sk_c, sklen, message);
    CHECK(lbpre_registered_records(proxy) == 1); /* More recipients do not consume Q. */
    CHECK(lbpre_reencrypt(proxy, re3, relen, aa, pk_a, pklen, pk_a, pklen, src, srclen, rng) == LBPRE_OK);
    check_terminal(ctx, re3, relen, sk_a, sklen, message);
    CHECK(lbpre_registered_rekeys(proxy) == 3);
    /* Secret-free proxy instances reproduce the same RK/record pad. Changing
     * only the RK seed changes it, with the fresh coins held fixed. */
    CHECK(lbpre_register(replica_proxy, pk_a, pklen, src, srclen) == LBPRE_OK);
    CHECK(lbpre_register(variant_proxy, pk_a, pklen, src, srclen) == LBPRE_OK);
    rng1 = new_rng(70); rng2 = new_rng(70);
    CHECK(lbpre_reencrypt(proxy, re1, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng1) == LBPRE_OK);
    CHECK(lbpre_reencrypt(replica_proxy, re2, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re1, re2, relen) == 0);
    lbpre_rng_free(rng2); rng2 = new_rng(70);
    CHECK(lbpre_reencrypt(variant_proxy, re3, relen, ab_variant, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re1, re3, relen) != 0);
    check_terminal(ctx, re3, relen, sk_b, sklen, message);
    lbpre_rng_free(rng1); lbpre_rng_free(rng2);
    /* Optional deterministic-pad memoization must be byte-for-byte equivalent
     * to recomputation with the same fresh coins, including after eviction. */
    cached_pad_proxy = lbpre_proxy_new(ctx);
    CHECK(cached_pad_proxy != NULL);
    CHECK(lbpre_proxy_set_pad_cache(cached_pad_proxy, 1) == LBPRE_OK);
    CHECK(lbpre_register(cached_pad_proxy, pk_a, pklen, src, srclen) == LBPRE_OK);
    CHECK(lbpre_register(cached_pad_proxy, pk_a, pklen, unregistered, srclen) == LBPRE_OK);
    rng1 = new_rng(80); rng2 = new_rng(80);
    CHECK(lbpre_reencrypt(proxy, re1, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng1) == LBPRE_OK);
    CHECK(lbpre_reencrypt(cached_pad_proxy, re2, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re1, re2, relen) == 0); /* Cold cache. */
    lbpre_rng_free(rng2); rng2 = new_rng(80);
    CHECK(lbpre_reencrypt(cached_pad_proxy, re2, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re1, re2, relen) == 0); /* Warm cache. */
    /* A distinct seed on the same source/target/record must not hit the old pad. */
    lbpre_rng_free(rng1); rng1 = new_rng(80);
    lbpre_rng_free(rng2); rng2 = new_rng(80);
    CHECK(lbpre_reencrypt(variant_proxy, re2, relen, ab_variant, pk_a, pklen, pk_b, pklen, src, srclen, rng1) == LBPRE_OK);
    CHECK(lbpre_reencrypt(cached_pad_proxy, re3, relen, ab_variant, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re2,re3,relen) == 0 && memcmp(re1,re3,relen) != 0);
    check_terminal(ctx,re3,relen,sk_b,sklen,message);
    CHECK(lbpre_registered_rekeys(cached_pad_proxy) == 2);
    lbpre_proxy_clear_pad_cache(cached_pad_proxy);
    lbpre_rng_free(rng2); rng2 = new_rng(80);
    CHECK(lbpre_reencrypt(cached_pad_proxy, re2, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re1, re2, relen) == 0); /* Cleared and recomputed. */
    CHECK(lbpre_reencrypt(cached_pad_proxy, re3, relen, ab, pk_a, pklen, pk_b, pklen, unregistered, srclen, rng) == LBPRE_OK);
    check_terminal(ctx, re3, relen, sk_b, sklen, other_message);
    lbpre_rng_free(rng2); rng2 = new_rng(80);
    CHECK(lbpre_reencrypt(cached_pad_proxy, re2, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re1, re2, relen) == 0); /* Other record evicted the first pad. */
    CHECK(lbpre_proxy_set_pad_cache(cached_pad_proxy, 0) == LBPRE_OK);
    lbpre_rng_free(rng2); rng2 = new_rng(80);
    CHECK(lbpre_reencrypt(cached_pad_proxy, re2, relen, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng2) == LBPRE_OK);
    CHECK(memcmp(re1, re2, relen) == 0);
    CHECK(lbpre_registered_records(cached_pad_proxy) == 2);
    lbpre_rng_free(rng1); lbpre_rng_free(rng2);

    /* Length/type separation and malformed canonical encodings. No claim of
     * validating arbitrary malicious but canonically encoded ciphertexts/RKs. */
    CHECK(lbpre_keygen(ctx, bad, pklen - 1, sk_c, sklen, rng) != LBPRE_OK);
    CHECK(lbpre_encrypt(ctx, bad, srclen - 1, pk_a, pklen, message, rng) != LBPRE_OK);
    CHECK(lbpre_encrypt(ctx, bad, srclen, pk_a, pklen - 1, message, rng) != LBPRE_OK);
    CHECK(lbpre_decrypt_source(ctx, decoded, src, srclen - 1, sk_a, sklen) != LBPRE_OK);
    CHECK(lbpre_decrypt_source(ctx, decoded, src, srclen, sk_a, sklen - 1) != LBPRE_OK);
    CHECK(lbpre_decrypt_source(ctx, decoded, re1, relen, sk_a, sklen) != LBPRE_OK);
    CHECK(lbpre_decrypt_terminal(ctx, decoded, src, srclen, sk_a, sklen) != LBPRE_OK);
    CHECK(lbpre_decrypt_terminal(ctx, decoded, re1, relen - 1, sk_b, sklen) != LBPRE_OK);
    CHECK(lbpre_rekeygen(ctx, bad, rklen - 1, sk_a, sklen, pk_b, pklen, rng) != LBPRE_OK);
    CHECK(lbpre_rekey_prepare(ctx, rk_ab, rklen - 1, pk_a, pklen, pk_b, pklen) == NULL);
    CHECK(lbpre_register(proxy, pk_a, pklen, src, srclen - 1) != LBPRE_OK);
    CHECK(lbpre_reencrypt(proxy, re2, relen - 1, ab, pk_a, pklen, pk_b, pklen, src, srclen, rng) != LBPRE_OK);
    CHECK(lbpre_reencrypt(proxy, re2, relen, ab, pk_b, pklen, pk_b, pklen, src, srclen, rng) == LBPRE_ERR_ARGUMENT);
    CHECK(lbpre_reencrypt(proxy, re2, relen, ab, pk_a, pklen, pk_c, pklen, src, srclen, rng) == LBPRE_ERR_ARGUMENT);
    memcpy(bad, pk_a, pklen); set_coefficient(bad, 0, p->q_bits, p->q);
    CHECK(lbpre_encrypt(ctx, unregistered, srclen, bad, pklen, message, rng) != LBPRE_OK);
    CHECK(lbpre_register(proxy, bad, pklen, src, srclen) != LBPRE_OK);
    CHECK(lbpre_rekey_prepare(ctx, rk_ab, rklen, bad, pklen, pk_b, pklen) == NULL);
    memcpy(bad, pk_b, pklen); set_coefficient(bad, (size_t)p->ell * LBPRE_D, p->q_bits, p->q);
    CHECK(lbpre_rekeygen(ctx, rk_ac, rklen, sk_a, sklen, bad, pklen, rng) != LBPRE_OK);
    memcpy(bad, sk_a, sklen); set_coefficient(bad, 0, p->q_bits, p->q);
    CHECK(lbpre_decrypt_source(ctx, decoded, src, srclen, bad, sklen) != LBPRE_OK);
    CHECK(lbpre_rekeygen(ctx, rk_ac, rklen, bad, sklen, pk_c, pklen, rng) != LBPRE_OK);
    memcpy(bad, sk_b, sklen); set_coefficient(bad, (size_t)p->k * LBPRE_D, p->q_bits, p->q);
    CHECK(lbpre_decrypt_terminal(ctx, decoded, re1, relen, bad, sklen) != LBPRE_OK);
    memcpy(bad, src, srclen); set_coefficient(bad, 0, p->q_bits, p->q);
    CHECK(lbpre_decrypt_source(ctx, decoded, bad, srclen, sk_a, sklen) != LBPRE_OK);
    CHECK(lbpre_register(proxy, pk_a, pklen, bad, srclen) != LBPRE_OK);
    memcpy(bad, rk_ab, rklen); set_coefficient(bad, 0, p->q_bits, p->q);
    CHECK(lbpre_rekey_prepare(ctx, bad, rklen, pk_a, pklen, pk_b, pklen) == NULL);
    CHECK(lbpre_registered_records(proxy) == 1);

    printf("PASS logQ=%u base=%u PK=%zu SK=%zu A=%zu RK=%zu source=%zu RE=%zu\n",
           e->logQ, p->base, pklen, sklen, alen, rklen, srclen, relen);
    lbpre_proxy_free(proxy); lbpre_proxy_free(replica_proxy); lbpre_proxy_free(variant_proxy);
    lbpre_proxy_free(cached_pad_proxy);
    lbpre_rekey_cache_free(ab); lbpre_rekey_cache_free(ac); lbpre_rekey_cache_free(aa);
    lbpre_rekey_cache_free(ab_variant);
    lbpre_rng_free(rng); lbpre_ctx_free(ctx);
    free(pk_a); free(pk_b); free(pk_c); free(sk_a); free(sk_b); free(sk_c);
    free(src); free(unregistered); free(re1); free(re2); free(re3);
    free(rk_ab); free(rk_ac); free(rk_aa); free(rk_ab_variant); free(bad); free(matrix); free(matrix2);
}

int main(void) {
    size_t i;
    CHECK(strcmp(lbpre_parameter_source_sha256(), "c5d401fd996652e386be274d8921b5f3e6c94d8be08543cf61af5f378b3cd509") == 0);
    CHECK(strcmp(lbpre_parameter_profile_id(), "LATPRE-CLASSICAL128-LMH-SELECTION-v1") == 0);
    printf("Parameter archive SHA256: %s\n", lbpre_parameter_source_sha256());
    CHECK(lbpre_params_get(0) == NULL);
    CHECK(lbpre_params_get(5) == NULL);
    CHECK(lbpre_params_get(10) == NULL);
    CHECK(lbpre_params_get(15) == NULL);
    CHECK(lbpre_params_get(25) == NULL);
    CHECK(lbpre_params_get(35) == NULL);
    CHECK(lbpre_params_named(NULL) == NULL && lbpre_params_named("unknown") == NULL);
    CHECK(lbpre_params_get(31) == NULL);
    CHECK(lbpre_params_get(41) == NULL);
    for (i = 0; i < sizeof(EXPECTED) / sizeof(EXPECTED[0]); i++) test_one(&EXPECTED[i]);
    printf("All three L/M/H public-API parameter profiles passed; backend=%s\n", lbpre_backend());
    return EXIT_SUCCESS;
}
