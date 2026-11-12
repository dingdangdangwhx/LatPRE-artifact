/* Focused white-box codec/registry/context tests.
 *
 * Registry stress inputs below are synthetic canonical byte strings, not
 * claims of honest encryption or proofs of key/ciphertext validity. Trusted
 * registration is an API precondition; this isolates its bookkeeping.
 */
#include "internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr,"FAIL core edge %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); \
} } while (0)

static uint8_t *allocate(size_t size)
{
    uint8_t *p = calloc(size,1); CHECK(p != NULL); return p;
}

static void set_wire_coefficient(uint8_t *wire, size_t index, unsigned bits, uint64_t value)
{
    unsigned j;
    for (j = 0; j < bits; ++j) {
        size_t bit = index*bits+j;
        uint8_t mask = (uint8_t)(1u << (bit%8));
        wire[bit/8] = (uint8_t)((wire[bit/8] & (uint8_t)~mask)
            | ((value>>j)&1 ? mask : 0));
    }
}

static uint64_t wire_coefficient(const uint8_t *wire, size_t index, unsigned bits)
{
    uint64_t value = 0;
    unsigned j;
    for (j = 0; j < bits; ++j) {
        size_t bit = index*bits+j;
        value |= (uint64_t)((wire[bit/8] >> (bit%8)) & 1u) << j;
    }
    return value;
}

static void codec_tests(void)
{
    static const unsigned qlogs[] = {20,30,40};
    size_t which;
    for (which = 0; which < sizeof(qlogs)/sizeof(qlogs[0]); ++which) {
        const lbpre_params *p = lbpre_params_get(qlogs[which]);
        uint64_t in[LBPRE_D], out[LBPRE_D];
        uint8_t wire[32*43];
        unsigned i, bits;
        for (i = 0; i < LBPRE_D; ++i) {
            switch (i%8) {
                case 0: in[i] = 0; break;
                case 1: in[i] = 1; break;
                case 2: in[i] = p->q-1; break;
                case 3: in[i] = p->q/2; break;
                case 4: in[i] = p->q/2+1; break;
                default: in[i] = ((uint64_t)i*i*UINT64_C(339967)+UINT64_C(8033148))%p->q;
            }
        }
        memset(wire,0xA5,sizeof(wire));
        lbpre_pack_poly(wire,in,p->q_bits);
        for (i = 0; i < LBPRE_D; ++i)
            CHECK(wire_coefficient(wire,i,p->q_bits) == in[i]);
        lbpre_unpack_poly(out,wire,p->q_bits);
        CHECK(memcmp(out,in,sizeof(in)) == 0);
        for (bits = 1; bits <= p->q_bits; ++bits) {
            uint64_t radius = bits == p->q_bits ? 0 : (p->q+(UINT64_C(1)<<bits))>>(bits+1);
            memset(wire,0xA5,sizeof(wire));
            lbpre_compress_poly(p,wire,in,bits);
            lbpre_decompress_poly(p,out,wire,bits);
            for (i = 0; i < LBPRE_D; ++i) {
                uint64_t diff = out[i] >= in[i] ? out[i]-in[i] : in[i]-out[i];
                if (p->q-diff < diff) diff = p->q-diff;
                CHECK(out[i] < p->q);
                CHECK(diff <= radius);
                if (bits == p->q_bits) CHECK(out[i] == in[i]);
            }
            /* A full polynomial is byte aligned even at odd bit widths. */
            for (i = 32*bits; i < sizeof(wire); ++i) CHECK(wire[i] == 0xA5);
        }
    }
}

static void registry_tests(void)
{
    uint8_t seed[32] = {1}, other_seed[32] = {2};
    lbpre_ctx *ctx = lbpre_setup(20,seed), *other = lbpre_setup(20,other_seed);
    lbpre_ctx *same = lbpre_setup(20,seed);
    const lbpre_params *p;
    lbpre_proxy *proxy, *same_pad, *other_ctx_pad;
    lbpre_rekey_cache *cache;
    lbpre_rng *rng;
    uint8_t id[64], original_id[64], changed_id[64], other_id[64], key_id[64];
    uint64_t pad[LBPRE_D], again[LBPRE_D];
    uint8_t *pk, *ct, *rk, *terminal;
    size_t pklen, ctlen, rklen, terminal_len, before;
    uint64_t expected_records = 0;
    unsigned key, record;
    CHECK(ctx && other && same);
    p = ctx->p; pklen = lbpre_public_key_bytes(p); ctlen = lbpre_source_bytes(p);
    rklen = lbpre_rekey_bytes(p); terminal_len = lbpre_terminal_bytes(p);
    pk = allocate(pklen); ct = allocate(ctlen); rk = allocate(rklen); terminal = allocate(terminal_len);
    CHECK(memcmp(ctx->id,same->id,sizeof(ctx->id)) == 0);
    CHECK(memcmp(ctx->id,other->id,sizeof(ctx->id)) != 0);
    proxy = lbpre_proxy_new(ctx); same_pad = lbpre_proxy_new(ctx);
    other_ctx_pad = lbpre_proxy_new(other); CHECK(proxy && same_pad && other_ctx_pad);
    before = lbpre_proxy_memory_bytes(proxy);

    /* More than eight keys exercise key-table growth; 120 records exercise
     * multiple record-table rehashes. Keep three records under every key. */
    for (key = 1; key <= 40; ++key) {
        set_wire_coefficient(pk,0,p->q_bits,key);
        for (record = 1; record <= 3; ++record) {
            set_wire_coefficient(ct,0,p->q_bits,record);
            CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_OK);
            ++expected_records;
        }
    }
    CHECK(lbpre_registered_records(proxy) == expected_records);
    CHECK(proxy->key_count == 40 && proxy->key_cap >= 80 && proxy->record_cap >= 240);
    CHECK(lbpre_proxy_memory_bytes(proxy) > before);
    for (key = 1; key <= 40; ++key) {
        set_wire_coefficient(pk,0,p->q_bits,key);
        for (record = 1; record <= 3; ++record) {
            set_wire_coefficient(ct,0,p->q_bits,record);
            lbpre_record_id(ctx,id,pk,ct);
            CHECK(lbpre_registry_has(proxy,id));
            CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_OK);
        }
    }
    CHECK(lbpre_registered_records(proxy) == expected_records);
    set_wire_coefficient(pk,0,p->q_bits,1);
    for (record = 4; record <= 1024; ++record) {
        set_wire_coefficient(ct,0,p->q_bits,record);
        CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_OK); ++expected_records;
    }
    /* Inject the count near the real Q limit, without creating a million records. */
    {
        size_t j;
        lbpre_public_key_id(ctx,key_id,pk);
        for(j=0;j<proxy->key_cap;++j)
            if(proxy->keys[j].used && !memcmp(proxy->keys[j].id,key_id,64)) break;
        CHECK(j<proxy->key_cap);
        proxy->keys[j].count=UINT64_C(1)<<p->logQ;
    }
    set_wire_coefficient(ct,0,p->q_bits,1025);
    CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_ERR_BUDGET);
    set_wire_coefficient(ct,0,p->q_bits,1);
    CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_OK);
    CHECK(lbpre_registered_records(proxy) == expected_records);

    /* Every byte of both PK roles and final compressed source payload is
     * bound. IDs are the full 512-bit digest, not a truncated table slot. */
    lbpre_record_id(ctx,original_id,pk,ct); lbpre_public_key_id(ctx,key_id,pk);
    CHECK(memcmp(original_id,key_id,64) != 0);
    ct[ctlen-1] ^= 1;
    lbpre_record_id(ctx,changed_id,pk,ct); CHECK(memcmp(original_id,changed_id,64) != 0);
    ct[ctlen-1] ^= 1;
    set_wire_coefficient(pk,(size_t)p->ell*LBPRE_D,p->q_bits,1);
    lbpre_record_id(ctx,changed_id,pk,ct); CHECK(memcmp(original_id,changed_id,64) != 0);
    set_wire_coefficient(pk,(size_t)p->ell*LBPRE_D,p->q_bits,0);
    lbpre_record_id(same,id,pk,ct); CHECK(memcmp(original_id,id,64) == 0);
    lbpre_record_id(other,other_id,pk,ct); CHECK(memcmp(original_id,other_id,64) != 0);
    {
        lbpre_rekey_cache *a=lbpre_rekey_prepare(ctx,rk,rklen,pk,pklen,pk,pklen);
        lbpre_rekey_cache *b=lbpre_rekey_prepare(other,rk,rklen,pk,pklen,pk,pklen);
        lbpre_rekey_cache *c;
        CHECK(a && b);
        CHECK(lbpre_proxy_set_pad_cache(same_pad,1)==LBPRE_OK);
        lbpre_pad_poly(a,pad,original_id); lbpre_pad_poly(a,again,original_id);
        CHECK(!memcmp(pad,again,sizeof(pad)));
        lbpre_cached_pad_poly(same_pad,a,again,original_id);
        CHECK(!memcmp(pad,again,sizeof(pad)));
        lbpre_pad_poly(b,again,original_id); CHECK(memcmp(pad,again,sizeof(pad)));
        lbpre_pad_poly(a,again,changed_id); CHECK(memcmp(pad,again,sizeof(pad)));
        rk[rklen-1]^=1;
        c=lbpre_rekey_prepare(ctx,rk,rklen,pk,pklen,pk,pklen); CHECK(c);
        lbpre_cached_pad_poly(same_pad,c,again,original_id);
        CHECK(memcmp(pad,again,sizeof(pad)));
        lbpre_cached_pad_poly(same_pad,a,again,original_id);
        CHECK(!memcmp(pad,again,sizeof(pad)));
        rk[rklen-1]^=1;
        lbpre_rekey_cache_free(a); lbpre_rekey_cache_free(b); lbpre_rekey_cache_free(c);
    }

    /* Canonical membership is not transferred between proxy registries. */
    CHECK(!lbpre_registry_has(other_ctx_pad,other_id));
    CHECK(lbpre_register(other_ctx_pad,pk,pklen,ct,ctlen) == LBPRE_OK);
    CHECK(lbpre_registry_has(other_ctx_pad,other_id));
    CHECK(!lbpre_registry_has(other_ctx_pad,original_id));

    /* Reject a cache from another context before running its algebra.
     * The zero RK is syntactically canonical and never used for a success. */
    cache = lbpre_rekey_prepare(same,rk,rklen,pk,pklen,pk,pklen); CHECK(cache);
    rng = lbpre_rng_new(seed); CHECK(rng);
    CHECK(lbpre_reencrypt(proxy,terminal,terminal_len,cache,pk,pklen,pk,pklen,ct,ctlen,rng)
          == LBPRE_ERR_ARGUMENT);
    lbpre_rekey_cache_free(cache); lbpre_rng_free(rng);

    /* Failure must not preserve stale decoded plaintext. */
    {
        uint8_t message[LBPRE_MESSAGE_BYTES];
        memset(message,0xA5,sizeof(message));
        CHECK(lbpre_decrypt_source(ctx,message,ct,ctlen,NULL,0) == LBPRE_ERR_ARGUMENT);
        for (key = 0; key < sizeof(message); ++key) CHECK(message[key] == 0);
    }
    lbpre_proxy_free(proxy); lbpre_proxy_free(same_pad); lbpre_proxy_free(other_ctx_pad);
    lbpre_ctx_free(ctx); lbpre_ctx_free(same); lbpre_ctx_free(other);
    free(pk); free(ct); free(rk); free(terminal);
}

/* Counts are injected near each limit to test uint64_t budget arithmetic
 * without allocating 2^40 records. The ordinary path is exercised separately
 * by the registry stress test above. */
static void large_budget_edges(void)
{
    static const unsigned logs[] = {20,30,40};
    uint8_t seed[32] = {42};
    size_t i,j;
    for (i = 0; i < sizeof(logs)/sizeof(logs[0]); ++i) {
        lbpre_ctx *ctx = lbpre_setup(logs[i],seed);
        lbpre_proxy *proxy;
        const lbpre_params *p;
        uint8_t *pk,*ct;
        size_t pklen,ctlen;
        uint64_t budget = UINT64_C(1)<<logs[i];
        CHECK(ctx != NULL); p = ctx->p;
        pklen = lbpre_public_key_bytes(p); ctlen = lbpre_source_bytes(p);
        pk = allocate(pklen); ct = allocate(ctlen);
        proxy = lbpre_proxy_new(ctx); CHECK(proxy != NULL);
        CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_OK);
        for (j = 0; j < proxy->key_cap; ++j) if (proxy->keys[j].used) break;
        CHECK(j < proxy->key_cap);
        proxy->keys[j].count = budget-1;
        set_wire_coefficient(ct,0,p->q_bits,1);
        CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_OK);
        CHECK(proxy->keys[j].count == budget);
        CHECK(lbpre_registered_records(proxy) == 2);
        CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_OK);
        set_wire_coefficient(ct,0,p->q_bits,2);
        CHECK(lbpre_register(proxy,pk,pklen,ct,ctlen) == LBPRE_ERR_BUDGET);
        CHECK(proxy->keys[j].count == budget);
        CHECK(lbpre_registered_records(proxy) == 2);
        lbpre_proxy_free(proxy); lbpre_ctx_free(ctx); free(pk); free(ct);
    }
}

/* Canonical zero matrices isolate lifetime rekey-version bookkeeping.
 * Seed-only variants are quota fixtures, not freshly generated honest rekeys. */
static void rekey_budget_edges(void)
{
    uint8_t seed[32]={91};
    lbpre_ctx *ctx=lbpre_setup(20,seed); CHECK(ctx);
    const lbpre_params *p=ctx->p;
    size_t pklen=lbpre_public_key_bytes(p), rklen=lbpre_rekey_bytes(p);
    uint8_t *pk=allocate(pklen), *rk=allocate(rklen);
    lbpre_proxy *proxy=lbpre_proxy_new(ctx); CHECK(proxy);
    const uint64_t limit=UINT64_C(1)<<p->logM;
    for(uint64_t i=0;i<=limit;++i) {
        memcpy(rk+lbpre_rekey_body_bytes(p),&i,sizeof(i));
        lbpre_rekey_cache *cache=lbpre_rekey_prepare(ctx,rk,rklen,pk,pklen,pk,pklen);
        CHECK(cache);
        int expected=i<limit?LBPRE_OK:LBPRE_ERR_BUDGET;
        CHECK(lbpre_register_rekey(proxy,cache)==expected);
        CHECK(lbpre_register_rekey(proxy,cache)==expected);
        lbpre_rekey_cache_free(cache);
    }
    CHECK(lbpre_registered_rekeys(proxy)==limit);
    CHECK(lbpre_registered_records(proxy)==0);
    /* Existing version still works at the limit; a second source has its own M. */
    memset(rk+lbpre_rekey_body_bytes(p),0,LBPRE_SEED_BYTES);
    lbpre_rekey_cache *cache=lbpre_rekey_prepare(ctx,rk,rklen,pk,pklen,pk,pklen);
    CHECK(cache && lbpre_register_rekey(proxy,cache)==LBPRE_OK);
    lbpre_rekey_cache_free(cache);
    set_wire_coefficient(pk,0,p->q_bits,1);
    cache=lbpre_rekey_prepare(ctx,rk,rklen,pk,pklen,pk,pklen);
    CHECK(cache && lbpre_register_rekey(proxy,cache)==LBPRE_OK);
    CHECK(lbpre_registered_rekeys(proxy)==limit+1);
    lbpre_rekey_cache_free(cache); lbpre_proxy_free(proxy); lbpre_ctx_free(ctx);
    free(pk); free(rk);
}

/* Figure 5 derives a pad from the independent rekey seed and source record,
 * never from the rekey-matrix randomness. Sharing a seed across two honest
 * matrix samples is intentional here: it isolates this dependency, while
 * version IDs and quota entries must still distinguish the matrices. */
static void pad_matrix_independence(void)
{
    static const unsigned logs[] = {20,30,40};
    size_t which;
    for (which = 0; which < sizeof(logs)/sizeof(logs[0]); ++which) {
        uint8_t setup_seed[32] = {111}, first_seed[32] = {112}, second_seed[32] = {113};
        uint8_t message[LBPRE_MESSAGE_BYTES] = {114};
        uint8_t record_id[LBPRE_ID_BYTES], second_id[LBPRE_ID_BYTES];
        uint64_t pad[LBPRE_D], again[LBPRE_D];
        lbpre_ctx *ctx = lbpre_setup(logs[which],setup_seed);
        lbpre_rng *first = lbpre_rng_new(first_seed), *second = lbpre_rng_new(second_seed);
        lbpre_proxy *proxy;
        lbpre_rekey_cache *a,*b,*changed_seed;
        const lbpre_params *p;
        size_t pklen,sklen,ctlen,rklen,bodylen;
        uint8_t *pk_a,*pk_b,*sk_a,*sk_b,*ct,*rk_a,*rk_b;
        CHECK(ctx && first && second); p = ctx->p;
        pklen = lbpre_public_key_bytes(p); sklen = lbpre_secret_key_bytes(p);
        ctlen = lbpre_source_bytes(p); rklen = lbpre_rekey_bytes(p);
        bodylen = lbpre_rekey_body_bytes(p);
        pk_a = allocate(pklen); pk_b = allocate(pklen);
        sk_a = allocate(sklen); sk_b = allocate(sklen); ct = allocate(ctlen);
        rk_a = allocate(rklen); rk_b = allocate(rklen);
        CHECK(lbpre_keygen(ctx,pk_a,pklen,sk_a,sklen,first) == LBPRE_OK);
        CHECK(lbpre_keygen(ctx,pk_b,pklen,sk_b,sklen,first) == LBPRE_OK);
        CHECK(lbpre_encrypt(ctx,ct,ctlen,pk_a,pklen,message,first) == LBPRE_OK);
        lbpre_record_id(ctx,record_id,pk_a,ct);
        CHECK(lbpre_rekeygen(ctx,rk_a,rklen,sk_a,sklen,pk_b,pklen,first) == LBPRE_OK);
        CHECK(lbpre_rekeygen(ctx,rk_b,rklen,sk_a,sklen,pk_b,pklen,second) == LBPRE_OK);
        CHECK(memcmp(rk_a,rk_b,bodylen) != 0);
        memcpy(rk_b+bodylen,rk_a+bodylen,LBPRE_SEED_BYTES);
        a = lbpre_rekey_prepare(ctx,rk_a,rklen,pk_a,pklen,pk_b,pklen);
        b = lbpre_rekey_prepare(ctx,rk_b,rklen,pk_a,pklen,pk_b,pklen);
        CHECK(a && b);
        CHECK(memcmp(a->edge,b->edge,LBPRE_ID_BYTES) != 0);
        lbpre_pad_poly(a,pad,record_id); lbpre_pad_poly(b,again,record_id);
        CHECK(memcmp(pad,again,sizeof(pad)) == 0);
        CHECK(memcmp(a->pad_domain,b->pad_domain,LBPRE_ID_BYTES) == 0);

        proxy = lbpre_proxy_new(ctx); CHECK(proxy);
        CHECK(lbpre_proxy_set_pad_cache(proxy,1) == LBPRE_OK);
        CHECK(lbpre_register_rekey(proxy,a) == LBPRE_OK);
        CHECK(lbpre_register_rekey(proxy,b) == LBPRE_OK);
        CHECK(lbpre_registered_rekeys(proxy) == 2);
        lbpre_cached_pad_poly(proxy,a,again,record_id);
        CHECK(memcmp(pad,again,sizeof(pad)) == 0);
        lbpre_cached_pad_poly(proxy,b,again,record_id);
        CHECK(memcmp(pad,again,sizeof(pad)) == 0);

        rk_b[rklen-1] ^= 1;
        changed_seed = lbpre_rekey_prepare(ctx,rk_b,rklen,pk_a,pklen,pk_b,pklen);
        CHECK(changed_seed);
        CHECK(memcmp(b->edge,changed_seed->edge,LBPRE_ID_BYTES) != 0);
        lbpre_cached_pad_poly(proxy,changed_seed,again,record_id);
        CHECK(memcmp(pad,again,sizeof(pad)) != 0);
        lbpre_cached_pad_poly(proxy,a,again,record_id);
        CHECK(memcmp(pad,again,sizeof(pad)) == 0);
        CHECK(lbpre_encrypt(ctx,ct,ctlen,pk_a,pklen,message,first) == LBPRE_OK);
        lbpre_record_id(ctx,second_id,pk_a,ct);
        CHECK(memcmp(record_id,second_id,LBPRE_ID_BYTES) != 0);
        lbpre_pad_poly(a,again,second_id);
        CHECK(memcmp(pad,again,sizeof(pad)) != 0);

        lbpre_rekey_cache_free(a); lbpre_rekey_cache_free(b);
        lbpre_rekey_cache_free(changed_seed); lbpre_proxy_free(proxy);
        lbpre_rng_free(first); lbpre_rng_free(second); lbpre_ctx_free(ctx);
        free(pk_a); free(pk_b); free(sk_a); free(sk_b); free(ct); free(rk_a); free(rk_b);
    }
}

/* Set A and both public-key roles to zero in a private test context. This
 * intentionally synthetic case exposes the additive coins directly. It
 * catches accidentally retaining the old uniform-ternary encryption law:
 * CBD_1 must have coefficient support {-1,0,1} and about one-half zeros.
 * This is an implementation regression test, not a validity/security claim. */
static void encryption_coin_regression(void)
{
    uint8_t seed[32] = {71}, rng_seed[32] = {72}, message[32] = {0};
    lbpre_ctx *ctx = lbpre_setup(20,seed);
    const lbpre_params *p;
    lbpre_rng *rng = lbpre_rng_new(rng_seed);
    uint8_t *pk,*sk,*ct,*rk;
    size_t pklen,sklen,ctlen,rklen,i,count,zeros;
    CHECK(ctx && rng); p = ctx->p;
    memset(ctx->a_ntt,0,(size_t)p->k*p->ell*LBPRE_D*sizeof(*ctx->a_ntt));
    pklen=lbpre_public_key_bytes(p); sklen=lbpre_secret_key_bytes(p);
    ctlen=lbpre_source_bytes(p); rklen=lbpre_rekey_bytes(p);
    pk=allocate(pklen); sk=allocate(sklen); ct=allocate(ctlen); rk=allocate(rklen);
    CHECK(lbpre_encrypt(ctx,ct,ctlen,pk,pklen,message,rng) == LBPRE_OK);
    count=(size_t)p->k*LBPRE_D; zeros=0;
    for (i=0; i<count; ++i) {
        uint64_t x=wire_coefficient(ct,i,p->q_bits);
        CHECK(x == 0 || x == 1 || x == p->q-1); zeros += x == 0;
    }
    CHECK(zeros*10 > count*4 && zeros*10 < count*6);
    CHECK(lbpre_rekeygen(ctx,rk,rklen,sk,sklen,pk,pklen,rng) == LBPRE_OK);
    count=(size_t)(p->k+1)*p->k*p->length*LBPRE_D; zeros=0;
    for (i=0; i<count; ++i) {
        uint64_t x=wire_coefficient(rk,i,p->q_bits);
        CHECK(x == 0 || x == 1 || x == p->q-1); zeros += x == 0;
    }
    CHECK(zeros*100 > count*45 && zeros*100 < count*55);
    lbpre_rng_free(rng); lbpre_ctx_free(ctx); free(pk); free(sk); free(ct); free(rk);
}

int main(void)
{
    codec_tests(); registry_tests(); large_budget_edges(); rekey_budget_edges(); encryption_coin_regression();
    pad_matrix_independence();
    printf("%u codec/registry/context edge checks passed\n",checks);
    return 0;
}
