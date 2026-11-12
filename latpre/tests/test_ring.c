#include "internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t state = UINT64_C(0xb636a2078bc4d7f9);
static unsigned checks;

static uint64_t random_u64(void)
{
    /* Deterministic test data; this is not a cryptographic sampler. */
    state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
    return state*UINT64_C(2685821657736338717);
}

static void require(int condition, const char *label, uint64_t q)
{
    ++checks;
    if (!condition) {
        fprintf(stderr,"FAIL %s q=%" PRIu64 "\n",label,q);
        exit(1);
    }
}

static void equal(const uint64_t *a, const uint64_t *b, const char *label, uint64_t q)
{
    size_t i;
    for (i = 0; i < LBPRE_D; ++i) {
        if (a[i] != b[i]) {
            fprintf(stderr,"FAIL %s q=%" PRIu64 " index=%zu got=%" PRIu64
                    " wanted=%" PRIu64 "\n",label,q,i,a[i],b[i]);
            exit(1);
        }
    }
    ++checks;
}

static void canonical(const uint64_t *a, uint64_t q)
{
    size_t i;
    for (i = 0; i < LBPRE_D; ++i) require(a[i] < q,"canonical residue",q);
}

static uint64_t normal_product(uint64_t a, uint64_t b, uint64_t q)
{
    return (uint64_t)(((__uint128_t)a*b) % q);
}

static uint64_t normal_power(uint64_t a, unsigned e, uint64_t q)
{
    uint64_t x = 1;
    while (e--) x = normal_product(x,a,q);
    return x;
}

static void test_pair(const lbpre_ring *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t expected[LBPRE_D], got[LBPRE_D], x[LBPRE_D], y[LBPRE_D];
    uint64_t sum[LBPRE_D], refsum[LBPRE_D], refdifference[LBPRE_D];
    size_t i;
    lbpre_poly_mul_schoolbook(r,expected,a,b);
    lbpre_poly_mul(r,got,a,b);
    equal(got,expected,"NTT multiplication vs schoolbook",r->q);
    canonical(got,r->q);

    memcpy(x,a,sizeof(x)); lbpre_ntt(r,x); canonical(x,r->q);
    memcpy(y,x,sizeof(y)); lbpre_intt(r,y);
    equal(y,a,"NTT round trip",r->q);
    memcpy(y,b,sizeof(y)); lbpre_ntt(r,y);
    lbpre_pointwise(r,sum,x,y); lbpre_intt(r,sum);
    equal(sum,expected,"explicit transform product",r->q);

    memcpy(got,a,sizeof(got)); lbpre_poly_mul(r,got,got,b);
    equal(got,expected,"multiply left alias",r->q);
    memcpy(got,b,sizeof(got)); lbpre_poly_mul(r,got,a,got);
    equal(got,expected,"multiply right alias",r->q);
    memcpy(got,a,sizeof(got)); lbpre_poly_mul_schoolbook(r,got,got,b);
    equal(got,expected,"schoolbook alias",r->q);

    /* Transformed pointwise multiplication also permits either alias. */
    memcpy(got,x,sizeof(got)); lbpre_pointwise(r,got,got,y); lbpre_intt(r,got);
    equal(got,expected,"pointwise left alias",r->q);
    memcpy(got,y,sizeof(got)); lbpre_pointwise(r,got,x,got); lbpre_intt(r,got);
    equal(got,expected,"pointwise right alias",r->q);

    for (i = 0; i < LBPRE_D; ++i) {
        refsum[i] = (a[i]+b[i]) % r->q;
        refdifference[i] = (a[i]+r->q-b[i]) % r->q;
        expected[i] = (expected[i]+a[i]) % r->q;
    }
    memcpy(got,x,sizeof(got)); lbpre_pointwise_acc(r,got,x,y); lbpre_intt(r,got);
    equal(got,expected,"mulacc left alias: a+a*b",r->q);
    for (i = 0; i < LBPRE_D; ++i)
        expected[i] = (expected[i]+r->q-a[i]+b[i]) % r->q;
    memcpy(got,y,sizeof(got)); lbpre_pointwise_acc(r,got,x,got); lbpre_intt(r,got);
    equal(got,expected,"mulacc right alias: b+a*b",r->q);

    lbpre_poly_add(r,sum,a,b); equal(sum,refsum,"coefficient add",r->q);
    lbpre_poly_sub(r,sum,a,b); equal(sum,refdifference,"coefficient subtract",r->q);
    memcpy(sum,a,sizeof(sum)); lbpre_poly_add(r,sum,sum,b);
    equal(sum,refsum,"add left alias",r->q);
    memcpy(sum,b,sizeof(sum)); lbpre_poly_add(r,sum,a,sum);
    equal(sum,refsum,"add right alias",r->q);
    memcpy(sum,a,sizeof(sum)); lbpre_poly_sub(r,sum,sum,b);
    equal(sum,refdifference,"subtract left alias",r->q);
    memcpy(sum,b,sizeof(sum)); lbpre_poly_sub(r,sum,a,sum);
    equal(sum,refdifference,"subtract right alias",r->q);
}

static void test_modulus(uint64_t q)
{
    lbpre_ring r;
    uint64_t a[LBPRE_D], b[LBPRE_D], got[LBPRE_D], expected[LBPRE_D];
    size_t i;
    unsigned iteration;
    require(lbpre_ring_init(&r,q) == LBPRE_OK,"ring initialization",q);
    require(q*r.qinv == UINT64_MAX,"Montgomery q inverse",q);
    require(normal_power(r.psi,LBPRE_D,q) == q-1,"psi exact order 512",q);
    require(normal_power(r.psi,2*LBPRE_D,q) == 1,"psi power 512",q);
    require(normal_product(r.ninv,LBPRE_D,q) == 1,"inverse degree",q);

    memset(a,0,sizeof(a)); memset(b,0,sizeof(b)); test_pair(&r,a,b);
    a[0] = 1; test_pair(&r,a,b);
    b[0] = q-1; test_pair(&r,a,b);

    /* Basis-vector evaluation pins transform order and Montgomery scaling. */
    memset(a,0,sizeof(a)); a[1] = 1; memcpy(got,a,sizeof(got)); lbpre_ntt(&r,got);
    for (i = 0; i < LBPRE_D; ++i)
        expected[i] = normal_product(normal_power(r.psi,(unsigned)(2*i+1),q),r.one,q);
    equal(got,expected,"forward evaluation at odd roots",q);
    memset(a,0,sizeof(a)); memset(b,0,sizeof(b));
    a[LBPRE_D-1] = 1; b[1] = 1;
    lbpre_poly_mul(&r,got,a,b); memset(expected,0,sizeof(expected)); expected[0] = q-1;
    equal(got,expected,"negacyclic wrap x^256=-1",q); test_pair(&r,a,b);

    for (i = 0; i < LBPRE_D; ++i) a[i] = b[i] = q-1;
    lbpre_poly_mul(&r,got,a,b);
    for (i = 0; i < LBPRE_D; ++i) expected[i] = (q+2*i+2-LBPRE_D) % q;
    equal(got,expected,"all maximum residues closed form",q); test_pair(&r,a,b);
    for (i = 0; i < LBPRE_D; ++i) { a[i] = i&1 ? q-1 : 0; b[i] = i&1 ? 0 : q-1; }
    test_pair(&r,a,b);

    for (iteration = 0; iteration < 48; ++iteration) {
        for (i = 0; i < LBPRE_D; ++i) { a[i] = random_u64()%q; b[i] = random_u64()%q; }
        test_pair(&r,a,b);
    }
    /* Squaring/full alias and accumulation into all three aliased operands. */
    lbpre_poly_mul_schoolbook(&r,expected,a,a);
    memcpy(got,a,sizeof(got)); lbpre_poly_mul(&r,got,got,got);
    equal(got,expected,"multiply all alias",q);
    memcpy(got,a,sizeof(got)); lbpre_ntt(&r,got);
    lbpre_pointwise_acc(&r,got,got,got); lbpre_intt(&r,got);
    for (i = 0; i < LBPRE_D; ++i) expected[i] = (expected[i]+a[i]) % q;
    equal(got,expected,"mulacc all alias",q);
    printf("ring q=%" PRIu64 ": OK\n",q);
}

/* Slow bit-addressed oracle independent of the streaming serializer. */
static void reference_pack(uint8_t *out, const uint64_t *in, unsigned bits)
{
    memset(out,0,32u*bits);
    for (unsigned i = 0; i < LBPRE_D; ++i)
        for (unsigned j = 0; j < bits; ++j) {
            size_t bit = (size_t)i*bits+j;
            out[bit/8] |= (uint8_t)(((in[i]>>j)&1u) << (bit%8));
        }
}

static void test_packing(void)
{
    uint8_t got[32u*62+2], expected[32u*62];
    uint64_t in[LBPRE_D], recovered[LBPRE_D];
    for (unsigned bits = 1; bits <= 62; ++bits) {
        uint64_t mask = (UINT64_C(1)<<bits)-1;
        for (unsigned i = 0; i < LBPRE_D; ++i)
            in[i] = i%4 == 0 ? 0 : i%4 == 1 ? mask : random_u64()&mask;
        memset(got,0xa5,sizeof(got));
        reference_pack(expected,in,bits);
        lbpre_pack_poly(got+1,in,bits);
        require(got[0] == 0xa5 && got[32u*bits+1] == 0xa5,"packing byte bounds",bits);
        require(memcmp(got+1,expected,32u*bits) == 0,"packing bit oracle",bits);
        lbpre_unpack_poly(recovered,expected,bits);
        equal(recovered,in,"unpacking bit oracle",bits);
    }
}

static void test_compression(uint64_t q, unsigned qbits)
{
    lbpre_params p = {0};
    lbpre_ctx ctx = {0};
    uint8_t packed[32u*62+2], expected[32u*62];
    uint64_t in[LBPRE_D], quantized[LBPRE_D], recovered[LBPRE_D];
    p.q = q; p.q_bits = qbits; ctx.p = &p;
    for (unsigned bits = 1; bits <= qbits; ++bits) {
        uint64_t levels = UINT64_C(1)<<bits;
        uint64_t radius = bits == qbits ? 0 : (q+levels)/(2*levels);
        for (unsigned i = 0; i < LBPRE_D; ++i) {
            /* Include wraparound and values adjacent to rounding boundaries. */
            switch (i%8) {
            case 0: in[i] = 0; break;
            case 1: in[i] = q-1; break;
            case 2: in[i] = q/2; break;
            case 3: in[i] = (uint64_t)(((__uint128_t)q*(random_u64()&(levels-1)))/levels); break;
            default: in[i] = random_u64()%q;
            }
            quantized[i] = bits == qbits ? in[i] :
                (uint64_t)((2*(__uint128_t)in[i]*levels+q)/(2*(__uint128_t)q))%levels;
        }
        reference_pack(expected,quantized,bits);
        memset(packed,0xa5,sizeof(packed));
        lbpre_compress_poly(&p,packed+1,in,bits);
        require(memcmp(packed+1,expected,32u*bits) == 0,"compression rational oracle",q);
        require(packed[0] == 0xa5 && packed[32u*bits+1] == 0xa5,"compression byte bounds",q);
        lbpre_decompress_poly(&p,recovered,expected,bits);
        for (unsigned i = 0; i < LBPRE_D; ++i) {
            uint64_t want = bits == qbits ? in[i] :
                (uint64_t)((2*(__uint128_t)q*quantized[i]+levels)/(2*(__uint128_t)levels))%q;
            uint64_t error = recovered[i] > in[i] ? recovered[i]-in[i] : in[i]-recovered[i];
            if (error > q-error) error = q-error;
            require(recovered[i] == want,"decompression rational oracle",q);
            require(error <= radius,"compression circular error bound",q);
        }
    }
    memset(in,0,sizeof(in)); in[0] = q-1;
    lbpre_pack_poly(packed,in,qbits);
    require(lbpre_valid_exact(&ctx,packed,1),"accept canonical polynomial",q);
    in[LBPRE_D-1] = q;
    lbpre_pack_poly(packed,in,qbits);
    require(!lbpre_valid_exact(&ctx,packed,1),"reject noncanonical polynomial",q);
    printf("serialization q=%" PRIu64 ": OK\n",q);
}

int main(void)
{
    /* Actual L/M/H moduli, followed by a prime immediately below the guard. */
    static const uint64_t q[] = {UINT64_C(265753601),UINT64_C(34016143361),UINT64_C(4354066046977),
        UINT64_C(8708132098049),UINT64_C(4611686018427379201)};
    static const unsigned qbits[] = {28,35,42,43,62};
    static const uint64_t invalid[] = {0,1,2,17,513,1025,1537,UINT64_C(17179869185),
        UINT64_C(1)<<62,(UINT64_C(1)<<62)+1,UINT64_MAX};
    lbpre_ring r;
    size_t i;
    require(lbpre_ring_init(NULL,q[0]) == LBPRE_ERR_ARGUMENT,"null context",q[0]);
    for (i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        require(lbpre_ring_init(&r,invalid[i]) == LBPRE_ERR_ARGUMENT,"invalid modulus",invalid[i]);
    test_packing();
    for (i = 0; i < sizeof(q)/sizeof(q[0]); ++i) {
        test_modulus(q[i]);
        test_compression(q[i],qbits[i]);
    }
    printf("backend: %s\n%u ring checks passed\n",lbpre_ring_backend(),checks);
    return 0;
}
