#include "internal.h"

/* Internal callers use 1 <= bits <= 62 and coefficients below 2^bits.
 * Before draining bytes, the packing buffer contains at most bits+7 bits;
 * uint128 therefore also covers the largest modulus accepted by ring.c. */
void lbpre_pack_poly(uint8_t *out, const uint64_t in[LBPRE_D], unsigned bits)
{
    /* bits+7<=63: the accumulator and every shift fit uint64 exactly. */
    if(bits<=56) {
        uint64_t acc=0;
        unsigned have=0;
        for(unsigned i=0;i<LBPRE_D;++i) {
            acc|=in[i]<<have; have+=bits;
            while(have>=8) { *out++=(uint8_t)acc; acc>>=8; have-=8; }
        }
        return;
    }
    __uint128_t acc=0;
    unsigned have=0;
    for(unsigned i=0;i<LBPRE_D;++i) {
        acc|=(__uint128_t)in[i]<<have; have+=bits;
        while(have>=8) { *out++=(uint8_t)acc; acc>>=8; have-=8; }
    }
}
void lbpre_unpack_poly(uint64_t out[LBPRE_D], const uint8_t *in, unsigned bits)
{
    uint64_t mask=(UINT64_C(1)<<bits)-1;
    if(bits<=56) {
        uint64_t acc=0;
        unsigned have=0;
        for(unsigned i=0;i<LBPRE_D;++i) {
            while(have<bits) { acc|=(uint64_t)*in++<<have; have+=8; }
            out[i]=acc&mask; acc>>=bits; have-=bits;
        }
        return;
    }
    __uint128_t acc=0;
    unsigned have=0;
    for(unsigned i=0;i<LBPRE_D;++i) {
        while(have<bits) { acc|=(__uint128_t)*in++<<have; have+=8; }
        out[i]=(uint64_t)acc&mask; acc>>=bits; have-=bits;
    }
}
void lbpre_compress_poly(const lbpre_params *p, uint8_t *out,
                         const uint64_t in[LBPRE_D], unsigned bits)
{
    if(bits==p->q_bits) { lbpre_pack_poly(out,in,bits); return; }
    uint64_t tmp[LBPRE_D], mask=(UINT64_C(1)<<bits)-1;
    /* q<2^q_bits and q_bits+bits<=63 bound the rounded numerator
     * below 2^64, avoiding the compiler's generic uint128 divide. */
    if(p->q_bits+bits<=63) {
        for(unsigned i=0;i<LBPRE_D;++i)
            tmp[i]=((in[i]<<bits)+p->q/2)/p->q&mask;
    } else {
        for(unsigned i=0;i<LBPRE_D;++i)
            tmp[i]=(uint64_t)((((__uint128_t)in[i]<<bits)+p->q/2)/p->q)&mask;
    }
    lbpre_pack_poly(out,tmp,bits);
}
void lbpre_decompress_poly(const lbpre_params *p, uint64_t out[LBPRE_D],
                           const uint8_t *in, unsigned bits)
{
    lbpre_unpack_poly(out,in,bits);
    if(bits==p->q_bits) return;
    /* For 0<=x<2^bits, rounding q*x/2^bits gives a value in [0,q].
     * Thus at most one subtraction is needed for the canonical residue. */
    if(p->q_bits+bits<=63) {
        for(unsigned i=0;i<LBPRE_D;++i) {
            uint64_t value=(p->q*out[i]+(UINT64_C(1)<<(bits-1)))>>bits;
            out[i]=value-(p->q & (UINT64_C(0)-(value>=p->q)));
        }
    } else {
        for(unsigned i=0;i<LBPRE_D;++i) {
            uint64_t value=(uint64_t)(((__uint128_t)p->q*out[i]+(UINT64_C(1)<<(bits-1)))>>bits);
            out[i]=value-(p->q & (UINT64_C(0)-(value>=p->q)));
        }
    }
}
static int valid_full(const lbpre_params *p, const uint8_t *in, size_t polys)
{
    uint64_t tmp[LBPRE_D];
    for(size_t j=0;j<polys;++j) {
        lbpre_unpack_poly(tmp,in+j*32u*p->q_bits,p->q_bits);
        for(unsigned i=0;i<LBPRE_D;++i) if(tmp[i]>=p->q) return 0;
    }
    return 1;
}
int lbpre_valid_pk(const lbpre_ctx *ctx, const uint8_t *pk, size_t len)
{
    return ctx && pk && len==lbpre_public_key_bytes(ctx->p) && valid_full(ctx->p,pk,2u*ctx->p->ell);
}
int lbpre_valid_source(const lbpre_ctx *ctx, const uint8_t *ct, size_t len)
{
    return ctx && ct && len==lbpre_source_bytes(ctx->p) && valid_full(ctx->p,ct,ctx->p->k);
}
/* Internal exact-object check, also used for secret keys and RK matrices. */
int lbpre_valid_exact(const lbpre_ctx *ctx, const uint8_t *in, size_t polys)
{ return ctx && in && valid_full(ctx->p,in,polys); }
