#include <stdlib.h>
#include <string.h>
#include "internal.h"

#define MAX_K 9u
#define MAX_ELL 10u
#define POLY_BYTES(p) (32u*(p)->q_bits)
#define A_AT(c,i,j) ((c)->a_ntt+((size_t)(i)*(c)->p->k+(j))*LBPRE_D)
static uint64_t addq(uint64_t a, uint64_t b, uint64_t q)
{ uint64_t x=a+b; return x>=q?x-q:x; }
static void hash_u64(sha3_t *s, uint64_t x)
{
    uint8_t b[8]; for(unsigned i=0;i<8;++i) b[i]=(uint8_t)(x>>(8*i));
    sha3_absorb(s,b,sizeof(b));
}
static lbpre_ctx *setup_parameters(const lbpre_params *p, const uint8_t matrix_seed[LBPRE_SEED_BYTES])
{
    if(!p || !matrix_seed || p->k>MAX_K || p->ell>MAX_ELL) return NULL;
    lbpre_ctx *ctx=calloc(1,sizeof(*ctx));
    if(!ctx) return NULL;
    ctx->p=p;
    if(lbpre_ring_init(&ctx->ring,p->q)) { lbpre_ctx_free(ctx); return NULL; }
    ctx->a_ntt=calloc((size_t)p->ell*p->k*LBPRE_D,sizeof(uint64_t));
    ctx->source_gaussian=lbpre_gaussian_new(p->sigma_source);
    ctx->pad_gaussian=lbpre_gaussian_new(p->sigma_pad);
    if(!ctx->a_ntt || !ctx->source_gaussian || !ctx->pad_gaussian) {
        lbpre_ctx_free(ctx); return NULL;
    }
    sha3_t s; lbpre_xof_begin(&s,"LatPRE-LMH-v1/PUBLIC-CONTEXT");
    hash_u64(&s,p->logQ); hash_u64(&s,p->logM); hash_u64(&s,p->q);
    sha3_absorb(&s,(const uint8_t *)lbpre_parameter_context_sha256(p),64);
    /* Keep the frozen sampler context identifier independent of its display name. */
    {
        const char *sampler=lbpre_gaussian_context_id();
        hash_u64(&s,strlen(sampler));
        sha3_absorb(&s,(const uint8_t *)sampler,strlen(sampler));
    }
    sha3_absorb(&s,matrix_seed,LBPRE_SEED_BYTES); sha3_pad(&s,SHAKE_PAD);
    sha3_squeeze(&s,ctx->id,LBPRE_ID_BYTES); sha3_clear(&s);
    lbpre_rng rng; lbpre_xof_begin(&rng.xof,"LBPRE-v1/PUBLIC-MATRIX");
    sha3_absorb(&rng.xof,ctx->id,LBPRE_ID_BYTES); sha3_pad(&rng.xof,SHAKE_PAD);
    for(unsigned i=0;i<p->ell;++i) for(unsigned j=0;j<p->k;++j) {
        uint64_t *a=A_AT(ctx,i,j);
        lbpre_uniform_poly(a,p->q,&rng); lbpre_ntt(&ctx->ring,a);
    }
    lbpre_secure_zero(&rng,sizeof(rng)); return ctx;
}
lbpre_ctx *lbpre_setup(unsigned logQ, const uint8_t matrix_seed[LBPRE_SEED_BYTES])
{ return setup_parameters(lbpre_params_get(logQ),matrix_seed); }
lbpre_ctx *lbpre_setup_named(const char *name, const uint8_t matrix_seed[LBPRE_SEED_BYTES])
{ return setup_parameters(lbpre_params_named(name),matrix_seed); }
void lbpre_ctx_free(lbpre_ctx *ctx)
{
    if(!ctx) return;
    free(ctx->a_ntt);
    lbpre_gaussian_free(ctx->source_gaussian);
    lbpre_gaussian_free(ctx->pad_gaussian);
    lbpre_secure_zero(ctx,sizeof(*ctx)); free(ctx);
}
const lbpre_params *lbpre_ctx_params(const lbpre_ctx *ctx) { return ctx?ctx->p:NULL; }
const char *lbpre_backend(void) { return lbpre_ring_backend(); }
int lbpre_export_matrix(const lbpre_ctx *ctx, uint8_t *out, size_t outlen)
{
    if(!ctx || !out || outlen!=lbpre_public_matrix_bytes(ctx->p)) return LBPRE_ERR_ARGUMENT;
    uint64_t a[LBPRE_D];
    for(unsigned i=0;i<ctx->p->ell;++i) for(unsigned j=0;j<ctx->p->k;++j) {
        memcpy(a,A_AT(ctx,i,j),sizeof(a)); lbpre_intt(&ctx->ring,a);
        lbpre_pack_poly(out,a,ctx->p->q_bits); out+=POLY_BYTES(ctx->p);
    }
    return LBPRE_OK;
}
int lbpre_keygen(const lbpre_ctx *ctx, uint8_t *pk, size_t pklen,
                uint8_t *sk, size_t sklen, lbpre_rng *rng)
{
    if(!ctx || !pk || !sk || !rng || pklen!=lbpre_public_key_bytes(ctx->p)
       || sklen!=lbpre_secret_key_bytes(ctx->p)) return LBPRE_ERR_ARGUMENT;
    const lbpre_params *p=ctx->p;
    uint64_t sec[MAX_K][LBPRE_D], acc[LBPRE_D], err[LBPRE_D];
    for(unsigned role=0;role<2;++role) {
        for(unsigned j=0;j<p->k;++j) {
            if(role) lbpre_cbd_poly(sec[j],p->q,p->terminal_eta,rng);
            else lbpre_gaussian_poly(sec[j],p->q,ctx->source_gaussian,rng);
            lbpre_pack_poly(sk,sec[j],p->q_bits); sk+=POLY_BYTES(p);
            lbpre_ntt(&ctx->ring,sec[j]);
        }
        for(unsigned i=0;i<p->ell;++i) {
            memset(acc,0,sizeof(acc));
            for(unsigned j=0;j<p->k;++j) lbpre_pointwise_acc(&ctx->ring,acc,A_AT(ctx,i,j),sec[j]);
            lbpre_intt(&ctx->ring,acc);
            if(role) lbpre_cbd_poly(err,p->q,p->terminal_eta,rng);
            else lbpre_gaussian_poly(err,p->q,ctx->source_gaussian,rng);
            lbpre_poly_add(&ctx->ring,acc,acc,err); lbpre_pack_poly(pk,acc,p->q_bits); pk+=POLY_BYTES(p);
        }
    }
    lbpre_secure_zero(sec,sizeof(sec)); lbpre_secure_zero(err,sizeof(err));
    lbpre_secure_zero(acc,sizeof(acc)); return LBPRE_OK;
}
/* Convert a public vector to Montgomery NTT once per operation, not per RK column. */
static void public_ntt(const lbpre_ctx *ctx, uint64_t *out, const uint8_t *pk, unsigned role)
{
    pk+=(size_t)role*ctx->p->ell*POLY_BYTES(ctx->p);
    for(unsigned i=0;i<ctx->p->ell;++i) {
        lbpre_unpack_poly(out+i*LBPRE_D,pk,ctx->p->q_bits); pk+=POLY_BYTES(ctx->p);
        lbpre_ntt(&ctx->ring,out+i*LBPRE_D);
    }
}
/* Common public-key encryption with exact CBD coins, no compression or encoding.
 * Offset may alias out's last polynomial (added only after its new value is ready). */
static void internal_encrypt(const lbpre_ctx *ctx, uint64_t *out, const uint64_t *t_ntt,
                             const uint64_t *offset, lbpre_rng *rng, unsigned eta)
{
    const lbpre_params *p=ctx->p;
    uint64_t r[MAX_ELL][LBPRE_D], a[LBPRE_D], acc[LBPRE_D];
    for(unsigned i=0;i<p->ell;++i) { lbpre_cbd_poly(r[i],p->q,eta,rng); lbpre_ntt(&ctx->ring,r[i]); }
    for(unsigned j=0;j<p->k;++j) {
        memset(acc,0,sizeof(acc));
        for(unsigned i=0;i<p->ell;++i) lbpre_pointwise_acc(&ctx->ring,acc,A_AT(ctx,i,j),r[i]);
        lbpre_intt(&ctx->ring,acc); lbpre_cbd_poly(a,p->q,eta,rng);
        lbpre_poly_add(&ctx->ring,out+j*LBPRE_D,acc,a);
    }
    memset(acc,0,sizeof(acc));
    for(unsigned i=0;i<p->ell;++i) lbpre_pointwise_acc(&ctx->ring,acc,t_ntt+i*LBPRE_D,r[i]);
    lbpre_intt(&ctx->ring,acc); lbpre_cbd_poly(a,p->q,eta,rng);
    lbpre_poly_add(&ctx->ring,acc,acc,a);
    if(offset) lbpre_poly_add(&ctx->ring,acc,acc,offset);
    memcpy(out+p->k*LBPRE_D,acc,sizeof(acc));
    lbpre_secure_zero(r,sizeof(r)); lbpre_secure_zero(a,sizeof(a)); lbpre_secure_zero(acc,sizeof(acc));
}
int lbpre_encrypt(const lbpre_ctx *ctx, uint8_t *ct, size_t ctlen,
                  const uint8_t *pk, size_t pklen,
                  const uint8_t message[LBPRE_MESSAGE_BYTES], lbpre_rng *rng)
{
    if(!ctx || !ct || !message || !rng || ctlen!=lbpre_source_bytes(ctx->p)) return LBPRE_ERR_ARGUMENT;
    if(!lbpre_valid_pk(ctx,pk,pklen)) return LBPRE_ERR_ENCODING;
    const lbpre_params *p=ctx->p;
    uint64_t t[MAX_ELL*LBPRE_D], raw[(MAX_K+1)*LBPRE_D], mu[LBPRE_D];
    public_ntt(ctx,t,pk,0);
    for(unsigned i=0;i<LBPRE_D;++i) mu[i]=((message[i/8]>>(i%8))&1u)*(p->q/2);
    internal_encrypt(ctx,raw,t,mu,rng,p->source_eta);
    for(unsigned i=0;i<p->k;++i) { lbpre_pack_poly(ct,raw+i*LBPRE_D,p->q_bits); ct+=POLY_BYTES(p); }
    lbpre_compress_poly(p,ct,raw+p->k*LBPRE_D,p->source_v_bits);
    lbpre_secure_zero(raw,sizeof(raw)); lbpre_secure_zero(mu,sizeof(mu)); return LBPRE_OK;
}
static int decrypt(const lbpre_ctx *ctx, uint8_t *message, const uint8_t *ct, size_t ctlen,
                   const uint8_t *sk, size_t sklen, unsigned terminal)
{
    if(message) memset(message,0,LBPRE_MESSAGE_BYTES);
    if(!ctx || !message || !ct || !sk || sklen!=lbpre_secret_key_bytes(ctx->p)
       || ctlen!=(terminal?lbpre_terminal_bytes(ctx->p):lbpre_source_bytes(ctx->p))) return LBPRE_ERR_ARGUMENT;
    const lbpre_params *p=ctx->p;
    if(!lbpre_valid_exact(ctx,sk,2u*p->k)) return LBPRE_ERR_ENCODING;
    if(!terminal && !lbpre_valid_source(ctx,ct,ctlen)) return LBPRE_ERR_ENCODING;
    uint64_t s[LBPRE_D], u[LBPRE_D], acc[LBPRE_D], v[LBPRE_D];
    memset(acc,0,sizeof(acc)); sk+=(size_t)terminal*p->k*POLY_BYTES(p);
    unsigned ub=terminal?p->re_u_bits:p->q_bits, vb=terminal?p->re_v_bits:p->source_v_bits;
    for(unsigned i=0;i<p->k;++i) {
        lbpre_unpack_poly(s,sk,p->q_bits); sk+=POLY_BYTES(p); lbpre_ntt(&ctx->ring,s);
        lbpre_decompress_poly(p,u,ct,ub); ct+=32u*ub; lbpre_ntt(&ctx->ring,u);
        lbpre_pointwise_acc(&ctx->ring,acc,s,u);
    }
    lbpre_intt(&ctx->ring,acc); lbpre_decompress_poly(p,v,ct,vb); lbpre_poly_sub(&ctx->ring,v,v,acc);
    for(unsigned i=0;i<LBPRE_D;++i) {
        uint64_t d0=v[i]<p->q-v[i]?v[i]:p->q-v[i];
        uint64_t delta=p->q/2, d1=v[i]>delta?v[i]-delta:delta-v[i];
        if(p->q-d1<d1) d1=p->q-d1;
        message[i/8]|=(uint8_t)((d1<d0)<<(i%8));
    }
    lbpre_secure_zero(s,sizeof(s)); lbpre_secure_zero(acc,sizeof(acc));
    lbpre_secure_zero(v,sizeof(v)); return LBPRE_OK;
}
int lbpre_decrypt_source(const lbpre_ctx *ctx, uint8_t message[LBPRE_MESSAGE_BYTES],
                        const uint8_t *ct, size_t ctlen, const uint8_t *sk, size_t sklen)
{ return decrypt(ctx,message,ct,ctlen,sk,sklen,0); }
int lbpre_decrypt_terminal(const lbpre_ctx *ctx, uint8_t message[LBPRE_MESSAGE_BYTES],
                          const uint8_t *ct, size_t ctlen, const uint8_t *sk, size_t sklen)
{ return decrypt(ctx,message,ct,ctlen,sk,sklen,1); }
int lbpre_rekeygen(const lbpre_ctx *ctx, uint8_t *rk, size_t rklen,
                  const uint8_t *source_sk, size_t sklen,
                  const uint8_t *target_pk, size_t pklen, lbpre_rng *rng)
{
    if(!ctx || !rk || !source_sk || !rng || rklen!=lbpre_rekey_bytes(ctx->p)
       || sklen!=lbpre_secret_key_bytes(ctx->p)) return LBPRE_ERR_ARGUMENT;
    const lbpre_params *p=ctx->p;
    if(!lbpre_valid_pk(ctx,target_pk,pklen) || !lbpre_valid_exact(ctx,source_sk,2u*p->k)) return LBPRE_ERR_ENCODING;
    uint64_t t[MAX_ELL*LBPRE_D], s[LBPRE_D], offset[LBPRE_D], col[(MAX_K+1)*LBPRE_D];
    public_ntt(ctx,t,target_pk,1);
    for(unsigned i=0;i<p->k;++i) {
        lbpre_unpack_poly(s,source_sk+i*POLY_BYTES(p),p->q_bits);
        uint64_t power=1;
        for(unsigned j=0;j<p->length;++j) {
            for(unsigned a=0;a<LBPRE_D;++a) {
                uint64_t x=(uint64_t)((__uint128_t)power*s[a]%p->q); offset[a]=x?p->q-x:0;
            }
            internal_encrypt(ctx,col,t,offset,rng,p->internal_eta);
            for(unsigned a=0;a<=p->k;++a) { lbpre_pack_poly(rk,col+a*LBPRE_D,p->q_bits); rk+=POLY_BYTES(p); }
            power=(uint64_t)((__uint128_t)power*p->base%p->q);
        }
    }
    /* Independent per-rekey pad seed, appended to the packed matrix body. */
    sha3_squeeze(&rng->xof,rk,LBPRE_SEED_BYTES);
    lbpre_secure_zero(s,sizeof(s)); lbpre_secure_zero(offset,sizeof(offset));
    lbpre_secure_zero(col,sizeof(col)); return LBPRE_OK;
}
lbpre_rekey_cache *lbpre_rekey_prepare(const lbpre_ctx *ctx, const uint8_t *rk, size_t rklen,
                  const uint8_t *source_pk, size_t sourcelen,
                  const uint8_t *target_pk, size_t targetlen)
{
    if(!ctx || !rk || rklen!=lbpre_rekey_bytes(ctx->p)
       || !lbpre_valid_pk(ctx,source_pk,sourcelen) || !lbpre_valid_pk(ctx,target_pk,targetlen)) return NULL;
    const lbpre_params *p=ctx->p;
    size_t polys=(size_t)(p->k+1)*p->k*p->length;
    if(!lbpre_valid_exact(ctx,rk,polys)) return NULL;
    lbpre_rekey_cache *c=calloc(1,sizeof(*c));
    if(!c) return NULL;
    c->ctx=ctx; c->columns_ntt=calloc(polys*LBPRE_D,sizeof(uint64_t));
    c->target_ntt=calloc(p->ell*LBPRE_D,sizeof(uint64_t));
    if(!c->columns_ntt || !c->target_ntt) { lbpre_rekey_cache_free(c); return NULL; }
    for(size_t i=0;i<polys;++i) {
        lbpre_unpack_poly(c->columns_ntt+i*LBPRE_D,rk+i*POLY_BYTES(p),p->q_bits);
        lbpre_ntt(&ctx->ring,c->columns_ntt+i*LBPRE_D);
    }
    public_ntt(ctx,c->target_ntt,target_pk,1);
    lbpre_public_key_id(ctx,c->source,source_pk); lbpre_public_key_id(ctx,c->target,target_pk);
    memcpy(c->pad_seed,rk+lbpre_rekey_body_bytes(p),LBPRE_SEED_BYTES);
    sha3_t h; lbpre_xof_begin(&h,"LatPRE-LMH-v1/REKEY-VERSION");
    sha3_absorb(&h,ctx->id,LBPRE_ID_BYTES);
    sha3_absorb(&h,c->source,LBPRE_ID_BYTES); sha3_absorb(&h,c->target,LBPRE_ID_BYTES);
    sha3_absorb(&h,rk,rklen); sha3_pad(&h,SHAKE_PAD);
    sha3_squeeze(&h,c->edge,LBPRE_ID_BYTES); sha3_clear(&h);
    /* Keep the pad independent of rekey-matrix randomness, as in Figure 5.
     * Only public context and user identities enter this domain; the seed
     * independently separates rekeys. The full-RK edge digest above remains
     * solely for version admission and cache lookup. */
    lbpre_xof_begin(&h,"LatPRE-LMH-v2/PAD-DOMAIN");
    sha3_absorb(&h,ctx->id,LBPRE_ID_BYTES);
    sha3_absorb(&h,c->source,LBPRE_ID_BYTES); sha3_absorb(&h,c->target,LBPRE_ID_BYTES);
    sha3_pad(&h,SHAKE_PAD);
    sha3_squeeze(&h,c->pad_domain,LBPRE_ID_BYTES); sha3_clear(&h); return c;
}
void lbpre_rekey_cache_free(lbpre_rekey_cache *c)
{
    if(!c) return;
    if(c->columns_ntt) {
        const lbpre_params *p=c->ctx->p;
        lbpre_secure_zero(c->columns_ntt,(size_t)(p->k+1)*p->k*p->length*LBPRE_D*sizeof(uint64_t));
        free(c->columns_ntt);
    }
    free(c->target_ntt); lbpre_secure_zero(c,sizeof(*c)); free(c);
}
size_t lbpre_rekey_cache_memory_bytes(const lbpre_rekey_cache *c)
{
    if(!c) return 0;
    const lbpre_params *p=c->ctx->p;
    return sizeof(*c)+((size_t)(p->k+1)*p->k*p->length+p->ell)*LBPRE_D*sizeof(uint64_t);
}
int lbpre_reencrypt(lbpre_proxy *proxy, uint8_t *ct, size_t ctlen,
                    const lbpre_rekey_cache *cache, const uint8_t *source_pk, size_t sourcelen,
                    const uint8_t *target_pk, size_t targetlen,
                    const uint8_t *source_ct, size_t sourcctlen, lbpre_rng *rng)
{
    if(!proxy || !ct || !cache || !rng) return LBPRE_ERR_ARGUMENT;
    const lbpre_ctx *ctx=proxy->ctx; const lbpre_params *p=ctx->p;
    if(cache->ctx!=ctx || ctlen!=lbpre_terminal_bytes(p)) return LBPRE_ERR_ARGUMENT;
    if(!lbpre_valid_pk(ctx,source_pk,sourcelen) || !lbpre_valid_pk(ctx,target_pk,targetlen)
       || !lbpre_valid_source(ctx,source_ct,sourcctlen)) return LBPRE_ERR_ENCODING;
    uint8_t id[LBPRE_ID_BYTES], pkid[LBPRE_ID_BYTES];
    lbpre_public_key_id(ctx,pkid,source_pk);
    if(memcmp(pkid,cache->source,sizeof(pkid))) return LBPRE_ERR_ARGUMENT;
    lbpre_public_key_id(ctx,pkid,target_pk);
    if(memcmp(pkid,cache->target,sizeof(pkid))) return LBPRE_ERR_ARGUMENT;
    lbpre_record_id(ctx,id,source_pk,source_ct);
    if(!lbpre_registry_has(proxy,id)) return LBPRE_ERR_UNREGISTERED;
    uint64_t acc[(MAX_K+1)*LBPRE_D]={0}, digit[LBPRE_D], u[LBPRE_D];
    uint64_t fresh[(MAX_K+1)*LBPRE_D], pad[LBPRE_D], source_v[LBPRE_D];
    int64_t work[LBPRE_D];
    for(unsigned i=0;i<p->k;++i) {
        lbpre_unpack_poly(u,source_ct+i*POLY_BYTES(p),p->q_bits);
        for(unsigned a=0;a<LBPRE_D;++a) work[a]=(int64_t)u[a]-(u[a]>p->q/2?(int64_t)p->q:0);
        for(unsigned j=0;j<p->length;++j) {
            for(unsigned a=0;a<LBPRE_D;++a) {
                int64_t base=(int64_t)p->base, half=(int64_t)(p->base-1)/2;
                int64_t quotient=work[a]/base, d=work[a]-quotient*base;
                if(d>half) { d-=base; ++quotient; }
                if(d< -half) { d+=base; --quotient; }
                work[a]=quotient;
                digit[a]=d<0?p->q-(uint64_t)(-d):(uint64_t)d;
            }
            lbpre_ntt(&ctx->ring,digit);
            const uint64_t *column=cache->columns_ntt+((size_t)i*p->length+j)*(p->k+1)*LBPRE_D;
            for(unsigned a=0;a<=p->k;++a) lbpre_pointwise_acc(&ctx->ring,acc+a*LBPRE_D,column+a*LBPRE_D,digit);
        }
        for(unsigned a=0;a<LBPRE_D;++a) if(work[a]) return LBPRE_ERR_ENCODING;
    }
    int admission=lbpre_register_rekey(proxy,cache);
    if(admission) return admission;
    lbpre_cached_pad_poly(proxy,cache,pad,id);
    internal_encrypt(ctx,fresh,cache->target_ntt,pad,rng,p->internal_eta);
    lbpre_decompress_poly(p,source_v,source_ct+p->k*POLY_BYTES(p),p->source_v_bits);
    for(unsigned i=0;i<=p->k;++i) {
        uint64_t *v=acc+i*LBPRE_D; lbpre_intt(&ctx->ring,v);
        lbpre_poly_add(&ctx->ring,v,v,fresh+i*LBPRE_D);
        if(i==p->k) for(unsigned a=0;a<LBPRE_D;++a) v[a]=addq(v[a],source_v[a],p->q);
        unsigned bits=i<p->k?p->re_u_bits:p->re_v_bits;
        lbpre_compress_poly(p,ct,v,bits); ct+=32u*bits;
    }
    lbpre_secure_zero(pad,sizeof(pad)); lbpre_secure_zero(fresh,sizeof(fresh)); return LBPRE_OK;
}
