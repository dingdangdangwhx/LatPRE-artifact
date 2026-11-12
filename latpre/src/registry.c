#include <stdlib.h>
#include <string.h>
#include "internal.h"

static void absorb_u64(sha3_t *s, uint64_t x)
{
    uint8_t b[8];
    for(unsigned i=0;i<8;++i) b[i]=(uint8_t)(x>>(8*i));
    sha3_absorb(s,b,8);
}
void lbpre_public_key_id(const lbpre_ctx *ctx, uint8_t out[LBPRE_ID_BYTES], const uint8_t *pk)
{
    sha3_t s; lbpre_xof_begin(&s,"LBPRE-v1/PUBLIC-KEY-ID");
    sha3_absorb(&s,ctx->id,LBPRE_ID_BYTES);
    absorb_u64(&s,lbpre_public_key_bytes(ctx->p));
    sha3_absorb(&s,pk,lbpre_public_key_bytes(ctx->p));
    sha3_pad(&s,SHAKE_PAD); sha3_squeeze(&s,out,LBPRE_ID_BYTES); sha3_clear(&s);
}
void lbpre_record_id(const lbpre_ctx *ctx, uint8_t out[LBPRE_ID_BYTES],
                     const uint8_t *pk, const uint8_t *ct)
{
    sha3_t s; lbpre_xof_begin(&s,"LBPRE-v1/CANONICAL-SOURCE-ID");
    sha3_absorb(&s,ctx->id,LBPRE_ID_BYTES);
    absorb_u64(&s,lbpre_public_key_bytes(ctx->p));
    sha3_absorb(&s,pk,lbpre_public_key_bytes(ctx->p));
    absorb_u64(&s,lbpre_source_bytes(ctx->p));
    sha3_absorb(&s,ct,lbpre_source_bytes(ctx->p));
    sha3_pad(&s,SHAKE_PAD); sha3_squeeze(&s,out,LBPRE_ID_BYTES); sha3_clear(&s);
}
static size_t slot(const uint8_t id[LBPRE_ID_BYTES], size_t cap)
{
    uint64_t x=0;
    for(unsigned i=0;i<8;++i) x|=(uint64_t)id[i]<<(8*i);
    return (size_t)x&(cap-1);
}
static size_t record_slot(const lbpre_proxy *p, const uint8_t id[LBPRE_ID_BYTES])
{
    size_t i=slot(id,p->record_cap);
    while(p->records[i].used && memcmp(p->records[i].id,id,LBPRE_ID_BYTES)) i=(i+1)&(p->record_cap-1);
    return i;
}
static size_t key_slot(const lbpre_proxy *p, const uint8_t id[LBPRE_ID_BYTES])
{
    size_t i=slot(id,p->key_cap);
    while(p->keys[i].used && memcmp(p->keys[i].id,id,LBPRE_ID_BYTES)) i=(i+1)&(p->key_cap-1);
    return i;
}
static size_t edge_slot(const lbpre_proxy *p, const uint8_t id[LBPRE_ID_BYTES])
{
    size_t i=slot(id,p->edge_cap);
    while(p->edges[i].used && memcmp(p->edges[i].id,id,LBPRE_ID_BYTES)) i=(i+1)&(p->edge_cap-1);
    return i;
}
static int grow_edges(lbpre_proxy *p)
{
    size_t oldcap=p->edge_cap;
    if(oldcap>SIZE_MAX/(2*sizeof(record_entry))) return LBPRE_ERR_MEMORY;
    record_entry *old=p->edges, *next=calloc(oldcap*2,sizeof(*next));
    if(!next) return LBPRE_ERR_MEMORY;
    p->edges=next; p->edge_cap=oldcap*2;
    for(size_t i=0;i<oldcap;++i) if(old[i].used) next[edge_slot(p,old[i].id)]=old[i];
    free(old); return LBPRE_OK;
}
static int grow_records(lbpre_proxy *p)
{
    size_t oldcap=p->record_cap;
    if(oldcap>SIZE_MAX/(2*sizeof(record_entry))) return LBPRE_ERR_MEMORY;
    record_entry *old=p->records, *next=calloc(oldcap*2,sizeof(*next));
    if(!next) return LBPRE_ERR_MEMORY;
    p->records=next; p->record_cap=oldcap*2;
    for(size_t i=0;i<oldcap;++i) if(old[i].used) next[record_slot(p,old[i].id)]=old[i];
    lbpre_secure_zero(old,oldcap*sizeof(*old)); free(old); return LBPRE_OK;
}
static int grow_keys(lbpre_proxy *p)
{
    size_t oldcap=p->key_cap;
    if(oldcap>SIZE_MAX/(2*sizeof(key_entry))) return LBPRE_ERR_MEMORY;
    key_entry *old=p->keys, *next=calloc(oldcap*2,sizeof(*next));
    if(!next) return LBPRE_ERR_MEMORY;
    p->keys=next; p->key_cap=oldcap*2;
    for(size_t i=0;i<oldcap;++i) if(old[i].used) next[key_slot(p,old[i].id)]=old[i];
    lbpre_secure_zero(old,oldcap*sizeof(*old)); free(old); return LBPRE_OK;
}
lbpre_proxy *lbpre_proxy_new(const lbpre_ctx *ctx)
{
    if(!ctx) return NULL;
    lbpre_proxy *p=calloc(1,sizeof(*p));
    if(!p) return NULL;
    p->ctx=ctx; p->record_cap=p->key_cap=p->edge_cap=16;
    p->records=calloc(p->record_cap,sizeof(*p->records));
    p->keys=calloc(p->key_cap,sizeof(*p->keys));
    p->edges=calloc(p->edge_cap,sizeof(*p->edges));
    if(!p->records || !p->keys || !p->edges) { lbpre_proxy_free(p); return NULL; }
    return p;
}
void lbpre_proxy_free(lbpre_proxy *p)
{
    if(!p) return;
    if(p->records) { lbpre_secure_zero(p->records,p->record_cap*sizeof(*p->records)); free(p->records); }
    if(p->keys) { lbpre_secure_zero(p->keys,p->key_cap*sizeof(*p->keys)); free(p->keys); }
    free(p->edges);
    if(p->pads) { lbpre_secure_zero(p->pads,p->pad_capacity*sizeof(*p->pads)); free(p->pads); }
    lbpre_secure_zero(p,sizeof(*p)); free(p);
}
int lbpre_registry_has(const lbpre_proxy *p, const uint8_t id[LBPRE_ID_BYTES])
{ return p && p->records[record_slot(p,id)].used; }
int lbpre_register(lbpre_proxy *p, const uint8_t *pk, size_t pklen,
                   const uint8_t *ct, size_t ctlen)
{
    if(!p || !pk || !ct) return LBPRE_ERR_ARGUMENT;
    if(!lbpre_valid_pk(p->ctx,pk,pklen) || !lbpre_valid_source(p->ctx,ct,ctlen)) return LBPRE_ERR_ENCODING;
    uint8_t id[LBPRE_ID_BYTES], key[LBPRE_ID_BYTES];
    lbpre_record_id(p->ctx,id,pk,ct);
    if(lbpre_registry_has(p,id)) return LBPRE_OK;
    lbpre_public_key_id(p->ctx,key,pk);
    size_t j=key_slot(p,key);
    if(p->keys[j].used && p->keys[j].count>=(UINT64_C(1)<<p->ctx->p->logQ)) return LBPRE_ERR_BUDGET;
    if(p->record_count>=p->record_cap/2) { int ret=grow_records(p); if(ret) return ret; }
    if(!p->keys[j].used && p->key_count>=p->key_cap/2) {
        int ret=grow_keys(p); if(ret) return ret; j=key_slot(p,key);
    }
    if(!p->keys[j].used) { p->keys[j].used=1; memcpy(p->keys[j].id,key,sizeof(key)); ++p->key_count; }
    ++p->keys[j].count;
    size_t i=record_slot(p,id); p->records[i].used=1; memcpy(p->records[i].id,id,sizeof(id));
    ++p->record_count; return LBPRE_OK;
}
uint64_t lbpre_registered_records(const lbpre_proxy *p) { return p?p->record_count:0; }
int lbpre_register_rekey(lbpre_proxy *p, const lbpre_rekey_cache *cache)
{
    if(!p || !cache || cache->ctx!=p->ctx) return LBPRE_ERR_ARGUMENT;
    size_t i=edge_slot(p,cache->edge), j=key_slot(p,cache->source);
    if(p->edges[i].used) return LBPRE_OK;
    if(p->keys[j].used && p->keys[j].rekey_count>=(UINT64_C(1)<<p->ctx->p->logM)) return LBPRE_ERR_BUDGET;
    if(p->edge_count>=p->edge_cap/2) {
        int ret=grow_edges(p); if(ret) return ret; i=edge_slot(p,cache->edge);
    }
    if(!p->keys[j].used && p->key_count>=p->key_cap/2) {
        int ret=grow_keys(p); if(ret) return ret; j=key_slot(p,cache->source);
    }
    if(!p->keys[j].used) {
        p->keys[j].used=1; memcpy(p->keys[j].id,cache->source,LBPRE_ID_BYTES); ++p->key_count;
    }
    ++p->keys[j].rekey_count;
    p->edges[i].used=1; memcpy(p->edges[i].id,cache->edge,LBPRE_ID_BYTES); ++p->edge_count;
    return LBPRE_OK;
}
uint64_t lbpre_registered_rekeys(const lbpre_proxy *p) { return p?p->edge_count:0; }
size_t lbpre_proxy_memory_bytes(const lbpre_proxy *p)
{ return p?sizeof(*p)+p->record_cap*sizeof(*p->records)+p->key_cap*sizeof(*p->keys)+p->edge_cap*sizeof(*p->edges)+p->pad_capacity*sizeof(*p->pads):0; }
int lbpre_proxy_set_pad_cache(lbpre_proxy *p, size_t capacity)
{
    if(!p) return LBPRE_ERR_ARGUMENT;
    if(capacity>SIZE_MAX/sizeof(pad_entry)) return LBPRE_ERR_MEMORY;
    pad_entry *next=capacity?calloc(capacity,sizeof(*next)):NULL;
    if(capacity && !next) return LBPRE_ERR_MEMORY;
    if(p->pads) { lbpre_secure_zero(p->pads,p->pad_capacity*sizeof(*p->pads)); free(p->pads); }
    p->pads=next; p->pad_capacity=capacity; return LBPRE_OK;
}
void lbpre_proxy_clear_pad_cache(lbpre_proxy *p)
{ if(p && p->pads) lbpre_secure_zero(p->pads,p->pad_capacity*sizeof(*p->pads)); }
void lbpre_pad_poly(const lbpre_rekey_cache *cache, uint64_t out[LBPRE_D], const uint8_t id[LBPRE_ID_BYTES])
{
    const lbpre_ctx *ctx=cache->ctx;
    sha3_t s; uint8_t seed[LBPRE_SEED_BYTES];
    lbpre_xof_begin(&s,"LatPRE-LMH-v1/REKEY-PAD");
    sha3_absorb(&s,cache->pad_seed,LBPRE_SEED_BYTES); sha3_absorb(&s,ctx->id,LBPRE_ID_BYTES);
    sha3_absorb(&s,cache->pad_domain,LBPRE_ID_BYTES);
    sha3_absorb(&s,id,LBPRE_ID_BYTES); sha3_pad(&s,SHAKE_PAD);
    sha3_squeeze(&s,seed,sizeof(seed)); sha3_clear(&s);
    /* Stack RNG avoids allocation/failure during a deterministic pad evaluation. */
    lbpre_rng rng; lbpre_xof_begin(&rng.xof,"LBPRE-v1/PAD-GAUSSIAN-STREAM");
    sha3_absorb(&rng.xof,seed,sizeof(seed)); sha3_pad(&rng.xof,SHAKE_PAD);
    lbpre_gaussian_poly(out,ctx->p->q,ctx->pad_gaussian,&rng);
    lbpre_secure_zero(seed,sizeof(seed)); lbpre_secure_zero(&rng,sizeof(rng));
}
void lbpre_cached_pad_poly(lbpre_proxy *p, const lbpre_rekey_cache *cache,
                          uint64_t out[LBPRE_D], const uint8_t id[LBPRE_ID_BYTES])
{
    /* A cache identifier binds both the rekey version and the source record. */
    uint8_t memo_id[LBPRE_ID_BYTES];
    sha3_t h; lbpre_xof_begin(&h,"LatPRE-LMH-v1/PAD-CACHE");
    sha3_absorb(&h,cache->edge,LBPRE_ID_BYTES); sha3_absorb(&h,id,LBPRE_ID_BYTES);
    sha3_pad(&h,SHAKE_PAD); sha3_squeeze(&h,memo_id,sizeof(memo_id)); sha3_clear(&h);
    pad_entry *entry=NULL;
    if(p->pad_capacity) {
        uint64_t x=0; for(unsigned i=0;i<8;++i) x|=(uint64_t)memo_id[i]<<(8*i);
        entry=&p->pads[x%p->pad_capacity];
        if(entry->used && !memcmp(entry->id,memo_id,LBPRE_ID_BYTES)) {
            memcpy(out,entry->value,sizeof(entry->value)); return;
        }
    }
    lbpre_pad_poly(cache,out,id);
    if(entry) {
        lbpre_secure_zero(entry,sizeof(*entry)); memcpy(entry->id,memo_id,LBPRE_ID_BYTES);
        memcpy(entry->value,out,sizeof(entry->value)); entry->used=1;
    }
}
