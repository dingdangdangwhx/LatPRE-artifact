#ifndef LBPRE_INTERNAL_H
#define LBPRE_INTERNAL_H
#include "lbpre.h"
#include "lbpre_ring.h"
#include "lbpre_sampling.h"
#define LBPRE_ID_BYTES 64
struct lbpre_ctx {
    const lbpre_params *p;
    lbpre_ring ring;
    uint64_t *a_ntt;
    uint8_t id[LBPRE_ID_BYTES];
    lbpre_gaussian *source_gaussian, *pad_gaussian;
};
struct lbpre_rekey_cache {
    const lbpre_ctx *ctx;
    uint8_t source[LBPRE_ID_BYTES], target[LBPRE_ID_BYTES];
    uint8_t edge[LBPRE_ID_BYTES], pad_seed[LBPRE_SEED_BYTES];
    uint8_t pad_domain[LBPRE_ID_BYTES]; /* public context/identities only; no RK matrix */
    uint64_t *columns_ntt, *target_ntt;
};
typedef struct { uint8_t id[LBPRE_ID_BYTES]; unsigned char used; } record_entry;
typedef struct { uint8_t id[LBPRE_ID_BYTES]; uint64_t count, rekey_count; unsigned char used; } key_entry;
typedef struct { uint8_t id[LBPRE_ID_BYTES]; uint64_t value[LBPRE_D]; unsigned char used; } pad_entry;
struct lbpre_proxy {
    const lbpre_ctx *ctx;
    record_entry *records;
    record_entry *edges;
    key_entry *keys;
    size_t record_cap, key_cap, key_count, edge_cap;
    uint64_t record_count, edge_count;
    pad_entry *pads;
    size_t pad_capacity;
};
void lbpre_pack_poly(uint8_t *out, const uint64_t in[LBPRE_D], unsigned bits);
void lbpre_unpack_poly(uint64_t out[LBPRE_D], const uint8_t *in, unsigned bits);
void lbpre_compress_poly(const lbpre_params *p, uint8_t *out,
                         const uint64_t in[LBPRE_D], unsigned bits);
void lbpre_decompress_poly(const lbpre_params *p, uint64_t out[LBPRE_D],
                           const uint8_t *in, unsigned bits);
int lbpre_valid_pk(const lbpre_ctx *ctx, const uint8_t *pk, size_t len);
int lbpre_valid_source(const lbpre_ctx *ctx, const uint8_t *ct, size_t len);
int lbpre_valid_exact(const lbpre_ctx *ctx, const uint8_t *in, size_t polys);
void lbpre_public_key_id(const lbpre_ctx *ctx, uint8_t out[LBPRE_ID_BYTES], const uint8_t *pk);
void lbpre_record_id(const lbpre_ctx *ctx, uint8_t out[LBPRE_ID_BYTES],
                     const uint8_t *pk, const uint8_t *ct);
int lbpre_registry_has(const lbpre_proxy *proxy, const uint8_t id[LBPRE_ID_BYTES]);
void lbpre_pad_poly(const lbpre_rekey_cache *cache, uint64_t out[LBPRE_D],
                    const uint8_t id[LBPRE_ID_BYTES]);
void lbpre_cached_pad_poly(lbpre_proxy *proxy, const lbpre_rekey_cache *cache,
                          uint64_t out[LBPRE_D], const uint8_t id[LBPRE_ID_BYTES]);
#endif
