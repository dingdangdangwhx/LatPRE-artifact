#ifndef LBPRE_H
#define LBPRE_H
#include <stddef.h>
#include <stdint.h>
#define LBPRE_D 256
#define LBPRE_SEED_BYTES 32
#define LBPRE_MESSAGE_BYTES 32
enum { LBPRE_OK=0, LBPRE_ERR_ARGUMENT=-1, LBPRE_ERR_MEMORY=-2,
       LBPRE_ERR_ENCODING=-3, LBPRE_ERR_UNREGISTERED=-4,
       LBPRE_ERR_BUDGET=-5, LBPRE_ERR_RANDOM=-6 };
typedef struct {
    const char *name;
    unsigned logQ, logM, k, ell, q_bits, base, length, source_v_bits, re_u_bits, re_v_bits;
    uint64_t q;
    /* Independent centered binomial laws: sum_eta (Bernoulli-Bernoulli). */
    unsigned source_eta, internal_eta, terminal_eta;
    /* Exact decimal SD proxies from the frozen archive. The width strings
     * below are generated with 400-bit-or-better relative precision. */
    const char *source_std, *pad_std;
    /* sigma_terminal is NULL for the current CBD-only terminal profiles. */
    const char *sigma_source, *sigma_terminal, *sigma_pad;
} lbpre_params;
typedef struct lbpre_ctx lbpre_ctx;
typedef struct lbpre_rng lbpre_rng;
typedef struct lbpre_proxy lbpre_proxy;
typedef struct lbpre_rekey_cache lbpre_rekey_cache;
const lbpre_params *lbpre_params_get(unsigned logQ);
const lbpre_params *lbpre_params_named(const char *name);
const char *lbpre_parameter_profile_id(void);
size_t lbpre_public_key_bytes(const lbpre_params *p);
size_t lbpre_secret_key_bytes(const lbpre_params *p);
size_t lbpre_source_bytes(const lbpre_params *p);
size_t lbpre_terminal_bytes(const lbpre_params *p);
size_t lbpre_rekey_bytes(const lbpre_params *p);
size_t lbpre_rekey_body_bytes(const lbpre_params *p);
size_t lbpre_public_matrix_bytes(const lbpre_params *p);
lbpre_rng *lbpre_rng_new(const uint8_t seed[LBPRE_SEED_BYTES]);
void lbpre_rng_free(lbpre_rng *rng);
int lbpre_random_seed(uint8_t seed[LBPRE_SEED_BYTES]);
lbpre_ctx *lbpre_setup(unsigned logQ, const uint8_t matrix_seed[LBPRE_SEED_BYTES]);
/* Named selection also distinguishes supplementary sets sharing the same Q. */
lbpre_ctx *lbpre_setup_named(const char *name, const uint8_t matrix_seed[LBPRE_SEED_BYTES]);
void lbpre_ctx_free(lbpre_ctx *ctx);
const lbpre_params *lbpre_ctx_params(const lbpre_ctx *ctx);
int lbpre_export_matrix(const lbpre_ctx *ctx, uint8_t *out, size_t outlen);
int lbpre_keygen(const lbpre_ctx *ctx, uint8_t *pk, size_t pklen,
                uint8_t *sk, size_t sklen, lbpre_rng *rng);
int lbpre_encrypt(const lbpre_ctx *ctx, uint8_t *ct, size_t ctlen,
                  const uint8_t *pk, size_t pklen,
                  const uint8_t message[LBPRE_MESSAGE_BYTES], lbpre_rng *rng);
int lbpre_decrypt_source(const lbpre_ctx *ctx, uint8_t message[LBPRE_MESSAGE_BYTES],
                        const uint8_t *ct, size_t ctlen,
                        const uint8_t *sk, size_t sklen);
int lbpre_rekeygen(const lbpre_ctx *ctx, uint8_t *rk, size_t rklen,
                  const uint8_t *source_sk, size_t sklen,
                  const uint8_t *target_pk, size_t pklen, lbpre_rng *rng);
lbpre_rekey_cache *lbpre_rekey_prepare(const lbpre_ctx *ctx,
                  const uint8_t *rk, size_t rklen,
                  const uint8_t *source_pk, size_t sourcelen,
                  const uint8_t *target_pk, size_t targetlen);
void lbpre_rekey_cache_free(lbpre_rekey_cache *cache);
size_t lbpre_rekey_cache_memory_bytes(const lbpre_rekey_cache *cache);
/* No global proxy key. Admission/quota state plus an optional sensitive pad cache. */
lbpre_proxy *lbpre_proxy_new(const lbpre_ctx *ctx);
void lbpre_proxy_free(lbpre_proxy *proxy);
/* Trusted registration of honestly generated source records; not a validity proof. */
int lbpre_register(lbpre_proxy *proxy, const uint8_t *source_pk, size_t pklen,
                   const uint8_t *ct, size_t ctlen);
uint64_t lbpre_registered_records(const lbpre_proxy *proxy);
/* Admit an honestly generated rekey version, idempotently. ReEnc also calls
 * this wrapper. Durable, shared lifetime Q/M accounting is the caller's job. */
int lbpre_register_rekey(lbpre_proxy *proxy, const lbpre_rekey_cache *cache);
uint64_t lbpre_registered_rekeys(const lbpre_proxy *proxy);
size_t lbpre_proxy_memory_bytes(const lbpre_proxy *proxy);
/* Optional bounded memoization of fixed pads. Zero capacity disables it.
 * This never caches the fresh internal encryption or its coins. */
int lbpre_proxy_set_pad_cache(lbpre_proxy *proxy, size_t capacity);
void lbpre_proxy_clear_pad_cache(lbpre_proxy *proxy);
int lbpre_reencrypt(lbpre_proxy *proxy, uint8_t *ct, size_t ctlen,
                    const lbpre_rekey_cache *cache,
                    const uint8_t *source_pk, size_t sourcelen,
                    const uint8_t *target_pk, size_t targetlen,
                    const uint8_t *source_ct, size_t sourcctlen, lbpre_rng *rng);
int lbpre_decrypt_terminal(const lbpre_ctx *ctx, uint8_t message[LBPRE_MESSAGE_BYTES],
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t *sk, size_t sklen);
const char *lbpre_backend(void);
const char *lbpre_parameter_source_sha256(void);
#endif
