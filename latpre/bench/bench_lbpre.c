#define _POSIX_C_SOURCE 200809L
#include "lbpre.h"
#include "lbpre_sampling.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

/* Public serialized-API timings; no crypto operation is implemented here. */
typedef enum {
    OP_SETUP, OP_EXPORT_MATRIX, OP_KEYGEN, OP_ENCRYPT, OP_DECRYPT_SOURCE,
    OP_REKEYGEN, OP_REKEY_PREPARE, OP_REKEYGEN_PREPARED, OP_PROXY_NEW, OP_REGISTER,
    OP_REENCRYPT, OP_REENCRYPT_CACHED_PAD, OP_DECRYPT_TERMINAL, OP_COUNT
} operation;
static const char *OP_NAMES[OP_COUNT] = {
    "Setup", "ExportMatrix", "KeyGen", "Enc", "DecSource", "ReKeyGen",
    "ReKeyPrepare", "ReKeyGenPrepared", "ProxyNew", "Register", "ReEnc", "ReEncCachedPad", "DecTerminal"
};
typedef struct {
    unsigned logQ, base;
    uint64_t q;
    size_t pk, sk, matrix, rk, source, terminal;
} expected_sizes;
/* Independently frozen selected-profile wire-size expectations. */
static const expected_sizes EXPECTED[] = {
    {20, 643, UINT64_C(265753601), 8960, 7168, 17920, 53792, 3808, 1824},
    {30, 3241, UINT64_C(34016143361), 13440, 11200, 33600, 100832, 5792, 2240},
    {40, 2086641, UINT64_C(4354066046977), 18816, 16128, 56448, 112928, 8320, 2912},
};
#define PROFILE_COUNT (sizeof(EXPECTED) / sizeof(EXPECTED[0]))
typedef struct {
    const lbpre_params *p;
    lbpre_ctx *ctx, *temporary_ctx;
    lbpre_rng *rng;
    lbpre_proxy *proxy, *cached_proxy, *temporary_proxy;
    lbpre_rekey_cache *cache, *temporary_cache;
    uint8_t matrix_seed[LBPRE_SEED_BYTES];
    uint8_t message[LBPRE_MESSAGE_BYTES], decoded[LBPRE_MESSAGE_BYTES];
    uint8_t *pk_a, *pk_b, *sk_a, *sk_b, *source, *terminal, *rk;
    uint8_t *work_pk, *work_sk, *work_source, *work_rk, *matrix;
    size_t pklen, sklen, sourcelen, terminal_len, rklen, matrix_len;
} fixture;
typedef struct {
    unsigned logQ, logM, base, k, ell, q_bits;
    const char *name;
    uint64_t q;
    operation op;
    size_t count, warmup, pklen, sklen, matrix_len, rklen, sourcelen, terminal_len;
    size_t cache_memory, proxy_memory, cached_proxy_memory;
    uint64_t *samples, minimum, median, p95;
    double mean;
} result;
static volatile uint64_t checksum;
static uint32_t timer_numer = 1, timer_denom = 1;

static const char *timer_name(void) {
#ifdef __APPLE__
    return "mach_absolute_time";
#else
    return "CLOCK_MONOTONIC";
#endif
}

static void die(const char *message) {
    fprintf(stderr, "bench_lbpre: %s\n", message);
    exit(EXIT_FAILURE);
}

static void *allocate(size_t len) {
    void *p = calloc(1, len);
    if (p == NULL) die("allocation failed");
    return p;
}

static uint64_t monotonic_ns(void) {
#ifdef __APPLE__
    return (uint64_t)((__uint128_t)mach_absolute_time() * timer_numer / timer_denom);
#else
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) die("clock_gettime failed");
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
#endif
}

static void seed_bytes(uint8_t seed[LBPRE_SEED_BYTES], unsigned logQ, unsigned domain) {
    size_t i;
    for (i = 0; i < LBPRE_SEED_BYTES; i++)
        seed[i] = (uint8_t)(13U * i + 19U * domain + logQ);
}

static void fixture_init(fixture *f, const expected_sizes *e) {
    uint8_t seed[LBPRE_SEED_BYTES];
    size_t i;
    memset(f, 0, sizeof(*f));
    f->p = lbpre_params_get(e->logQ);
    if (f->p == NULL || f->p->q != e->q || f->p->base != e->base) die("parameter identity mismatch");
    seed_bytes(f->matrix_seed, e->logQ, 1);
    seed_bytes(seed, e->logQ, 3);
    f->ctx = lbpre_setup(e->logQ, f->matrix_seed);
    f->rng = lbpre_rng_new(seed);
    if (f->ctx == NULL || f->rng == NULL) die("fixture Setup/RNG failed");
    f->pklen = lbpre_public_key_bytes(f->p); f->sklen = lbpre_secret_key_bytes(f->p);
    f->sourcelen = lbpre_source_bytes(f->p); f->terminal_len = lbpre_terminal_bytes(f->p);
    f->rklen = lbpre_rekey_bytes(f->p); f->matrix_len = lbpre_public_matrix_bytes(f->p);
    if (f->pklen != e->pk || f->sklen != e->sk || f->matrix_len != e->matrix
        || f->rklen != e->rk || f->sourcelen != e->source || f->terminal_len != e->terminal)
        die("wire sizes disagree with selected profile expectations");
    f->pk_a = allocate(f->pklen); f->pk_b = allocate(f->pklen);
    f->sk_a = allocate(f->sklen); f->sk_b = allocate(f->sklen);
    f->source = allocate(f->sourcelen); f->terminal = allocate(f->terminal_len);
    f->rk = allocate(f->rklen); f->work_pk = allocate(f->pklen); f->work_sk = allocate(f->sklen);
    f->work_source = allocate(f->sourcelen); f->work_rk = allocate(f->rklen);
    f->matrix = allocate(f->matrix_len);
    for (i = 0; i < LBPRE_MESSAGE_BYTES; i++) f->message[i] = (uint8_t)(i * 31U + e->logQ);
    if (lbpre_keygen(f->ctx, f->pk_a, f->pklen, f->sk_a, f->sklen, f->rng) != LBPRE_OK
        || lbpre_keygen(f->ctx, f->pk_b, f->pklen, f->sk_b, f->sklen, f->rng) != LBPRE_OK
        || lbpre_encrypt(f->ctx, f->source, f->sourcelen, f->pk_a, f->pklen, f->message, f->rng) != LBPRE_OK
        || lbpre_rekeygen(f->ctx, f->rk, f->rklen, f->sk_a, f->sklen, f->pk_b, f->pklen, f->rng) != LBPRE_OK)
        die("fixture key generation/encryption failed");
    f->cache = lbpre_rekey_prepare(f->ctx, f->rk, f->rklen, f->pk_a, f->pklen, f->pk_b, f->pklen);
    f->proxy = lbpre_proxy_new(f->ctx);
    f->cached_proxy = lbpre_proxy_new(f->ctx);
    if (f->cache == NULL || f->proxy == NULL
        || f->cached_proxy == NULL || lbpre_proxy_set_pad_cache(f->cached_proxy, 1) != LBPRE_OK
        || lbpre_register(f->proxy, f->pk_a, f->pklen, f->source, f->sourcelen) != LBPRE_OK
        || lbpre_register(f->cached_proxy, f->pk_a, f->pklen, f->source, f->sourcelen) != LBPRE_OK
        || lbpre_reencrypt(f->proxy, f->terminal, f->terminal_len, f->cache,
             f->pk_a, f->pklen, f->pk_b, f->pklen, f->source, f->sourcelen, f->rng) != LBPRE_OK
        || lbpre_reencrypt(f->cached_proxy, f->terminal, f->terminal_len, f->cache,
             f->pk_a, f->pklen, f->pk_b, f->pklen, f->source, f->sourcelen, f->rng) != LBPRE_OK)
        die("fixture cache/proxy/RE failed");
}

static void fixture_free(fixture *f) {
    lbpre_rekey_cache_free(f->cache); lbpre_proxy_free(f->proxy); lbpre_proxy_free(f->cached_proxy);
    lbpre_rng_free(f->rng); lbpre_ctx_free(f->ctx);
    free(f->pk_a); free(f->pk_b); free(f->sk_a); free(f->sk_b);
    free(f->source); free(f->terminal); free(f->rk);
    free(f->work_pk); free(f->work_sk); free(f->work_source); free(f->work_rk); free(f->matrix);
}

/* Registration is measured for one fresh record in an empty registry. Proxy
 * construction is excluded from Register and separately timed as ProxyNew. */
static void prepare_operation(fixture *f, operation op) {
    if (op == OP_REGISTER) {
        f->temporary_proxy = lbpre_proxy_new(f->ctx);
        if (f->temporary_proxy == NULL) die("Register fixture allocation failed");
    }
}

static int invoke(fixture *f, operation op) {
    switch (op) {
    case OP_SETUP:
        f->temporary_ctx = lbpre_setup(f->p->logQ, f->matrix_seed);
        return f->temporary_ctx == NULL ? LBPRE_ERR_MEMORY : LBPRE_OK;
    case OP_EXPORT_MATRIX:
        return lbpre_export_matrix(f->ctx, f->matrix, f->matrix_len);
    case OP_KEYGEN:
        return lbpre_keygen(f->ctx, f->work_pk, f->pklen, f->work_sk, f->sklen, f->rng);
    case OP_ENCRYPT:
        return lbpre_encrypt(f->ctx, f->work_source, f->sourcelen, f->pk_a, f->pklen, f->message, f->rng);
    case OP_DECRYPT_SOURCE:
        return lbpre_decrypt_source(f->ctx, f->decoded, f->source, f->sourcelen, f->sk_a, f->sklen);
    case OP_REKEYGEN:
        return lbpre_rekeygen(f->ctx, f->work_rk, f->rklen, f->sk_a, f->sklen, f->pk_b, f->pklen, f->rng);
    case OP_REKEY_PREPARE:
        f->temporary_cache = lbpre_rekey_prepare(f->ctx, f->rk, f->rklen,
                                               f->pk_a, f->pklen, f->pk_b, f->pklen);
        return f->temporary_cache == NULL ? LBPRE_ERR_MEMORY : LBPRE_OK;
    case OP_REKEYGEN_PREPARED: {
        int status = lbpre_rekeygen(f->ctx, f->work_rk, f->rklen,
                f->sk_a, f->sklen, f->pk_b, f->pklen, f->rng);
        if (status != LBPRE_OK) return status;
        f->temporary_cache = lbpre_rekey_prepare(f->ctx, f->work_rk, f->rklen,
                                               f->pk_a, f->pklen, f->pk_b, f->pklen);
        return f->temporary_cache == NULL ? LBPRE_ERR_MEMORY : LBPRE_OK;
    }
    case OP_PROXY_NEW:
        f->temporary_proxy = lbpre_proxy_new(f->ctx);
        return f->temporary_proxy == NULL ? LBPRE_ERR_MEMORY : LBPRE_OK;
    case OP_REGISTER:
        return lbpre_register(f->temporary_proxy, f->pk_a, f->pklen, f->source, f->sourcelen);
    case OP_REENCRYPT:
        return lbpre_reencrypt(f->proxy, f->terminal, f->terminal_len, f->cache,
                              f->pk_a, f->pklen, f->pk_b, f->pklen, f->source, f->sourcelen, f->rng);
    case OP_REENCRYPT_CACHED_PAD:
        return lbpre_reencrypt(f->cached_proxy, f->terminal, f->terminal_len, f->cache,
                              f->pk_a, f->pklen, f->pk_b, f->pklen, f->source, f->sourcelen, f->rng);
    case OP_DECRYPT_TERMINAL:
        return lbpre_decrypt_terminal(f->ctx, f->decoded, f->terminal, f->terminal_len, f->sk_b, f->sklen);
    default:
        return LBPRE_ERR_ARGUMENT;
    }
}

static void finish_operation(fixture *f, operation op) {
    if (op == OP_SETUP) {
        lbpre_ctx_free(f->temporary_ctx); f->temporary_ctx = NULL;
    } else if (op == OP_REKEY_PREPARE || op == OP_REKEYGEN_PREPARED) {
        lbpre_rekey_cache_free(f->temporary_cache); f->temporary_cache = NULL;
    } else if (op == OP_PROXY_NEW || op == OP_REGISTER) {
        if (op == OP_REGISTER && lbpre_registered_records(f->temporary_proxy) != 1)
            die("Register count mismatch");
        lbpre_proxy_free(f->temporary_proxy); f->temporary_proxy = NULL;
    } else if (op == OP_DECRYPT_SOURCE || op == OP_DECRYPT_TERMINAL) {
        if (memcmp(f->decoded, f->message, LBPRE_MESSAGE_BYTES) != 0) die("decryption mismatch");
        checksum ^= f->decoded[0];
    } else if (op == OP_REENCRYPT || op == OP_REENCRYPT_CACHED_PAD) {
        if (lbpre_decrypt_terminal(f->ctx, f->decoded, f->terminal, f->terminal_len,
                                   f->sk_b, f->sklen) != LBPRE_OK
            || memcmp(f->decoded, f->message, LBPRE_MESSAGE_BYTES) != 0)
            die("ReEnc output failed decryption");
        checksum ^= f->terminal[0];
    } else {
        checksum ^= f->work_pk[0] ^ f->work_source[0] ^ f->work_rk[0];
    }
}

static int compare_u64(const void *a, const void *b) {
    uint64_t left = *(const uint64_t *)a, right = *(const uint64_t *)b;
    return (left > right) - (left < right);
}

static result benchmark(fixture *f, operation op, size_t count, size_t warmup) {
    result r;
    uint64_t *sorted;
    long double sum = 0;
    size_t i, p95_index;
    memset(&r, 0, sizeof(r));
    r.logQ = f->p->logQ; r.logM = f->p->logM; r.name = f->p->name; r.base = f->p->base; r.k = f->p->k; r.ell = f->p->ell;
    r.q = f->p->q; r.q_bits = f->p->q_bits; r.op = op; r.count = count; r.warmup = warmup;
    r.pklen = f->pklen; r.sklen = f->sklen; r.matrix_len = f->matrix_len;
    r.rklen = f->rklen; r.sourcelen = f->sourcelen; r.terminal_len = f->terminal_len;
    r.samples = allocate(count * sizeof(*r.samples));
    for (i = 0; i < count + warmup; i++) {
        uint64_t start, end;
        int status;
        prepare_operation(f, op);
        start = monotonic_ns();
        status = invoke(f, op);
        end = monotonic_ns();
        if (status != LBPRE_OK) {
            fprintf(stderr, "bench_lbpre: logQ=%u %s sample=%zu returned %d\n",
                    r.logQ, OP_NAMES[op], i, status);
            exit(EXIT_FAILURE);
        }
        finish_operation(f, op);
        if (end < start) die("monotonic clock went backwards");
        if (i >= warmup) r.samples[i - warmup] = end - start;
    }
    sorted = allocate(count * sizeof(*sorted));
    memcpy(sorted, r.samples, count * sizeof(*sorted));
    qsort(sorted, count, sizeof(*sorted), compare_u64);
    r.minimum = sorted[0];
    r.median = count % 2 ? sorted[count / 2]
        : sorted[count / 2 - 1] / 2 + sorted[count / 2] / 2
            + (sorted[count / 2 - 1] % 2 + sorted[count / 2] % 2) / 2;
    p95_index = (95 * count + 99) / 100 - 1;
    r.p95 = sorted[p95_index];
    for (i = 0; i < count; i++) sum += r.samples[i];
    r.mean = (double)(sum / count);
    r.cache_memory = lbpre_rekey_cache_memory_bytes(f->cache);
    r.proxy_memory = lbpre_proxy_memory_bytes(f->proxy);
    r.cached_proxy_memory = lbpre_proxy_memory_bytes(f->cached_proxy);
    free(sorted);
    fprintf(stderr, "logQ=%u %-14s median=%.6f ms min=%.6f ms p95=%.6f ms\n",
            r.logQ, OP_NAMES[op], r.median / 1e6, r.minimum / 1e6, r.p95 / 1e6);
    return r;
}

static void json_string(FILE *out, const char *text) {
    const unsigned char *p = (const unsigned char *)text;
    fputc('"', out);
    while (*p) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
        p++;
    }
    fputc('"', out);
}

static void csv_string(FILE *out, const char *text) {
    fputc('"', out);
    while (*text) { if (*text == '"') fputc('"', out); fputc(*text++, out); }
    fputc('"', out);
}

static void output_csv(FILE *out, const result *rows, size_t count) {
    size_t i;
    fputs("logQ,q,q_bits,k,ell,base,operation,samples,warmup,min_ns,median_ns,p95_ns,mean_ns,"
          "PK_bytes,SK_bytes,RK_bytes,source_bytes,RE_bytes,global_A_bytes,"
          "prepared_rekey_RAM_bytes,proxy_RAM_one_record_bytes,proxy_cached_pad_RAM_one_record_bytes,backend,gaussian_sampler,gaussian_sampler_is_approximate,gaussian_target,gaussian_sampler_error_bound_certified,parameter_sha256,profile,logM,RK_body_bytes,RK_seed_bytes\n", out);
    for (i = 0; i < count; i++) {
        const result *r = rows + i;
        fprintf(out, "%u,%" PRIu64 ",%u,%u,%u,%u,%s,%zu,%zu,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.3f,"
                "%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,", r->logQ, r->q, r->q_bits, r->k, r->ell, r->base,
                OP_NAMES[r->op], r->count, r->warmup, r->minimum, r->median, r->p95, r->mean,
                r->pklen, r->sklen, r->rklen, r->sourcelen, r->terminal_len, r->matrix_len,
                r->cache_memory, r->proxy_memory, r->cached_proxy_memory);
        csv_string(out, lbpre_backend()); fputc(',', out);
        csv_string(out, lbpre_gaussian_backend());
        fprintf(out, ",%d,", lbpre_gaussian_is_approximate());
        csv_string(out, lbpre_gaussian_target());
        fprintf(out, ",%d,", lbpre_gaussian_has_certified_error_bound());
        csv_string(out, lbpre_parameter_source_sha256());
        fprintf(out, ",%s,%u,%zu,32\n", r->name, r->logM, r->rklen - 32u);
    }
}

static void output_json(FILE *out, const result *rows, size_t count, int argc, char **argv) {
    struct utsname host;
    size_t i, j;
    fputs("{\n  \"schema\":\"lbpre-public-api-benchmark-v3\",\n  \"clock\":", out);
    json_string(out, timer_name());
    fprintf(out, ",\n  \"clock_tick_numer\":%u,\n  \"clock_tick_denom\":%u,\n", timer_numer, timer_denom);
    fputs("  \"time_unit\":\"nanoseconds\",\n  \"deterministic_benchmark_seeds\":true,\n"
          "  \"rng_construction_timed\":false,\n  \"cryptographic_sampling_timed\":true,\n"
          "  \"public_api_serialization_timed\":true,\n  \"reenc_prepared_rekey\":true,\n"
          "  \"six_algorithm_rekeygen_operation\":\"ReKeyGen\",\n"
          "  \"rekeygen_prepared_scope\":\"wire rekey generation plus one edge NTT preparation measured together\",\n"
          "  \"reenc_default_pad_memoization\":false,\n  \"reenc_cached_pad_capacity\":1,\n"
          "  \"register_registry_state\":\"fresh empty proxy, one honest record; ProxyNew excluded\",\n"
          "  \"proxy_memory_state\":\"one registered source record; pad memoization disabled\",\n"
          "  \"proxy_cached_memory_state\":\"one registered source record; capacity-one pad cache populated before timing\",\n"
          "  \"backend\":", out);
    json_string(out, lbpre_backend());
    fputs(",\n  \"gaussian_sampler\":", out); json_string(out, lbpre_gaussian_backend());
    fprintf(out, ",\n  \"gaussian_sampler_is_approximate\":%s,\n  \"ideal_discrete_gaussian_bounds_applicable\":%s",
            lbpre_gaussian_is_approximate()?"true":"false",
            lbpre_gaussian_has_certified_error_bound()?"true":"false");
    fputs(",\n  \"gaussian_target\":", out); json_string(out, lbpre_gaussian_target());
    fprintf(out, ",\n  \"gaussian_sampler_error_bound_certified\":%s",
            lbpre_gaussian_has_certified_error_bound()?"true":"false");
    fputs(",\n  \"parameter_sha256\":", out); json_string(out, lbpre_parameter_source_sha256());
    fputs(",\n  \"profile_id\":", out); json_string(out, lbpre_parameter_profile_id());
    fputs(",\n  \"proxy_secret\":false,\n  \"rekey_seed_bytes\":32", out);
    fputs(",\n  \"compiler\":", out); json_string(out, __VERSION__);
    fputs(",\n  \"build_timestamp\":", out); json_string(out, __DATE__ " " __TIME__);
    fputs(",\n  \"host\":", out);
    if (uname(&host) == 0) {
        fputs("{\"system\":", out); json_string(out, host.sysname);
        fputs(",\"release\":", out); json_string(out, host.release);
        fputs(",\"architecture\":", out); json_string(out, host.machine); fputc('}', out);
    } else fputs("null", out);
    fputs(",\n  \"command\":[", out);
    for (i = 0; i < (size_t)argc; i++) { if (i) fputc(',', out); json_string(out, argv[i]); }
    fputs("],\n  \"results\":[\n", out);
    for (i = 0; i < count; i++) {
        const result *r = rows + i;
        if (i) fputs(",\n", out);
        fprintf(out, "    {\"logQ\":%u,\"q\":%" PRIu64 ",\"q_bits\":%u,\"k\":%u,\"ell\":%u,\"base\":%u,\"operation\":",
                r->logQ, r->q, r->q_bits, r->k, r->ell, r->base);
        json_string(out, OP_NAMES[r->op]);
        fprintf(out, ",\"profile\":\"%s\",\"logM\":%u,\"RK_body_bytes\":%zu,\"RK_seed_bytes\":32", r->name, r->logM, r->rklen-32u);
        fprintf(out, ",\"samples\":%zu,\"warmup\":%zu,\"min_ns\":%" PRIu64 ",\"median_ns\":%" PRIu64
                ",\"p95_ns\":%" PRIu64 ",\"mean_ns\":%.3f,\"PK_bytes\":%zu,\"SK_bytes\":%zu,"
                "\"RK_bytes\":%zu,\"source_bytes\":%zu,\"RE_bytes\":%zu,\"global_A_bytes\":%zu,"
                "\"prepared_rekey_RAM_bytes\":%zu,\"proxy_RAM_one_record_bytes\":%zu,"
                "\"proxy_cached_pad_RAM_one_record_bytes\":%zu,\"samples_ns\":[",
                r->count, r->warmup, r->minimum, r->median, r->p95, r->mean,
                r->pklen, r->sklen, r->rklen, r->sourcelen, r->terminal_len, r->matrix_len,
                r->cache_memory, r->proxy_memory, r->cached_proxy_memory);
        for (j = 0; j < r->count; j++) { if (j) fputc(',', out); fprintf(out, "%" PRIu64, r->samples[j]); }
        fputs("]}", out);
    }
    fprintf(out, "\n  ],\n  \"checksum\":%" PRIu64 "\n}\n", checksum);
}

static unsigned long number(const char *text, unsigned long maximum) {
    char *end;
    unsigned long value;
    errno = 0; value = strtoul(text, &end, 10);
    if (errno || !*text || *end || value > maximum) die("invalid numeric option");
    return value;
}

static void choose_logQ(const char *text, unsigned selected[PROFILE_COUNT]) {
    const char *start = text;
    memset(selected, 0, PROFILE_COUNT * sizeof(*selected));
    while (*start) {
        char *end;
        unsigned long value = strtoul(start, &end, 10);
        size_t i;
        if (end == start || (*end && *end != ',')) die("--logQ expects 20,30,40 or a subset");
        for (i = 0; i < PROFILE_COUNT && EXPECTED[i].logQ != value; i++) { }
        if (i == PROFILE_COUNT) die("unsupported --logQ value");
        selected[i] = 1;
        if (!*end) break;
        start = end + 1;
        if (!*start) die("trailing comma in --logQ");
    }
    if (start == text && !*text) die("empty --logQ");
}

int main(int argc, char **argv) {
    size_t samples = 1000, warmup = 10, count = 0, i;
    int all_operations = 0;
    unsigned selected[PROFILE_COUNT] = {1, 1, 1};
    const char *csv_path = "-", *json_path = NULL;
    FILE *csv, *json;
    result *rows = allocate(PROFILE_COUNT * OP_COUNT * sizeof(*rows));
#ifdef __APPLE__
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || !timebase.denom)
        die("mach_timebase_info failed");
    timer_numer = timebase.numer; timer_denom = timebase.denom;
#endif
    for (i = 1; i < (size_t)argc; i++) {
        if (!strcmp(argv[i], "--help")) {
            puts("Usage: bench_lbpre [--samples 1000] [--warmup 10] [--logQ 20,30,40] [--csv FILE|-] [--json FILE|-] [--all-operations]");
            free(rows); return EXIT_SUCCESS;
        }
        if (!strcmp(argv[i], "--all-operations")) { all_operations = 1; continue; }
        if (i + 1 == (size_t)argc) die("option needs a value");
        if (!strcmp(argv[i], "--samples")) samples = number(argv[++i], 100000);
        else if (!strcmp(argv[i], "--warmup")) warmup = number(argv[++i], 100000);
        else if (!strcmp(argv[i], "--logQ")) { choose_logQ(argv[++i], selected); }
        else if (!strcmp(argv[i], "--csv")) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--json")) json_path = argv[++i];
        else die("unknown option");
    }
    if (!samples) die("--samples must be positive");
    if (json_path && !strcmp(csv_path, "-") && !strcmp(json_path, "-")) die("CSV and JSON cannot both use stdout");
    for (i = 0; i < PROFILE_COUNT; i++) if (selected[i]) {
        fixture f;
        operation op;
        fixture_init(&f, EXPECTED + i);
        for (op = OP_SETUP; op < OP_COUNT; op++) {
            if (!all_operations && op != OP_SETUP && op != OP_KEYGEN && op != OP_ENCRYPT
                    && op != OP_REKEYGEN && op != OP_REENCRYPT && op != OP_DECRYPT_TERMINAL)
                continue;
            rows[count++] = benchmark(&f, op, samples, warmup);
        }
        fixture_free(&f);
    }
    csv = !strcmp(csv_path, "-") ? stdout : fopen(csv_path, "w");
    if (csv == NULL) die("cannot open CSV output");
    output_csv(csv, rows, count);
    if (csv != stdout && fclose(csv) != 0) die("CSV close failed");
    if (json_path) {
        json = !strcmp(json_path, "-") ? stdout : fopen(json_path, "w");
        if (json == NULL) die("cannot open JSON output");
        output_json(json, rows, count, argc, argv);
        if (json != stdout && fclose(json) != 0) die("JSON close failed");
    }
    for (i = 0; i < count; i++) free(rows[i].samples);
    free(rows);
    return EXIT_SUCCESS;
}
