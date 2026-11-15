/* OpenFHE CDF/Karney regression tests with independently calculated SHAKE
 * known-answer vectors, finite-grid endpoint checks and frozen profiles.
 * These tests do not certify statistical distance or security. */
#include "lbpre_sampling.h"
#include <assert.h>
#include <fenv.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef LBPRE_GAUSSIAN_OPENFHE
#error "This test requires GAUSSIAN=openfhe"
#endif

typedef struct {
    const char *width;
    uint64_t radius;
    const char *following_rng_bytes;
    int64_t sample[32];
} independent_kat;

static const independent_kat KATS[] = {
    {"2.0", 10, "924948a0eaf13d5ba0fe59777689f4fb",
     {0,0,1,-1,0,0,-2,-1,0,0,-1,-1,0,1,0,0,
      -1,-1,1,0,-1,1,1,0,1,0,1,0,0,-1,-1,0}},
    {"751.98847988267198", 3602, "924948a0eaf13d5ba0fe59777689f4fb",
     {40,-62,445,-416,86,-40,-704,-582,-8,145,-476,-232,-61,395,-114,-140,
      -234,-428,212,-42,-310,380,344,196,238,169,343,-200,-121,-422,-347,183}},
    {"751.98848238930021", INT64_MAX, "ec89efd18f1f50b1e7603b863ad39e8d",
     {-32,-196,-280,-534,704,267,399,213,-361,-436,-74,-197,-344,-3,314,268,
      76,-654,-188,65,-88,-194,-236,590,224,134,-104,-147,153,45,124,168}},
    {"751.98848489592842", INT64_MAX, "d2fe378d97a80d345cc55a483a1becf8",
     {-70,-131,-61,-312,-301,135,467,243,-478,-222,-386,143,-282,-304,147,113,
      29,10,200,-169,362,-34,-135,98,154,-124,-66,-53,-185,393,-264,-294}},
    {"3.757287713530579173645676583010735349905182628242270780933942406566071410933e8",
     INT64_MAX, "88d3ec99effff035a95d6b2a78169f3c",
     {-60679045,-24615730,-3536766,-229749549,-157670291,139165486,51030836,-47517632,
      -152095090,-158964540,-37316588,155633181,133027896,2774211,144223805,-39813397,
      34213871,-107753314,-142946321,72353696,28360141,44366257,-3067519,-165386464,
      -132715862,85954853,117242558,-63466408,-81564509,-26565301,-25713268,83131639}},
    {"1099511627776", INT64_MAX, "d85ee6c75c86b8031acf094fddccc2d6",
     {-165570100204,-410009724268,-204550240454,-453266141310,1073358252420,285065399494,
      360083626332,-642868886776,-105931053346,-632299704343,4313978433,-45954915390,
      568535828764,415147696550,378050537265,-944189689577,-52191558090,98753410645,
      -434449720879,-357124264596,62854205552,21265991631,115685120304,-313494573220,
      -155218405376,65163943322,-6670683856,-291888255010,782226248730,-763419180956,
      -81801344884,-163802691198}}
};

static lbpre_rng *new_rng(unsigned tag)
{
    uint8_t seed[LBPRE_SEED_BYTES] = {0};
    lbpre_rng *rng;
    seed[0] = (uint8_t)tag;
    rng = lbpre_rng_new(seed);
    assert(rng != NULL);
    return rng;
}

static uint64_t residue(int64_t x, uint64_t q)
{
    uint64_t magnitude;
    assert(x != INT64_MIN);
    magnitude = (uint64_t)(x < 0 ? -x : x) % q;
    return x < 0 && magnitude ? q - magnitude : magnitude;
}

static void invalid_inputs_and_environment(void)
{
    static const char *bad[] = {NULL,"","0","-1","nan","inf","NaN","1x","1e100",
        "18014398509481988","0x1p2"," 2","2 ","1e","2,0","1e-9999","1e-200"};
    lbpre_gaussian *g;
    size_t i;
    int original = fegetround();
    assert(original == FE_TONEAREST);
    for (i = 0; i < sizeof(bad)/sizeof(bad[0]); i++)
        assert(lbpre_gaussian_new(bad[i]) == NULL);
    g = lbpre_gaussian_new("0.1");
    assert(g != NULL); /* CDF supports small positive widths; no polar variance correction. */
    assert(lbpre_gaussian_radius(g) == 1);
    lbpre_gaussian_free(g);
    assert(fesetround(FE_UPWARD) == 0);
    assert(lbpre_gaussian_new("2") == NULL);
    assert(fesetround(FE_DOWNWARD) == 0);
    assert(lbpre_gaussian_new("2") == NULL);
    assert(fesetround(FE_TOWARDZERO) == 0);
    assert(lbpre_gaussian_new("2") == NULL);
    assert(fesetround(original) == 0);
    assert(lbpre_gaussian_radius(NULL) == 0);
    lbpre_gaussian_free(NULL);
}

static void known_answers_and_consumption(void)
{
    size_t k, i;
    for (k = 0; k < sizeof(KATS)/sizeof(KATS[0]); k++) {
        const independent_kat *kat = KATS + k;
        lbpre_gaussian *g = lbpre_gaussian_new(kat->width);
        lbpre_rng *rng = new_rng(2);
        uint8_t next[16];
        assert(g != NULL && lbpre_gaussian_radius(g) == kat->radius);
        for (i = 0; i < 32; i++) {
            int64_t actual = lbpre_gaussian_sample(g,rng);
            if (actual != kat->sample[i])
                fprintf(stderr,"OpenFHE KAT %zu sample %zu: got %" PRId64 ", expected %" PRId64 "\n",
                        k,i,actual,kat->sample[i]);
            assert(actual == kat->sample[i]);
        }
        lbpre_rng_bytes(rng,next,sizeof(next));
        for (i = 0; i < sizeof(next); i++) {
            unsigned expected;
            assert(sscanf(kat->following_rng_bytes + 2*i,"%2x",&expected) == 1);
            assert(next[i] == expected);
        }
        lbpre_rng_free(rng);
        lbpre_gaussian_free(g);
    }
}

static void polynomial_history_and_scalar_agreement(const char *width, uint64_t q)
{
    lbpre_gaussian *g = lbpre_gaussian_new(width), *fresh = lbpre_gaussian_new(width);
    lbpre_rng *rng = new_rng(2), *scalar_rng = new_rng(2), *fresh_rng = new_rng(2), *other = new_rng(91);
    uint64_t poly[LBPRE_D], copy[LBPRE_D], unrelated[LBPRE_D];
    uint8_t after_poly[32], after_scalars[32];
    size_t i;
    assert(g != NULL && fresh != NULL);
    /* Odd scalar history plus an unrelated full polynomial catches a normal
     * spare, Bernoulli state, or shared sampler RNG retained across calls. */
    for (i = 0; i < 17; i++) (void)lbpre_gaussian_sample(g,other);
    lbpre_gaussian_poly(unrelated,q,g,other);
    lbpre_gaussian_poly(poly,q,g,rng);
    lbpre_gaussian_poly(copy,q,fresh,fresh_rng);
    assert(memcmp(poly,copy,sizeof(poly)) == 0);
    for (i = 0; i < LBPRE_D; i++) {
        int64_t sample = lbpre_gaussian_sample(fresh,scalar_rng);
        assert(poly[i] == residue(sample,q));
        assert(poly[i] < q);
    }
    lbpre_rng_bytes(rng,after_poly,sizeof(after_poly));
    lbpre_rng_bytes(scalar_rng,after_scalars,sizeof(after_scalars));
    assert(memcmp(after_poly,after_scalars,sizeof(after_poly)) == 0);
    lbpre_rng_free(rng); lbpre_rng_free(scalar_rng); lbpre_rng_free(fresh_rng); lbpre_rng_free(other);
    lbpre_gaussian_free(g); lbpre_gaussian_free(fresh);
}

static void small_discrete_pmf(void)
{
    const size_t count = 100000;
    lbpre_gaussian *g = lbpre_gaussian_new("2");
    lbpre_gaussian *same = lbpre_gaussian_new("2.0000000000000000000000000000000000000");
    lbpre_rng *rng = new_rng(17), *same_rng = new_rng(17);
    uint64_t histogram[7] = {0}, tails = 0;
    long double sum = 0, squares = 0;
    double normalization = 0, pi = acos(-1.0);
    size_t i;
    int x;
    assert(g != NULL && same != NULL && lbpre_gaussian_radius(g) == 10);
    for (x = -10; x <= 10; x++) normalization += exp(-pi*x*x/4.0);
    for (i = 0; i < count; i++) {
        int64_t sample = lbpre_gaussian_sample(g,rng);
        assert(sample == lbpre_gaussian_sample(same,same_rng));
        assert(sample >= -10 && sample <= 10);
        sum += sample; squares += (long double)sample*sample;
        if (sample >= -3 && sample <= 3) histogram[sample+3]++;
        else tails++;
    }
    /* Fixed-seed regression bands, not confidence/security certificates.
     * These check the small PMF and reject the old cutoff=1 mistake; the
     * independent KATs distinguish the intended algorithm and random grids. */
    for (x = -3; x <= 3; x++) {
        double expected = exp(-pi*x*x/4.0)/normalization;
        assert(fabs((double)histogram[x+3]/count - expected) < 0.006);
    }
    assert(histogram[1] + histogram[5] > 3500); /* Nonzero mass at +/-2. */
    assert(tails < 20);
    assert(fabsl(sum/count) < 0.015L);
    assert(squares/count > 0.61L && squares/count < 0.67L);
    assert(histogram[2] + 900 > histogram[4] && histogram[4] + 900 > histogram[2]);
    lbpre_rng_free(rng); lbpre_rng_free(same_rng);
    lbpre_gaussian_free(g); lbpre_gaussian_free(same);
}

static void all_profile_widths_and_wide_integers(void)
{
    static const unsigned logq[] = {20,30,40};
    lbpre_rng *rng = new_rng(33);
    lbpre_gaussian *g;
    uint64_t poly[LBPRE_D];
    size_t i,j,role;
    unsigned wider_than_32 = 0;
    for (i = 0; i < sizeof(logq)/sizeof(logq[0]); i++) {
        const lbpre_params *p = lbpre_params_get(logq[i]);
        assert(p != NULL);
        const char *widths[] = {p->sigma_source,p->sigma_pad};
        for (role = 0; role < 2; role++) {
            unsigned profile_wide = 0;
            g = lbpre_gaussian_new(widths[role]); assert(g != NULL);
            for (j = 0; j < 64; j++) {
                int64_t sample = lbpre_gaussian_sample(g,rng);
                assert(sample != INT64_MIN);
                assert((uint64_t)(sample < 0 ? -sample : sample) <= lbpre_gaussian_radius(g));
                profile_wide += sample > INT32_MAX || sample < INT32_MIN;
            }
            if (logq[i] == 40 && role == 1) assert(profile_wide > 32);
            lbpre_gaussian_poly(poly,p->q,g,rng);
            for (j = 0; j < LBPRE_D; j++) assert(poly[j] < p->q);
            lbpre_gaussian_free(g);
            polynomial_history_and_scalar_agreement(widths[role],p->q);
        }
    }
    g = lbpre_gaussian_new("1099511627776"); assert(g != NULL);
    for (j = 0; j < 64; j++) {
        int64_t sample = lbpre_gaussian_sample(g,rng);
        assert(sample != INT64_MIN);
        if (sample > INT32_MAX || sample < INT32_MIN) wider_than_32++;
    }
    assert(wider_than_32 > 32);
    lbpre_gaussian_poly(poly,UINT64_C(13779647489),g,rng);
    for (j = 0; j < LBPRE_D; j++) assert(poly[j] < UINT64_C(13779647489));
    lbpre_gaussian_free(g); lbpre_rng_free(rng);
}

static void wide_pad_statistics(void)
{
    const size_t count = 100000;
    const char *width = "3.757287713530579173645676583010735349905182628242270780933942406566071410933e8";
    const long double stddev = 149894092.8560174L;
    lbpre_gaussian *g = lbpre_gaussian_new(width);
    lbpre_rng *rng = new_rng(57);
    long double sum = 0, squares = 0;
    size_t i, positive = 0, negative = 0, tails = 0;
    assert(g != NULL);
    for (i = 0; i < count; i++) {
        int64_t sample = lbpre_gaussian_sample(g,rng);
        long double normalized = (long double)sample/stddev;
        assert(sample != INT64_MIN);
        sum += normalized; squares += normalized*normalized;
        positive += sample > 0; negative += sample < 0;
        tails += fabsl(normalized) >= 2;
    }
    assert(fabsl(sum/count) < 0.015L);
    assert(squares/count > 0.98L && squares/count < 1.02L);
    assert(positive > 49000 && positive < 51000 && negative > 49000 && negative < 51000);
    assert(tails > 4000 && tails < 5200);
    lbpre_gaussian_free(g); lbpre_rng_free(rng);
}

static void supplementary_wide_pad(void)
{
    const size_t count=20000;
    lbpre_gaussian *g=lbpre_gaussian_new("16000000000000000");
    lbpre_rng *rng=new_rng(117);
    long double sum=0,squares=0;
    size_t odd=0,i;
    assert(g && rng);
    for(i=0;i<count;i++) {
        int64_t sample=lbpre_gaussian_sample(g,rng);
        long double z=(long double)sample/(16000000000000000.0L/2.5066282746310005024L);
        assert(sample!=INT64_MIN);
        odd+=((uint64_t)sample&1u)!=0;
        sum+=z;squares+=z*z;
    }
    /* Detect mantissa-grid/parity collapse and gross width/tail regressions;
     * these checks do not certify a statistical-distance bound. */
    assert(odd>9500 && odd<10500);
    assert(fabsl(sum/count)<0.04L);
    assert(squares/count>0.94L && squares/count<1.06L);
    lbpre_gaussian_free(g);lbpre_rng_free(rng);
}

int main(void)
{
    assert(strcmp(lbpre_gaussian_backend(),"openfhe-cdf-karney-v1") == 0);
    assert(lbpre_gaussian_is_approximate() == 1);
    assert(strcmp(lbpre_gaussian_target(),"discrete-gaussian") == 0);
    assert(lbpre_gaussian_has_certified_error_bound() == 0);
    invalid_inputs_and_environment();
    known_answers_and_consumption();
    polynomial_history_and_scalar_agreement("2.0",UINT64_C(13779647489));
    polynomial_history_and_scalar_agreement(KATS[4].width,UINT64_C(13779647489));
    small_discrete_pmf();
    all_profile_widths_and_wide_integers();
    wide_pad_statistics();
    supplementary_wide_pad();
    puts("OpenFHE sampler tests: OK (independent CDF/Karney KATs, std300 boundary, RNG consumption/history, six L/M/H profile widths, 100000 small-PMF +100000 wide-pad samples; no certified error bound)");
    return 0;
}
