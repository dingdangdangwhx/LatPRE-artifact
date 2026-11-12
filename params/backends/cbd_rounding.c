/* Certified CBD terminal-u rounding envelope using actual C PMF convolution.
 *
 * If s_i ~ CBD_eta independently and a is independent of s, |a_i|<=r,
 * sum_i a_i s_i is convex-order dominated by r*Z, Z~CBD_(eta*k*d).
 * This follows by writing CBD_eta as 2*eta independent +/-1/2 signs and
 * successively increasing each coefficient magnitude to r (convex order).
 * Thus P[X>=r*t] <= E[(Z-h)_+^p]/(t-h)^p for p>=1,h<t.
 * Two signs and d coefficients are unioned, with no independence claim
 * between that event and any other PRE noise.
 *
 * The distribution is built with genuine integer CRT-NTT convolutions.
 * lbpre_dist stores a downward-rounded sub-PMF. Its missing mass is charged
 * at the exact largest possible value (N-h)^p, where Z lies in [-N,N].
 * Float optimization chooses h,p only. The reported multiplier is then
 * recomputed with outward MPFR rounding. No normal approximation is used.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include "lbpre_dist.h"
#include "crt_ntt.h"

static void die(const char *s) { fprintf(stderr,"%s\n",s); exit(2); }
static void usage(void) { die("cbd_rounding --eta ETA --k K --degree D --round-bits R --precision P"); }

int main(int argc,char **argv) {
    unsigned long eta=0,k=0,d=256,rb=130,prec=512;
    for(int i=1;i<argc;i++) {
        if(i+1>=argc) usage();
        const char *key=argv[i++]; unsigned long v=strtoul(argv[i],NULL,10);
        if(!strcmp(key,"--eta")) eta=v;
        else if(!strcmp(key,"--k")) k=v;
        else if(!strcmp(key,"--degree")) d=v;
        else if(!strcmp(key,"--round-bits")) rb=v;
        else if(!strcmp(key,"--precision")) prec=v;
        else usage();
    }
    if(!eta||!k||!d||prec<192||prec>896||rb>400||eta>10000||k>100) usage();
    uint64_t N=(uint64_t)eta*k*d;
    if(N>100000000) die("N guard exceeded");
    crt_ntt_init();
    lbpre_dist *base=lbpre_dist_uniform_weight(1,1,prec,0,3);
    if(!base) die(lbpre_dist_error());
    /* Replace uniform primitive by exact CBD1 weights, denominator 2^prec. */
    mpz_fdiv_q_2exp(base->numerator[0],base->denominator,2);
    mpz_fdiv_q_2exp(base->numerator[1],base->denominator,1);
    mpz_set(base->numerator[2],base->numerator[0]);
    lbpre_dist *pmf=lbpre_dist_power(base,N,4000001);
    lbpre_dist_free(base);
    if(!pmf) die(lbpre_dist_error());
    mpz_t mass,deficit,m[4],old[4],up,tmp,power,best_num;
    mpz_inits(mass,deficit,up,tmp,power,best_num,NULL);
    for(int j=0;j<4;j++) {mpz_init(m[j]);mpz_init(old[j]);}
    for(size_t i=0;i<pmf->length;i++) mpz_add(mass,mass,pmf->numerator[i]);
    mpz_sub(deficit,pmf->denominator,mass);
    if(mpz_sgn(deficit)<0) die("negative deficit");
    long maxz=pmf->offset+(long)pmf->length-1;
    double best=INFINITY; int bestp=0; long besth=0;
    /* m_j(h) = sum_{z>h}(z-h)^j subpmf[z] numerators. */
    for(long h=maxz;h>=0;h--) {
        for(int p=1;p<=3;p++) {
            mpz_ui_pow_ui(power,(unsigned long)(N-(uint64_t)h),(unsigned long)p);
            mpz_mul(up,deficit,power);mpz_add(up,up,m[p]);
            if(mpz_sgn(up)>0) {
                double logmoment=log2(mpz_get_d(up))-(double)prec;
                double a=(double)h+exp2((logmoment+(double)rb+log2(2.0*d))/p);
                if(a<best) {best=a;bestp=p;besth=h;mpz_set(best_num,up);}
            }
        }
        if(!h) break;
        for(int j=0;j<4;j++) mpz_set(old[j],m[j]);
        mpz_t *at=&pmf->numerator[(size_t)(h-pmf->offset)];
        mpz_add(m[0],old[0],*at);
        mpz_add(m[1],old[1],old[0]);mpz_add(m[1],m[1],*at);
        mpz_mul_ui(m[2],old[1],2);mpz_add(m[2],m[2],old[2]);
        mpz_add(m[2],m[2],old[0]);mpz_add(m[2],m[2],*at);
        mpz_mul_ui(m[3],old[2],3);mpz_addmul_ui(m[3],old[1],3);
        mpz_add(m[3],m[3],old[3]);mpz_add(m[3],m[3],old[0]);
        mpz_add(m[3],m[3],*at);
    }
    if(bestp==0) die("no stop-loss choice");
    mpfr_t a,eps,sg,ratio;
    mpfr_inits2(prec,a,eps,sg,ratio,(mpfr_ptr)0);
    mpfr_set_z(a,best_num,MPFR_RNDU);mpfr_div_2ui(a,a,prec,MPFR_RNDU);
    mpfr_mul_2ui(a,a,rb,MPFR_RNDU);mpfr_mul_ui(a,a,2*d,MPFR_RNDU);
    mpfr_rootn_ui(a,a,bestp,MPFR_RNDU);mpfr_add_si(a,a,besth,MPFR_RNDU);
    mpfr_set_z(eps,deficit,MPFR_RNDU);mpfr_div_2ui(eps,eps,prec,MPFR_RNDU);
    mpfr_set_ui(sg,2*d,MPFR_RNDU);mpfr_log(sg,sg,MPFR_RNDU);
    mpfr_const_log2(ratio,MPFR_RNDU);mpfr_mul_ui(ratio,ratio,rb,MPFR_RNDU);
    mpfr_add(sg,sg,ratio,MPFR_RNDU);mpfr_mul_ui(sg,sg,(unsigned long)N,MPFR_RNDU);
    mpfr_sqrt(sg,sg,MPFR_RNDU);
    printf("{\n  \"method\": \"C CRT-NTT CBD PMF convolution + convex-order stop-loss certificate\",\n");
    printf("  \"scope\": \"unconditional terminal-u rounding envelope, union over both signs and d coefficients; independent rounding vector required\",\n");
    printf("  \"eta\": %lu, \"k\": %lu, \"degree\": %lu, \"N\": %llu,\n",eta,k,d,(unsigned long long)N);
    printf("  \"round_bits\": %lu, \"precision_bits\": %lu, \"pmf_length\": %zu,\n",rb,prec,pmf->length);
    printf("  \"stoploss_power\": %d, \"stoploss_shift\": %ld,\n",bestp,besth);
    printf("  \"multiplier_upper\": \"");mpfr_printf("%.80RUg",a);printf("\",\n");
    printf("  \"subgaussian_multiplier_upper\": \"");mpfr_printf("%.80RUg",sg);printf("\",\n");
    printf("  \"pmf_missing_mass_upper\": \"");mpfr_printf("%.80RUe",eps);printf("\",\n");
    printf("  \"probability_bound\": \"2^-%lu\", \"certified\": true,\n",rb);
    printf("  \"full_PRE_PMF\": false, \"normal_approximation\": false\n}\n");
    mpfr_clears(a,eps,sg,ratio,(mpfr_ptr)0);
    mpz_clears(mass,deficit,up,tmp,power,best_num,NULL);
    for(int j=0;j<4;j++) {mpz_clear(m[j]);mpz_clear(old[j]);}
    lbpre_dist_free(pmf);crt_ntt_free();mpfr_free_cache();return 0;
}
