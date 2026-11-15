#include "lbpre.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    static const char *names[]={"E20_10","E20_15","E20_20","E25_15","E30_20","E50_25","E60_30"};
    static const unsigned qlogs[]={20,20,20,25,30,50,60},mlogs[]={10,15,20,15,20,25,30};
    uint8_t seed[32]={83},message[32],decoded[32];
    assert(lbpre_params_get(20)==lbpre_params_named("L"));
    assert(lbpre_params_get(30)==lbpre_params_named("M"));
    assert(lbpre_params_get(40)==lbpre_params_named("H"));
    assert(lbpre_setup_named(NULL,seed)==NULL);
    assert(lbpre_setup_named("unavailable",seed)==NULL);
    for(size_t n=0;n<sizeof(names)/sizeof(names[0]);n++) {
        lbpre_ctx *ctx=lbpre_setup_named(names[n],seed);
        const lbpre_params *p=lbpre_ctx_params(ctx);
        lbpre_rng *rng=lbpre_rng_new(seed);
        assert(ctx && p && rng && p->logQ==qlogs[n] && p->logM==mlogs[n]);
        size_t np=lbpre_public_key_bytes(p),ns=lbpre_secret_key_bytes(p),nr=lbpre_rekey_bytes(p);
        size_t nc=lbpre_source_bytes(p),nt=lbpre_terminal_bytes(p);
        uint8_t *pa=calloc(1,np),*pb=calloc(1,np),*sa=calloc(1,ns),*sb=calloc(1,ns);
        uint8_t *rk=calloc(1,nr),*ct=calloc(1,nc),*rt=calloc(1,nt);
        assert(pa && pb && sa && sb && rk && ct && rt);
        assert(lbpre_keygen(ctx,pa,np,sa,ns,rng)==LBPRE_OK);
        assert(lbpre_keygen(ctx,pb,np,sb,ns,rng)==LBPRE_OK);
        assert(lbpre_rekeygen(ctx,rk,nr,sa,ns,pb,np,rng)==LBPRE_OK);
        lbpre_rekey_cache *cache=lbpre_rekey_prepare(ctx,rk,nr,pa,np,pb,np);
        lbpre_proxy *proxy=lbpre_proxy_new(ctx);
        assert(cache && proxy);
        for(unsigned t=0;t<5;t++) {
            for(size_t j=0;j<32;j++)message[j]=(uint8_t)(j*17+t+n);
            assert(lbpre_encrypt(ctx,ct,nc,pa,np,message,rng)==LBPRE_OK);
            assert(lbpre_decrypt_source(ctx,decoded,ct,nc,sa,ns)==LBPRE_OK);
            assert(!memcmp(message,decoded,32));
            assert(lbpre_register(proxy,pa,np,ct,nc)==LBPRE_OK);
            for(unsigned repeat=0;repeat<2;repeat++) {
                assert(lbpre_reencrypt(proxy,rt,nt,cache,pa,np,pb,np,ct,nc,rng)==LBPRE_OK);
                assert(lbpre_decrypt_terminal(ctx,decoded,rt,nt,sb,ns)==LBPRE_OK);
                assert(!memcmp(message,decoded,32));
            }
        }
        assert(lbpre_registered_records(proxy)==5 && lbpre_registered_rekeys(proxy)==1);
        lbpre_proxy_free(proxy);lbpre_rekey_cache_free(cache);lbpre_rng_free(rng);lbpre_ctx_free(ctx);
        free(pa);free(pb);free(sa);free(sb);free(rk);free(ct);free(rt);
    }
    puts("Supplementary profiles: OK (named Q/M selection, repeated forwarding, all source/terminal round trips)");
    return 0;
}
