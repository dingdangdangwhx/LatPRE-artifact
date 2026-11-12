/* Independent bit-at-a-time/uint128 codec oracles. */
#include "internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x);return 1;} }while(0)
static uint64_t state=UINT64_C(871781911234);
static uint64_t random64(void) { state^=state<<13;state^=state>>7;state^=state<<17;return state; }
static void pack(uint8_t *out,const uint64_t *in,unsigned bits) {
 memset(out,0,32u*bits);
 for(unsigned i=0;i<256;++i)for(unsigned j=0;j<bits;++j)out[(i*bits+j)/8]|=(uint8_t)(((in[i]>>j)&1)<<((i*bits+j)%8));
}
static void unpack(uint64_t *out,const uint8_t *in,unsigned bits) {
 for(unsigned i=0;i<256;++i){out[i]=0;for(unsigned j=0;j<bits;++j)out[i]|=(uint64_t)((in[(i*bits+j)/8]>>((i*bits+j)%8))&1)<<j;}
}
int main(void) {
 static const uint64_t moduli[]={3,265753601,34016143361,UINT64_C(4354066046977),UINT64_C(8708132098049),UINT64_C(4611686018427379201)};
 uint64_t input[256],got[256],want[256],scratch[256];
 uint8_t wire[32*62],reference[32*62],compressed[32*62];
 unsigned cases=0;
 for(unsigned qidx=0;qidx<sizeof(moduli)/sizeof(moduli[0]);++qidx){
  lbpre_params p={0};p.q=moduli[qidx];uint64_t v=p.q;while(v){++p.q_bits;v>>=1;}
  for(unsigned bits=1;bits<=62;++bits){
   uint64_t mask=(UINT64_C(1)<<bits)-1;
   for(unsigned batch=0;batch<8;++batch){
    for(unsigned i=0;i<256;++i)input[i]=random64()&mask;
    input[0]=0;input[1]=1;input[2]=mask;input[3]=mask/2;
    memset(wire,0xA5,sizeof(wire));lbpre_pack_poly(wire,input,bits);pack(reference,input,bits);
    CHECK(!memcmp(wire,reference,32u*bits));
    for(unsigned i=32u*bits;i<sizeof(wire);++i)CHECK(wire[i]==0xA5);
    lbpre_unpack_poly(got,wire,bits);CHECK(!memcmp(got,input,sizeof(got)));
    /* Decode arbitrary wire codes including maximum, also beyond q_bits. */
    unpack(want,wire,bits);
    if(bits!=p.q_bits)for(unsigned i=0;i<256;++i)want[i]=(uint64_t)(((__uint128_t)p.q*want[i]+(UINT64_C(1)<<(bits-1)))>>bits)%p.q;
    lbpre_decompress_poly(&p,got,wire,bits);CHECK(!memcmp(got,want,sizeof(got)));
    for(unsigned i=0;i<256;++i)input[i]=random64()%p.q;
    input[0]=0;input[1]=1;input[2]=p.q-1;input[3]=p.q/2;input[4]=p.q/2+1;
    if(bits==p.q_bits)memcpy(scratch,input,sizeof(scratch));
    else for(unsigned i=0;i<256;++i)scratch[i]=(uint64_t)((((__uint128_t)input[i]<<bits)+p.q/2)/p.q)&mask;
    pack(reference,scratch,bits);lbpre_compress_poly(&p,compressed,input,bits);CHECK(!memcmp(compressed,reference,32u*bits));
    ++cases;
   }
  }
 }
 printf("PASS: %u polynomial codec cases, 6 moduli, all 1..62 bit widths, independent exact oracles\n",cases);
 return 0;
}
