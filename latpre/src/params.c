/* Frozen L/M/H parameters. Gaussian width = exact decimal SD * sqrt(2*pi).
 * Source/internal randomness and terminal keys use exact CBD sampling. */
#include "lbpre.h"
#include <string.h>
static const lbpre_params sets[] = {
    { .name="L", .logQ=20, .logM=10, .k=4, .ell=5, .q_bits=28, .base=643, .length=3, .source_v_bits=7, .re_u_bits=13, .re_v_bits=5,
      .q=UINT64_C(265753601), .source_eta=1, .internal_eta=1, .terminal_eta=12,
      .source_std="14.753136145925044", .pad_std="1951876.069544714",
      .sigma_source="36.9806282028563414953809458699387403994907945654508153677741598828917704327530799324658640797543936283325820965844996697370179803060584522071750295435", .sigma_terminal=NULL,
      .sigma_pad="4892627.74449640520017965975541654958757095141274329683922069449816616972796331447640801400348618175794966952906567185793512466187110478556401237892451" },
    { .name="M", .logQ=30, .logM=15, .k=5, .ell=6, .q_bits=35, .base=3241, .length=3, .source_v_bits=6, .re_u_bits=13, .re_v_bits=5,
      .q=UINT64_C(34016143361), .source_eta=1, .internal_eta=1, .terminal_eta=16,
      .source_std="24.609035968580166", .pad_std="337219778.8550402",
      .sigma_source="61.6857053702543337913552078216453215971522817352251097615598673087046146674547552367401451130415927649810810498181601380349390985084522629678729425530", .sigma_terminal=NULL,
      .sigma_pad="845284632.442856962608678428829763884444862996457571527816106316810027498918095182745192734300304646316869565659232510848230998782503285070514984041174" },
    { .name="H", .logQ=40, .logM=20, .k=6, .ell=7, .q_bits=42, .base=2086641, .length=2, .source_v_bits=8, .re_u_bits=14, .re_v_bits=7,
      .q=UINT64_C(4354066046977), .source_eta=1, .internal_eta=1, .terminal_eta=22,
      .source_std="35.7644675891657", .pad_std="60407946156.77607",
      .sigma_source="89.6482256861267567083977105145062742480738722735201467193191882327065069167424428767797962828029623532112306703808829541065027441352332188617444677679", .sigma_terminal=NULL,
      .sigma_pad="151420265848.961978123433377810309429242308760008072224629246857607467215302982943154462170301732166335710552580833319635835674053817462392573638833119" },
};
const lbpre_params *lbpre_params_get(unsigned logQ) {
    for (size_t i=0;i<sizeof(sets)/sizeof(sets[0]);++i) if(sets[i].logQ==logQ) return &sets[i];
    return NULL;
}
const lbpre_params *lbpre_params_named(const char *name) {
    if (!name) return NULL;
    for (size_t i=0;i<sizeof(sets)/sizeof(sets[0]);++i) if(strcmp(sets[i].name,name)==0) return &sets[i];
    return NULL;
}
const char *lbpre_parameter_profile_id(void) { return "LATPRE-CLASSICAL128-LMH-SELECTION-v1"; }
const char *lbpre_parameter_source_sha256(void) { return "c5d401fd996652e386be274d8921b5f3e6c94d8be08543cf61af5f378b3cd509"; }
size_t lbpre_public_key_bytes(const lbpre_params *p) { return p ? 2u*p->ell*LBPRE_D*p->q_bits/8u : 0; }
size_t lbpre_secret_key_bytes(const lbpre_params *p) { return p ? 2u*p->k*LBPRE_D*p->q_bits/8u : 0; }
size_t lbpre_source_bytes(const lbpre_params *p) { return p ? LBPRE_D*(p->k*p->q_bits+p->source_v_bits)/8u : 0; }
size_t lbpre_terminal_bytes(const lbpre_params *p) { return p ? LBPRE_D*(p->k*p->re_u_bits+p->re_v_bits)/8u : 0; }
size_t lbpre_rekey_body_bytes(const lbpre_params *p) { return p ? (size_t)(p->k+1u)*p->k*p->length*LBPRE_D*p->q_bits/8u : 0; }
size_t lbpre_rekey_bytes(const lbpre_params *p) { return p ? lbpre_rekey_body_bytes(p)+32u : 0; }
size_t lbpre_public_matrix_bytes(const lbpre_params *p) { return p ? p->k*p->ell*LBPRE_D*p->q_bits/8u : 0; }
