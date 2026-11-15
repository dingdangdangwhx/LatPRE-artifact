#!/usr/bin/env python3
"""Small, resumable finite search for supplementary classical-128 profiles.

Floating candidates are proposals, never security/correctness certificates.
The existing L/M/H profile file and measurements are read-only.
"""
import argparse
from copy import deepcopy
from decimal import Decimal, localcontext
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE/'backends'), str(HERE/'lib')]
import noise_bounds as nb
from sphere_search import bank_bound
from bounds import PI, verify_gaussian_and_sphere

PAIRS = ((20,10),(20,15),(20,20),(25,15),(30,20),(50,25),(60,30))

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False)+'\n')

def prime(n):
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    v=n-1; s=0
    while v%2==0: s+=1; v//=2
    for a in (2,325,9375,28178,450775,9780504,1795265022):
        x=pow(a%n,v,n)
        if x in (1,n-1): continue
        for _ in range(s-1):
            x=x*x%n
            if x==n-1: break
        else: return False
    return True

@lru_cache(None)
def modulus(bits):
    frozen={28:265753601,35:34016143361,42:4354066046977}
    if bits in frozen:return frozen[bits]
    q=(((1<<bits)*99//100-1)//512)*512+1
    while not prime(q): q-=512
    return q

def gadget(q,length):
    lo,hi=1,1<<32
    while lo<hi:
        mid=(lo+hi)//2
        if mid**length>=q: hi=mid
        else: lo=mid+1
    b=max(3,lo|1)
    assert b<(1<<32) and b**(length-1)<q<=b**length
    return b

@lru_cache(None)
def sphere(qlog,p):
    return bank_bound(1<<qlog,p,256,'1/2',160,certify=False)

def width(sd):
    with localcontext() as ctx:
        ctx.prec=160
        pi=(PI[0]+PI[1])/2
        return str(Decimal(sd)*(2*pi).sqrt())

def model(row):
    r=row['runtime']
    return nb.noise_model(r['k'],r['ell'],256,r['base'],r['length'],float(r['source_std']),
       math.sqrt(r['terminal_eta']/2),float(r['pad_std']),nb.distribution('cbd',1),nb.distribution('cbd',1),
       terminal_dist={'kind':'cbd','parameter':r['terminal_eta'],'bound':r['terminal_eta'],'variance':r['terminal_eta']/2})

def rounding_multiplier(m,rb=130):
    name='eta%d_k%d_d256_rb%d.json'%(m['terminal_dist']['parameter'],m['k'],rb)
    for folder in (HERE.parent/'results/extended-classical128/rounding',HERE/'evidence/rounding'):
        file=folder/name
        if file.exists():
            r=json.loads(file.read_text())
            return math.nextafter(float(r['multiplier_upper']),math.inf)*(1+1e-14),'c-pmf'
    return nb.rounding_multiplier(m,rb),'analytic'

def codecs(m,q,mult):
    bd=nb.budgets(130,128,136)
    sq=nb.source_quantile(m,136);rq=nb.re_quantile(m,bd['main_bits'])
    radius=(q-1)/4
    if max(sq,rq)>=radius:return []
    h=q.bit_length();rho={b:nb.rounding_bound(q,b) for b in range(1,h+1)}
    choices=[]
    for sv in range(1,h):
        if sq+rho[sv]>=radius:continue
        for ru in range(1,h):
            left=radius-rq-rho[sv]-mult*rho[ru]
            if left<=0:continue
            rv=max(1,min(h-1,math.ceil(math.log2(q/(2*left)))))
            while rv<h-1 and rho[rv]>=left:rv+=1
            if rho[rv]>=left:continue
            choices.append((32*(m['k']*h+sv)+32*(m['k']*ru+rv),sv,ru,rv))
    return sorted(choices)[:4]

def propose(pair,geometry,length,factor):
    qlog,mlog=pair;k,ell,bits,eta,H=geometry;q=modulus(bits);p=k+ell
    bank=deepcopy(sphere(qlog,p));B=bank['B']*(1<<mlog)
    req=(1.9*H*H+math.log(2*p*256+4)/math.pi)*(1+3e-6)
    sd=math.sqrt(req/(2*math.pi))*factor
    psd=math.sqrt(B/(1/req-1/(2*math.pi*sd*sd))/(2*math.pi))*(1+2e-6)
    if 12*psd>=(q-1)/4:return []
    r={'name':f'E{qlog}_{mlog}','logQ':qlog,'logM':mlog,'k':k,'ell':ell,'q_bits':bits,
       'base':gadget(q,length),'length':length,'q':q,'source_eta':1,'internal_eta':1,'terminal_eta':eta,
       'source_std':repr(sd),'pad_std':repr(psd),'sigma_terminal':None}
    row={'runtime':r}
    m=model(row);mult,backend=rounding_multiplier(m)
    out=[]
    for _,sv,ru,rv in codecs(m,q,mult):
        runtime=deepcopy(r);runtime.update(source_v_bits=sv,re_u_bits=ru,re_v_bits=rv,
          sigma_source=width(r['source_std']),sigma_pad=width(r['pad_std']))
        sizes={'public_key_bytes':2*ell*32*bits,'secret_key_bytes':2*k*32*bits,
          'source_ct_bytes':32*(k*bits+sv),'reenc_ct_bytes':32*(k*ru+rv),
          'rekey_body_bytes':(k+1)*k*length*32*bits,'rekey_seed_bytes':32}
        sizes['rekey_bytes']=sizes['rekey_body_bytes']+32
        runtime['sizes_bytes']=sizes
        cand={'profile':r['name'],'degree':256,'Q_log2':qlog,'M_log2':mlog,'Q':1<<qlog,'M':1<<mlog,
          'k':k,'ell':ell,'q':q,'q_bits':bits,'sigma_H':str(H),'B_original':bank['B'],'B_QM':B,
          'source_distribution':{'kind':'cbd','eta':1},'internal_distribution':{'kind':'cbd','eta':1},
          'terminal_distribution':{'kind':'cbd','eta':eta},'gadget_base':r['base'],'gadget_length':length,
          'source_v_bits':sv,'re_u_bits':ru,'re_v_bits':rv,'source_std':r['source_std'],'pad_std':r['pad_std'],
          'correctness_certificate':{'bank':{'original_bank':bank,'M':1<<mlog}}}
        item={'runtime':runtime,'candidate':cand,'rounding_backend':backend,
          'dfr_budgets':{'round_bits':130,'failure_bits':128,'source_bits':136},
          'status':'proposal-not-certified'}
        key=json.dumps(item,sort_keys=True)
        item['id']=hashlib.sha256(key.encode()).hexdigest()[:20]
        out.append(item)
    return out

def objective(row):
    s=row['runtime']['sizes_bytes']
    return (s['source_ct_bytes']+s['reenc_ct_bytes'],s['rekey_bytes'],s['reenc_ct_bytes'],float(row['runtime']['source_std']))

def candidates(rows):
    # Retain tradeoffs in all three communication axes, rather than alternatives
    # that merely use a larger rekey for the identical ciphertext sizes.
    unique={}
    for row in sorted(rows,key=objective):
        s=row['runtime']['sizes_bytes'];key=(s['source_ct_bytes'],s['reenc_ct_bytes'],s['rekey_bytes'])
        unique.setdefault(key,row)
    values=sorted(unique.values(),key=objective)
    if not values:return []
    best=objective(values[0])[0]
    values=[r for r in values if objective(r)[0]<=best+1024]
    front=[]
    for r in values:
        s=r['runtime']['sizes_bytes']
        if any(all(t['runtime']['sizes_bytes'][k]<=s[k] for k in
              ('source_ct_bytes','reenc_ct_bytes','rekey_bytes')) for t in front):continue
        front.append(r)
    chosen=[]
    selectors=[lambda r:objective(r),
      lambda r:(r['runtime']['sizes_bytes']['rekey_bytes'],*objective(r)),
      lambda r:(r['runtime']['sizes_bytes']['reenc_ct_bytes'],*objective(r)),
      lambda r:(r['runtime']['sizes_bytes']['source_ct_bytes'],*objective(r))]
    for order,key in enumerate(selectors):
        eligible=front if order<2 else [r for r in front if objective(r)[0]<=best+256]
        if eligible:
            r=min(eligible,key=key)
            if r not in chosen:chosen.append(r)
    for r in front:
        if len(chosen)>=3:break
        if r not in chosen:chosen.append(r)
    # When fewer than three wire-size tradeoffs exist, keep another finite
    # gadget/width configuration as reference, without calling it Pareto-optimal.
    for r in values:
        if len(chosen)>=3:break
        if r not in chosen:chosen.append(r)
    return sorted(chosen,key=objective)

def search(output, profiles=None):
    start=time.monotonic();frozen=json.loads((HERE/'profiles.json').read_text())
    catalog={
      (20,10):[(4,5,28,12,8.74)],
      (20,15):[(5,6,31,2,8.74),(5,6,35,16,8.74)],
      (20,20):[(5,6,33,8,8.74),(5,6,35,16,8.74)],
      (25,15):[(5,6,33,8,8.74),(5,6,35,16,8.74)],
      (30,20):[(6,7,38,4,8.74),(6,7,42,22,8.74)],
      (50,25):[(8,9,50,4,8.74)],
      (60,30):[(9,10,57,4,8.74)]}
    results=json.loads(output.read_text())['results'] if profiles and output.exists() else {}
    wanted=set(profiles.split(',')) if profiles else None
    if wanted and not wanted <= {f'E{a}_{b}' for a,b in PAIRS}:
        raise ValueError('Unknown supplementary profile')
    for pair in PAIRS:
        label=f'E{pair[0]}_{pair[1]}';pool=[]
        if wanted and label not in wanted:continue
        for g in catalog[pair]:
            for length in (2,3,4):
                for factor in (1.3,2,3,5,8,12,24,64):
                    pool.extend(propose(pair,g,length,factor))
        rows=candidates(pool)
        if pair==(20,10):
            current=deepcopy(frozen['profiles']['L']);current['id']='frozen-L';current['status']='existing-frozen'
            rows.insert(0,current)
        assert len(rows)>=3,(label,'insufficient candidates')
        results[label]={'candidate_count':len(pool),'candidates':rows}
        results={f'E{a}_{b}':results[f'E{a}_{b}'] for a,b in PAIRS if f'E{a}_{b}' in results}
        save(output,{'schema':'latpre-extended-search-v1','status':'proposals-require-verification',
             'selection_rule':'minimum total ciphertext; allow at most 128 extra bytes for a smaller rekey; preserve existing L',
             'finite_geometry_grid':{f'E{a}_{b}':v for (a,b),v in catalog.items()},
             'results':results,'seconds':time.monotonic()-start})
        print(label,'proposals',len(pool),'shortlist',[(x['id'],objective(x)[:3]) for x in rows],flush=True)

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,default=HERE.parent/'results/extended-classical128/candidates.json')
    ap.add_argument('--profiles',help='Recompute only these comma-separated profiles, retaining other saved groups')
    args=ap.parse_args();search(args.output,args.profiles)
