#!/usr/bin/env python3
"""Certify fixed supplementary candidates; run under SageMath.

Exact lattice instances are cached, including the eight attacks and uSVP scan.
No broad lattice search is performed. C PMFs and attack estimations run serially.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE/'lib'),str(HERE/'backends')]
import extended_search as search
import security
import cbd_noise_bounds as cbd
from bounds import verify_gaussian_and_sphere


def digest(spec):
    s={k:v for k,v in spec.items() if k!='tag'}
    return hashlib.sha256(json.dumps(s,sort_keys=True).encode()).hexdigest()

def report(path,value):search.save(path,value)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--directory',type=Path,default=HERE.parent/'results/extended-classical128')
    ap.add_argument('--verify-only',action='store_true')
    args=ap.parse_args();directory=args.directory.resolve()
    proposals=json.loads((directory/'candidates.json').read_text())
    api=None;started=time.monotonic();results={}
    folder=directory/'security';folder.mkdir(exist_ok=True)
    rounding_dir=directory/'rounding';rounding_dir.mkdir(exist_ok=True)
    # Retain the exact original certificate for the duplicate paper Light set.
    needed=set()
    for group in proposals['results'].values():
        for item in group['candidates']:
            r=item['runtime'];b=item.get('dfr_budgets',item.get('dfr',{}).get('budgets',{}))
            needed.add('eta%d_k%d_d256_rb%d.json'%(r['terminal_eta'],r['k'],b['round_bits']))
    for name in needed:
        file=HERE/'evidence/rounding'/name
        if file.exists() and not (rounding_dir/name).exists():(rounding_dir/name).write_bytes(file.read_bytes())
    cbd.set_rounding_directory(rounding_dir)
    for label,group in proposals['results'].items():
        results[label]=[]
        for candidate in group['candidates']:
            item=deepcopy(candidate);r=item['runtime'];c=item['candidate']
            print('checking',label,item['id'],flush=True)
            if item['id']=='frozen-L':
                item['verified_spectral']=verify_gaussian_and_sphere(c,r)
                for role,entry in item['security'].items():
                    original=HERE/entry['record']
                    raw=original.read_bytes()
                    assert hashlib.sha256(raw).hexdigest()==entry['sha256']
                    value=json.loads(raw)
                    assert value['full_gate_passed'] and value['min_bits']>=128
                    path=folder/(digest(value['instance'])+'.json')
                    if not path.exists():
                        assert not args.verify_only,('missing frozen reference',role)
                        path.write_bytes(raw)
                    entry['record']='security/'+path.name
                    entry['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                item['status']='verified-existing-frozen';results[label].append(item);continue
            item['verified_spectral']=verify_gaussian_and_sphere(c,r)
            c['correctness_certificate']['bank']['original_bank']['certificate']={
                'passed':True,
                'log2_bad_probability_upper':item['verified_spectral']['log2_spectral_failure_upper'],
                'arithmetic':item['verified_spectral']['arithmetic'],
                'scope':'one honest iid coefficient bank; M exact repeated blocks'}
            role_results={}
            for role in ('hint','terminal','source','internal'):
                spec=security.specification(item,role);key=digest(spec);path=folder/(key+'.json')
                if path.exists():value=json.loads(path.read_text())
                else:
                    assert not args.verify_only,('missing security evidence',label,role)
                    if api is None:api=security.load_estimator()
                    print('  full MATZOV',role,spec,flush=True)
                    value=security.estimate(spec,'classical',api);report(path,value)
                assert digest(value['instance'])==key
                assert value['mode']=='classical' and value['method']=='full'
                assert value['estimator_commit']==security.COMMIT
                finite=[v['bits'] for v in value['attacks'].values() if isinstance(v['bits'],(int,float))]
                assert min(finite)==value['min_bits']
                assert value['status']=='ok' and value['full_gate_passed'],(label,role,value['min_bits'])
                assert set(value['attacks'])==security.ATTACKS and value['usvp_block_scan']['max_beta']>=600
                role_results[role]={'record':'security/'+path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'min_bits':value['min_bits']}
            item['security']=role_results
            rb=item['dfr_budgets']['round_bits'];filename='eta%d_k%d_d256_rb%d.json'%(r['terminal_eta'],r['k'],rb)
            path=rounding_dir/filename
            if not path.exists():
                assert not args.verify_only,('missing rounding certificate',filename)
                if r['terminal_eta']*r['k']*256>100000:
                    raise ValueError('C PMF resource guard exceeded; use a separately certified analytic bound')
                binary=HERE/'build/cbd_rounding'
                if not binary.exists():subprocess.run(['make','-C',str(HERE),'rounding'],check=True)
                print('  C rounding',filename,flush=True)
                value=json.loads(subprocess.check_output([str(binary),'--eta',str(r['terminal_eta']),'--k',str(r['k']),
                      '--degree','256','--round-bits',str(rb),'--precision','512'],text=True))
                report(path,value)
            noise=search.model(item);b=item['dfr_budgets']
            cert=cbd.certify(noise,r['q'],r['source_v_bits'],r['re_u_bits'],r['re_v_bits'],**b)
            assert cert['passed'],(label,item['id'],cert)
            item['dfr']=cert;item['status']='verified';results[label].append(item)
            print('  PASS minimum bits',min(x['min_bits'] for x in role_results.values()),'DFR',cert['joint_log2_upper'],flush=True)
            if not args.verify_only:
                report(directory/'certified-candidates.json',{'schema':'latpre-extended-certified-v1','results':results,'seconds':time.monotonic()-started})
    selected={}
    for label,rows in results.items():
        if label=='E20_10':selected[label]=deepcopy(rows[0]);continue
        best=min(search.objective(r)[0] for r in rows)
        eligible=[r for r in rows if search.objective(r)[0]<=best+128]
        selected[label]=deepcopy(min(eligible,key=lambda r:(r['runtime']['sizes_bytes']['rekey_bytes'],*search.objective(r))))
    if args.verify_only:
        saved=json.loads((directory/'selected.json').read_text())
        assert {k:v['id'] for k,v in saved['profiles'].items()}=={k:v['id'] for k,v in selected.items()}
        print('ALL RETAINED CANDIDATES AND SELECTED PROFILES VERIFIED',flush=True)
        return
    report(directory/'certified-candidates.json',{'schema':'latpre-extended-certified-v1','results':results,'seconds':time.monotonic()-started})
    report(directory/'selected.json',{'schema':'latpre-extended-selection-v1','status':'verified','estimator_commit':security.COMMIT,
       'objective':'minimum total ciphertext; permit <=128 extra bytes for a smaller rekey; keep paper Light unchanged',
       'profiles':selected,'seconds':time.monotonic()-started,
       'scope':'classical128 underlying lattice attack-cost estimates; ideal-sampling DFR <= 2^-128; no multi-user tight-security claim'})
    print('ALL CANDIDATES VERIFIED AND SELECTION SAVED',flush=True)

if __name__=='__main__':main()
