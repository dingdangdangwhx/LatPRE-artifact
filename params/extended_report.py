#!/usr/bin/env python3
"""Summarize the selected supplementary profiles and measured API costs."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent

def table(headers,rows):
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']+
        ['| '+' | '.join(map(str,r))+' |' for r in rows])

def write_csv(path,rows):
    with path.open('w',newline='') as f:
        out=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');out.writeheader();out.writerows(rows)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--directory',type=Path,default=ROOT/'results/extended-classical128')
    args=ap.parse_args();folder=args.directory.resolve()
    selected=json.loads((folder/'selected.json').read_text())
    local_manifest=folder/'implementation-parameters.json'
    manifest=json.loads((local_manifest if local_manifest.exists() else ROOT/'latpre/EXTENDED_PARAMETER_SOURCE.json').read_text())
    assert manifest['selection_file_sha256']==hashlib.sha256((folder/'selected.json').read_bytes()).hexdigest()
    current_parameters={r['name']:r for r in manifest['generated_parameters']}
    benchmarks=[];source_runs=[]
    for path in [folder/'benchmark.json',*sorted(folder.glob('benchmark-E*.json'))]:
        bench=json.loads(path.read_text())
        if bench['parameter_sha256']==manifest['parameter_sha256']:build_manifest=manifest
        else:
            snapshot=folder/'implementation-manifests'/(bench['parameter_sha256']+'.json')
            build_manifest=json.loads(snapshot.read_text())
        built_parameters={r['name']:r for r in build_manifest['generated_parameters']}
        for row in bench['results']:
            assert built_parameters[row['profile']]==current_parameters[row['profile']]
        benchmarks.extend(bench['results'])
        source_runs.append({'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                            'parameter_sha256':bench['parameter_sha256']})
    old=json.loads((folder/'frozen-input-hashes.json').read_text())
    assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==value for name,value in old.items())
    observations={}
    for row in benchmarks:
        group=observations.setdefault(row['profile'],{})
        assert row['operation'] not in group,('duplicate measurement',row['profile'],row['operation'])
        group[row['operation']]=row
        assert row['samples']==1000 and row['warmup']==10
    assert set(observations)==set(selected['profiles'])
    params=[];comms=[];times=[];display=[];timedisplay=[]
    ops=('Setup','KeyGen','Enc','DecSource','ReKeyGen','ReKeyPrepare','ReKeyGenPrepared','ReEnc','DecTerminal')
    for name,item in selected['profiles'].items():
        r=item['runtime'];s=r['sizes_bytes'];measured=observations[name]
        for b in measured.values():
            for raw,key in [('PK_bytes','public_key_bytes'),('SK_bytes','secret_key_bytes'),('RK_bytes','rekey_bytes'),('source_bytes','source_ct_bytes'),('RE_bytes','reenc_ct_bytes')]:
                assert b[raw]==s[key],(name,raw)
        costs={key:value['min_bits'] for key,value in item['security'].items()}
        para={'profile':name,'log2_Q':r['logQ'],'log2_M':r['logM'],'d':256,'k':r['k'],'ell':r['ell'],
          'q':r['q'],'ceil_log2_q':r['q_bits'],'eta':1,'eta_T':r['terminal_eta'],
          'sigma_H':item['candidate']['sigma_H'],'sigma_S':r['sigma_source'],'sigma_y':r['sigma_pad'],
          'source_std':r['source_std'],'pad_std':r['pad_std'],'gadget_base':r['base'],'gadget_length':r['length'],
          'gadget_columns':r['k']*r['length'],'t_v':r['source_v_bits'],'t_re_u':r['re_u_bits'],'t_re_v':r['re_v_bits'],
          'minimum_classical_lattice_bits':min(costs.values()),'ideal_DFR_log2_upper':item['dfr']['joint_log2_upper']}
        params.append(para)
        comm={'profile':name,'log2_Q':r['logQ'],'log2_M':r['logM']}
        for key in ('public_key_bytes','secret_key_bytes','source_ct_bytes','reenc_ct_bytes','rekey_body_bytes','rekey_seed_bytes','rekey_bytes'):
            comm[key]=s[key];comm[key.replace('_bytes','_KB')]=s[key]/1024
        comm['public_matrix_bytes']=measured['Setup']['global_A_bytes']
        comm['prepared_rekey_RAM_bytes']=measured['ReEnc']['prepared_rekey_RAM_bytes']
        comms.append(comm)
        timing={'profile':name}
        for op in ops:timing[op+'_ms']=measured[op]['median_ns']/1e6
        times.append(timing)
        display.append([f'2^{r["logQ"]}',f'2^{r["logM"]}',f'({r["k"]},{r["ell"]})',r['q_bits'],
          f'{s["public_key_bytes"]/1024:.2f}',f'{s["secret_key_bytes"]/1024:.2f}',f'{s["source_ct_bytes"]/1024:.2f}',
          f'{s["reenc_ct_bytes"]/1024:.2f}',f'{s["rekey_bytes"]/1024:.2f}'])
        timedisplay.append([name]+[f'{timing[op+"_ms"]:.3f}' for op in ops])
    write_csv(folder/'parameters.csv',params);write_csv(folder/'communication.csv',comms);write_csv(folder/'runtime.csv',times)
    shortlist=json.loads((folder/'certified-candidates.json').read_text())
    text=['# Supplementary classical-128 parameter sets','',
      'Optional reference data; the paper\'s frozen L/M/H parameters and measurements are unchanged. E20_10 repeats paper Light.',
      '', 'All selected lattice instances passed all eight pinned MATZOV/GSA attack estimates, including the finite uSVP block scan. '
      'Directed spectral/Gaussian checks and 512-bit C-PMF-assisted correctness bounds passed. Security is an underlying-instance '
      'attack-cost estimate; correctness assumes ideal sampling. The implementation uses the same approximate OpenFHE-style sampler.',
      '', '## Selected communication costs (KB)', '',
      table(['Q','M','(k,ell)','ceil(log2 q)','PK','SK','Source CT','RE CT','Rekey'],display),
      '', 'Sizes include both key roles and the 32-byte rekey seed; 1 KB = 1024 bytes. Full moduli, widths, compression parameters and bounds are in `parameters.csv` and `selected.json`.',
      '', 'Uncompressed rekeys occupy `32(k+1)k Lg ceil(log2 q) + 32` bytes. E60_30 has k=9, Lg=2 and 57-bit coefficients: 180 ring elements of 1,824 bytes each, plus the seed, give 328,352 bytes (320.66 KB). The usage budget M affects parameter selection through the masking bound; it does not multiply the size of an individual rekey.',
      '', '## Measured computation costs (ms)', '',
      table(['Profile','Setup','KeyGen','Enc','DecSource','ReKeyGen','Prepare','ReKeyGen + Prepare','ReEnc','DecRE'],timedisplay),
      '', 'Single thread, 1,000 measurements after 10 warmups per operation; the table reports medians. ReKeyGen excludes NTT preparation; ReEnc uses a prepared rekey and recomputes its mask. `benchmark.json` and `benchmark-E*.json` retain individual samples and extra diagnostic operations. Added profiles are measured separately; earlier measurements are preserved, with the corresponding numeric-parameter manifests.',
      '', '## Candidate selection', '',
      'The finite search first minimizes the sum of source and re-encrypted ciphertext bytes, then permits at most 128 extra bytes for a smaller rekey. The original Light set is retained for the duplicated budget. No global optimum is claimed. The first CBD1 terminal attempt at (Q,M)=(2^20,2^15) was rejected at 127.20 bits; its failed estimate is retained in `security/`.',
      '']
    for name,group in shortlist['results'].items():
        rows=[]
        chosen=selected['profiles'][name]['id']
        for r in group:
            s=r['runtime']['sizes_bytes']
            g=r['runtime']
            rows.append([r['id']+(' (selected)' if r['id']==chosen else ''),f"{g['base']}/{g['length']}",s['source_ct_bytes'],s['reenc_ct_bytes'],s['rekey_bytes'],
              f'{min(x["min_bits"] for x in r["security"].values()):.2f}',f'{float(r["dfr"]["joint_log2_upper"]):.2f}'])
        text.extend(['### '+name,'',table(['Candidate','Base/length','Source (B)','RE (B)','Rekey (B)','Min bits','log2 DFR bound'],rows),''])
    text.extend(['## Reproduce', '', 'From the artifact root:', '', '```sh','make -C latpre all test',
      './latpre/build/bench_lbpre --profiles '+','.join(selected['profiles'])+' --samples 1000 --warmup 10 --all-operations --csv /tmp/extended.csv --json /tmp/extended.json',
      'sage -python params/extended_certify.py --verify-only','```','',
      '`params/extended_search.py` reruns the small floating search; `extended_certify.py` performs missing full security/C calculations serially and caches exact instances. `params/export_extended.py` regenerates the named C profiles from the verified selection. Runtime varies with the machine.', '',
      'For E60_30, wider masks use the existing Karney algorithm with exact integer arithmetic for the proposal origin, avoiding loss of integer units above the binary64 mantissa range. Original L/M/H sampler streams are preserved; finite-precision statistical error remains uncertified.',''])
    (folder/'README.md').write_text('\n'.join(text))
    (folder/'summary.json').write_text(json.dumps({'parameters':params,'communication':comms,'runtime_ms':times,'source_benchmarks':source_runs,'frozen_files_unchanged':True},indent=2)+'\n')
    print(table(['Q','M','(k,ell)','logq','PK KB','SK KB','Source KB','RE KB','RK KB'],display))
    print(table(['Set']+list(ops),timedisplay))

if __name__=='__main__':main()
