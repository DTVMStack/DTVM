#!/usr/bin/env python3
"""Cross-engine smoke tests; each invocation is a fresh contract instance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import reference

if not __debug__:
    raise SystemExit('validation must run without Python -O')

p = argparse.ArgumentParser()
p.add_argument('--runner', type=Path, required=True)
p.add_argument('--artifacts', type=Path, required=True)
p.add_argument('--results', type=Path)
a = p.parse_args()
engines = ['dtvm-interp', 'dtvm-singlepass', 'dtvm-multipass', 'dtvm-lazy', 'wasmtime']
selector = '4a7dd523'
max256 = (1 << 256) - 1
mod = max256 - 188
expected_vectors = ((max256 + 2) % mod).to_bytes(32, 'big') + ((max256 * max256) % mod).to_bytes(32, 'big') + reference.k256(b'') + bytes(32)
cases = [
    ('fibonacci-20', 'fibonacci_30', '61047ff4'+(20).to_bytes(32,'big').hex(), 0, (6765).to_bytes(32,'big')),
    ('archived-merkle', 'merkle_proof', '8903c5a2', 0, (1).to_bytes(32, 'big')),
    ('valid-merkle', 'merkle_valid', '8903c5a2', 0, (1).to_bytes(32, 'big')),
    ('invalid-merkle', 'merkle_valid', '8903c5a201', 0, bytes(32)),
    ('host-vectors', 'host_vectors', '', 0, expected_vectors),
    ('calldata-padding', 'host_copy', '010203', 0, bytes.fromhex('0203000000000000')),
    ('code-copy', 'host_code', '', 0, (a.artifacts/'host_code.wasm').stat().st_size.to_bytes(4, 'big') + b'\x00asm' + ((a.artifacts/'host_code.wasm').stat().st_size + 4).to_bytes(4, 'little') + bytes(4)),
    ('revert-selector', 'generative_nft', '00000000' + '00'*32, 2, b''),
]
for i in [0, 1, 2]:
    cases.append((f'nft-{i}', 'generative_nft', selector + i.to_bytes(32, 'big').hex(), 0, reference.nft(i).to_bytes(32, 'big')))
env={k:v for k,v in os.environ.items() if not k.startswith(('DTVM_RESEARCH_', 'DTVM_PR642_')) and k != 'DTVM_TRACE_DIR'}
results=[]
for case, module, calldata, code, expected in cases:
    by_engine=[]
    for engine in engines:
        cmd=[str(a.runner.resolve()),engine,str((a.artifacts/(module+'.wasm')).resolve()),calldata,'--trace']
        r=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, env=env)
        lines=r.stdout.splitlines()
        prefix='finish ' if code == 0 else 'revert '
        assert r.returncode == code, (case, engine, r.returncode, r.stdout, r.stderr)
        assert lines and lines[0] == prefix+expected.hex(), (case, engine, lines, expected.hex())
        assert len(lines)==3 and lines[1].startswith('counts ') and lines[2].startswith('crypto_trace '), (case,engine,lines)
        by_engine.append((lines[0],lines[1],lines[2]))
        results.append({'case':case,'engine':engine,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    assert len(set(by_engine))==1, (case, by_engine)
    print(case, 'ok', expected.hex())
# The archive WAT and our C reference execute exactly the same sequence of
# crypto host calls for the valid proof; FNV is a diagnostic, not a proof.
for engine in engines:
    x=next(r for r in results if r['case']=='archived-merkle' and r['engine']==engine)
    y=next(r for r in results if r['case']=='valid-merkle' and r['engine']==engine)
    assert x['stdout'].splitlines()[2] == y['stdout'].splitlines()[2]
for engine in engines:
    cmd=[str(a.runner.resolve()),engine,str((a.artifacts/'host_oob.wasm').resolve()),'','--trace']
    r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=60,env=env)
    assert r.returncode == 1 and not r.stdout.startswith(('finish ','revert ')), (engine,r.returncode,r.stdout,r.stderr)
    results.append({'case':'host-oob','engine':engine,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
print('host-oob ok')
for engine in engines:
    cmd=[str(a.runner.resolve()),engine,str((a.artifacts/'invalid_signature.wasm').resolve()),'']
    r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=60,env=env)
    assert r.returncode == 1 and 'call must have type () -> ()' in r.stderr, (engine,r.returncode,r.stdout,r.stderr)
    results.append({'case':'invalid-signature','engine':engine,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
print('invalid-signature ok')
assert reference.archived_merkle()[0] == 0
print('Solidity source reference: archived source returns false; WAT valid proof returns true')
if a.results:
    a.results.write_text(json.dumps({'runner_sha256':hashlib.sha256(a.runner.read_bytes()).hexdigest(),
      'wasm_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in a.artifacts.glob('*.wasm')},
      'results':results},indent=2)+'\n')
print(f'{len(results)} engine/case checks passed')
