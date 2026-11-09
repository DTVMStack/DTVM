#!/usr/bin/env python3
"""Fresh-process contract screen; no build/profiling may overlap the run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import resource
import statistics
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--runner', type=Path, required=True)
p.add_argument('--artifacts', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--rounds', type=int, default=21)
p.add_argument('--warmups', type=int, default=1)
p.add_argument('--seed', type=int, default=202611101)
p.add_argument('--cpu', type=int, default=0)
p.add_argument('--cases', help='comma-separated subset of the built-in cases')
a = p.parse_args()
if a.rounds < 1 or a.warmups < 0:
    p.error('rounds must be positive and warmups nonnegative')
a.out.mkdir(parents=True, exist_ok=False)
runner = a.runner.resolve()
base = a.artifacts.resolve()
word = lambda x: x.to_bytes(32, 'big').hex()
cases = {
    'merkle-wat': ('merkle_proof.wasm', '8903c5a2', word(1)),
    'merkle-c': ('merkle_valid.wasm', '8903c5a2', word(1)),
    'generative-nft': ('generative_nft.wasm', '4a7dd523' + word(1), '18af0dc9b7cee4fb3aeb6c665aec59809c6b317e582e7e587f4e370bfe3e4db0'),
    'fibonacci-20': ('fibonacci_30.wasm', '61047ff4' + word(20), word(6765)),
}
if a.cases:
    selected = a.cases.split(',')
    if len(set(selected)) != len(selected) or not set(selected) <= cases.keys():
        p.error('unknown or duplicate case; choose: ' + ', '.join(cases))
    cases = {case: cases[case] for case in selected}
engines = ['dtvm-singlepass', 'dtvm-multipass', 'dtvm-lazy', 'wasmtime']
sha = lambda b: hashlib.sha256(b).hexdigest()
env = {k:v for k,v in os.environ.items() if not k.startswith(('DTVM_RESEARCH_', 'DTVM_PR642_')) and k != 'DTVM_TRACE_DIR'}
env['LC_ALL']='C'
# Hash the library the dynamic loader actually resolves, including overrides.
ldd = subprocess.check_output(['ldd', str(runner)], env=env, text=True)
wasmtime_lines = [line for line in ldd.splitlines() if line.strip().startswith('libwasmtime.so => ')]
if len(wasmtime_lines) != 1 or 'not found' in wasmtime_lines[0]:
    raise RuntimeError('cannot resolve the runner Wasmtime shared library')
wasmtime_lib = Path(wasmtime_lines[0].split('=>', 1)[1].strip().split(' ', 1)[0]).resolve()
manifest = {
    'runner': {'path': str(runner), 'sha256': sha(runner.read_bytes())},
    'wasmtime_library': {'path': str(wasmtime_lib), 'sha256': sha(wasmtime_lib.read_bytes())},
    'inputs': {k: {'path': str(base/v[0]), 'sha256': sha((base/v[0]).read_bytes()), 'calldata': v[1], 'expected_return': v[2]} for k,v in cases.items()},
    'engines': engines, 'cpu': a.cpu, 'rounds': a.rounds, 'warmups': a.warmups, 'seed': a.seed,
    'git_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=Path(__file__).resolve().parents[4], text=True).strip(),
    'platform': platform.platform(),
    'dynamic_loader_environment': {k:v for k,v in env.items() if k.startswith('LD_')},
    'boundary': 'fresh process before spawn to exit; module loading, compilation, instantiation, one call with native host, result, and teardown; page cache warm; native host counts on, crypto trace off; not steady-state or pure execution',
    'run_policy': 'sequential, randomized within round; engine and workers pinned to one logical CPU; collect stdout/stderr and verify identical result and host-call counts',
}
(a.out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
rng = random.Random(a.seed)
rows = []
with (a.out/'samples.jsonl').open('w', buffering=1) as f:
    for case, (module, calldata, expected_hex) in cases.items():
        expected = None
        for rnd in range(-a.warmups, a.rounds):
            order = engines.copy()
            rng.shuffle(order)
            for engine in order:
                cmd = ['taskset', '-c', str(a.cpu), str(runner), engine, str(base/module), calldata]
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                start = time.perf_counter_ns()
                result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=180)
                end = time.perf_counter_ns()
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                if result.returncode != 0:
                    raise RuntimeError((case, engine, result.returncode, result.stderr.decode(errors='replace')))
                if not result.stdout.startswith(('finish ' + expected_hex + '\n').encode()):
                    raise RuntimeError((case, engine, 'unexpected contract result', result.stdout))
                if expected is None:
                    expected = (result.stdout, result.stderr)
                if (result.stdout, result.stderr) != expected:
                    raise RuntimeError((case, engine, 'output mismatch', result.stdout, result.stderr))
                row = {'case':case, 'engine':engine, 'round':rnd, 'wall_ms':(end-start)/1e6,
                       'cpu_ms':1000*((after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime)),
                       'stdout_sha256':sha(result.stdout), 'stderr_sha256':sha(result.stderr), 'exit':result.returncode}
                rows.append(row)
                f.write(json.dumps(row)+'\n')
        print(case, {e:round(statistics.median(x['wall_ms'] for x in rows if x['case']==case and x['engine']==e and x['round']>=0),3) for e in engines}, flush=True)

summary=[]
for case in cases:
    def values(engine):
        return [x['wall_ms'] for x in rows if x['case']==case and x['engine']==engine and x['round']>=0]
    medians = {e:statistics.median(values(e)) for e in engines}
    ratios = {}
    for e in engines[:-1]:
        ratios_by_round = [x/y for x,y in zip(values(e),values('wasmtime'))]
        boots = sorted(statistics.median(rng.choices(ratios_by_round,k=len(ratios_by_round))) for _ in range(10000))
        ratios[e+'/wasmtime'] = {'median':statistics.median(ratios_by_round), 'ci95':[boots[250],boots[9750]]}
    summary.append({'case':case,'medians_ms':medians,'paired':ratios})
(a.out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
