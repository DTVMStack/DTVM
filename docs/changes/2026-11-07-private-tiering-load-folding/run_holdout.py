import os,subprocess,time
from pathlib import Path
base=Path('work/combined-optimization/v2');os.sched_setaffinity(0,{1})
while 'all final cohorts completed' not in (base/'final-stages.log').read_text():
 if not Path('/proc/577519').exists():raise RuntimeError('final cohort runner exited before completion')
 time.sleep(1)
cmd=['python3','work/combined-optimization/benchmark.py','--suite','polybench','--cases','heat-3d,syr2k','--rounds','7','--seed','6461107','--out',str(base/'poly-holdout-r7'),'--variants','main,private,combined,wt45','--main','work/urem-research/dtvm-urem','--candidate',str(base/'dtvm-combined'),'--private',str(base/'dtvm-private'),'--wasmtime','benchmarks/paper/runtimes/wasmtime-45.0.0/out/wasmtime','--main-commit','7eb81b0','--candidate-commit','58b0fd3']
with (base/'poly-holdout-r7.log').open('w') as f:subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,check=True)
