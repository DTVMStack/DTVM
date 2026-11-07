import hashlib,json,os,subprocess
from pathlib import Path
base=Path('work/combined-optimization/v2');rev=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();os.sched_setaffinity(0,{1})
def run(cmd, log):
 print('starting',log,flush=True)
 with (base/log).open('w') as f:subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,check=True)
 print('finished',log,flush=True)
common=['--main','work/urem-research/dtvm-urem','--candidate',str(base/'dtvm-combined'),'--private',str(base/'dtvm-private'),'--wasmtime','benchmarks/paper/runtimes/wasmtime-45.0.0/out/wasmtime','--main-commit','7eb81b0','--candidate-commit',rev]
run(['python3','docs/changes/2026-11-07-anonymous-grown-pages/phase_bench.py','--inputs','work/pr643-research/phases','--out',str(base/'phase-final-r15'),'--rounds','15','--counts','1,8,30','--seed','6461103','--main','work/urem-research/dtvm-urem','--previous',str(base/'dtvm-private'),'--candidate',str(base/'dtvm-combined'),'--wasmtime','benchmarks/paper/runtimes/wasmtime-45.0.0/out/wasmtime','--main-revision','7eb81b0','--previous-revision',rev+' folding dispatch disabled','--candidate-revision',rev],'phase-final-r15.log')
run(['python3','work/combined-optimization/benchmark.py','--cases','atax,bicg,amirali,echo,md5,pi,qr2text','--rounds','31','--seed','6461104','--out',str(base/'confirm-r31'),'--variants','main,main_tier,private,private_tier,combined,combined_tier,wt45']+common,'confirm-r31.log')
# Whole-suite scout: no engine warmup; manifest input/binary hashing prewarms file pages.
# This is single-round discovery only; do not treat it as a stable ranking.
run(['python3','work/combined-optimization/benchmark.py','--suite','polybench','--rounds','1','--warmups','0','--seed','6461105','--out',str(base/'polybench-scout-r1'),'--variants','main,combined,wt45']+common,'polybench-scout-r1.log')
run(['python3','work/combined-optimization/benchmark.py','--suite','wapm','--rounds','7','--seed','6461106','--out',str(base/'wapm-final-r7'),'--variants','main,combined,combined_tier,wt45']+common,'wapm-final-r7.log')
print('all final cohorts completed',flush=True)
