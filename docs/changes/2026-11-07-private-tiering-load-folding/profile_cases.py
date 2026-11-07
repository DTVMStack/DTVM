"""Untimed native capture. Never run concurrently with the formal survey."""
import bisect,collections,gzip,hashlib,importlib.util,json,os,re,struct,subprocess,sys,time
from pathlib import Path
root=Path.cwd(); base=root/'work/combined-optimization/v2'; out=base/'profiles';out.mkdir(exist_ok=True)
os.sched_setaffinity(0,{1})
s=importlib.util.spec_from_file_location('h','benchmarks/paper/harness/run.py');h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
cs={c['id']:c for c in h.load_cases(h.read_json(h.CATALOG_PATH))};cs['pi1000']={**cs['pi'],'id':'pi1000','args':['1000']}
phase_inputs=json.loads((root/'work/pr643-research/phases/phase-inputs.json').read_text())
for case in ['atax','bicg']:
 cs[case+'-repeat30']={**cs[case],'id':case+'-repeat30','wasm':phase_inputs[case+':30']['wasm']}
binary=base/'dtvm-combined-diagnostic'; wt=root/'benchmarks/paper/runtimes/wasmtime-45.0.0/out/wasmtime'
refrows=[json.loads(l) for l in (root/'work/combined-optimization/pilot-r9/samples.jsonl').read_text().splitlines()]
for name in sys.argv[1].split(','):
 c=cs[name]
 for engine in (sys.argv[2].split(',') if len(sys.argv)>2 else ['main','serial','wt45']):
  folder=out/(name+'-'+engine);folder.mkdir(exist_ok=False);pcfile=folder/'samples.bin'
  env={**os.environ,'LC_ALL':'C','WASMTIME_CACHE':'0','LD_PRELOAD':str(root/'work/urem-research/sampler.so'),'DTVM_RESEARCH_SAMPLES':str(pcfile)}
  if engine!='wt45':env['DTVM_RESEARCH_NATIVE_DIR']=str(folder)
  cmd=h.wasmtime_cmd(wt,c) if engine=='wt45' else h.dtvm_cmd(binary,c,'lazy-G-MT',False)
  if engine=='serial':cmd.insert(1,'--disable-multipass-multithread')
  if engine=='policy':cmd.insert(1,'--enable-lazy-private-tiering')
  if engine=='wt45':cmd.insert(2,'--profile=perfmap')
  entries=[]
  if engine=='wt45':
   p=subprocess.Popen(cmd,cwd=h.case_cwd(c),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,preexec_fn=lambda:os.sched_setaffinity(0,{0}))
   path=Path('/tmp')/f'perf-{p.pid}.map';deadline=time.monotonic()+180
   while p.poll() is None and time.monotonic()<deadline:
    if path.exists():
     lines=path.read_text().splitlines()
     wanted=[line.split(' ',2) for line in lines if len(line.split(' ',2))==3 and not any(x in line.split(' ',2)[2] for x in ['trampoline','wasmtime_builtin'])]
     if wanted and any('trampoline' in line for line in lines):
      try:
       with Path(f'/proc/{p.pid}/mem').open('rb',buffering=0) as mem:
        for i,(addr,size,label) in enumerate(wanted):
         addr=int(addr,16);size=int(size,16);mem.seek(addr);data=mem.read(size);assert len(data)==size
         f=folder/f'func-{i}.bin';f.write_bytes(data);entries.append({'address':addr,'size':size,'name':label,'file':f.name})
       (folder/'perf.map').write_text('\n'.join(lines)+'\n');break
      except (ProcessLookupError,FileNotFoundError):pass
    time.sleep(.001)
   stdout,stderr=p.communicate(timeout=180);code=p.returncode;assert entries,(name,'capture failed')
  else:
   r=subprocess.run(cmd,cwd=h.case_cwd(c),input=c.get('stdin','').encode(),capture_output=True,env=env,timeout=180,preexec_fn=lambda:os.sched_setaffinity(0,{0}));stdout,stderr,code=r.stdout,r.stderr,r.returncode
   pat=rb'NATIVE (\d+) (\d+) ([0-9a-f]+) (\d+) (\d+)\n'
   for idx,tier,address,size,ns in re.findall(pat,stderr):
    idx=int(idx);tier=int(tier);addr=int(address,16)
    entries.append({'index':idx,'greedy':tier,'address':addr,'size':int(size),'compile_ns':int(ns),'name':str(idx),'file':f'func-{idx}-{tier}-{addr:x}.bin'})
   stderr=re.sub(pat,b'',stderr)
  assert code==0,(name,engine,code,stderr[-500:])
  hashes={s+'_sha256':hashlib.sha256(data).hexdigest() for s,data in [('stdout',stdout),('stderr',stderr)]}
  ref=[r for r in refrows if r['case']==name and r['variant']==('wt45' if engine=='wt45' else 'main') and r['exit']==0]
  if name.endswith('-repeat30'):
   original=name.removesuffix('-repeat30')
   expected=gzip.decompress((root/'work/combined-optimization/pilot-r9'/f'{original}.main.0.stderr.gz').read_bytes())*30
   assert stderr==expected and len(stdout)==56*30,(name,engine,'derived output mismatch')
   assert all(list(t)==sorted(t) for t in struct.iter_unpack('<7Q',stdout))
  else:
   assert ref and all(all(r[k]==v for k,v in hashes.items()) for r in ref),(name,engine,'output mismatch')
  pcs=list(struct.iter_unpack('<QQ',pcfile.read_bytes()));entries.sort(key=lambda e:e['address']);starts=[e['address'] for e in entries];hits=collections.defaultdict(collections.Counter)
  for pc,tid in pcs:
   i=bisect.bisect_right(starts,pc)-1
   if i>=0 and pc<starts[i]+entries[i]['size']:hits[i][pc-starts[i]]+=1
  for i,e in enumerate(entries):
   e['samples']=sum(hits[i].values());e['pc_offsets']=dict(hits[i])
   if e['samples']>=5 or e.get('index')==9:
    f=folder/e['file'];asm=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64',str(f)],text=True)
    with gzip.open(f.with_suffix('.asm.gz'),'wb') as z:z.write(asm.encode())
  result={'case':name,'engine':engine,'command':cmd,'exit':code,'total_samples':len(pcs),'jit_samples':sum(e['samples'] for e in entries),'events':entries,**hashes,'method':'Untimed diagnostic, SIGPROF with requested 1 ms interval (actual kernel granularity may be coarser); includes startup and compile; static byte dumps include pools. Dumping perturbs policy elapsed budgets. PC samples are descriptive, not instruction retired counts.'}
  (folder/'profile.json').write_text(json.dumps(result,indent=2)+'\n')
  print(name,engine,result['total_samples'],sorted([(e['name'],e.get('greedy'),e['samples'],e['size']) for e in entries],key=lambda x:-x[2])[:5],flush=True)
