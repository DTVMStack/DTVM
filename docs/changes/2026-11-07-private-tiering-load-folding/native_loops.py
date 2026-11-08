"""Offline CFG/natural-loop census of captured code; no performance timing."""
import collections,gzip,json,re,subprocess
from pathlib import Path
base=Path('work/combined-optimization/v2/profiles'); result=[]
for profile in sorted(base.glob('*/profile.json')):
 p=json.loads(profile.read_text()); folder=profile.parent
 for event in p['events']:
  if event['samples']<5:continue
  f=folder/event['file']; asm=subprocess.check_output(['objdump','-D','--no-show-raw-insn','-b','binary','-m','i386:x86-64',str(f)],text=True)
  ins={}
  for line in asm.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+([a-z][a-z0-9]*)\s*(.*)$',line)
   if m:ins[int(m[1],16)]=(m[2],m[3])
  if 0 not in ins:continue
  seq=sorted(ins); nxt=dict(zip(seq,seq[1:])); succ={}; unresolved=[]
  for a,(op,args) in ins.items():
   edges=[]
   if op.startswith('j'):
    m=re.match(r'^(?:0x)?([0-9a-f]+)(?:\s|$)',args)
    target=int(m[1],16) if m else None
    if target in ins:edges.append(target)
    else:unresolved.append(a)
   if not(op.startswith('ret') or op in ('ud2','int3','hlt','jmp','jmpq')) and a in nxt:edges.append(nxt[a])
   succ[a]=edges
  reached=set(); todo=[0]
  while todo:
   a=todo.pop()
   if a in reached:continue
   reached.add(a);todo+=succ[a]
  # Collapse straight-line instruction edges into basic blocks.
  leaders={0}
  for a in reached:
   if ins[a][0].startswith('j'):
    leaders.update(succ[a])
    if a in nxt and nxt[a] in reached:leaders.add(nxt[a])
  groups={};owner={};current=None
  for a in seq:
   if a not in reached:current=None;continue
   if a in leaders or current is None:current=a;groups[current]=[]
   groups[current].append(a);owner[a]=current
  bs={b:{owner[x] for x in succ[v[-1]] if x in owner} for b,v in groups.items()};pred={b:set() for b in bs}
  for b,edges in bs.items():
   for x in edges:pred[x].add(b)
  allb=set(bs); dom={b:({0} if b==0 else set(allb)) for b in bs}; changed=True
  while changed:
   changed=False
   for b in sorted(allb-{0}):
    d={b}|set.intersection(*(dom[x] for x in pred[b])) if pred[b] else {b}
    if d!=dom[b]:dom[b]=d;changed=True
  loops={}
  for tail,edges in bs.items():
   for header in edges:
    if header not in dom[tail]:continue
    members={header,tail};todo=[] if tail==header else [tail]
    while todo:
     b=todo.pop()
     for x in pred[b]:
      if x not in members:members.add(x);todo.append(x)
    loops.setdefault(header,set()).update(members)
  pcs={int(k):v for k,v in event['pc_offsets'].items()}
  rows=[]
  for header,members in loops.items():
   addresses=[a for b in members for a in groups[b]]; lo=min(members);hi=max(members)
   hits=sum(n for a,n in pcs.items() if any(b<=a<nxt.get(groups[b][-1],event['size']) for b in members))
   ops=[ins[a] for a in addresses]
   rows.append({'header':header,'innermost':not any(other<members for other in loops.values()),'blocks':len(members),'holes':[b for b in sorted(allb-members) if lo<b<hi],'samples_in_blocks':hits,'instructions':len(addresses),'fp_div':sum(op in ('divsd','divss','vdivsd','vdivss') for op,args in ops),'frame_memory_ops':sum(op!='lea' and bool(re.search(r'\([^)]*%(?:rbp|rsp)',args)) for op,args in ops),'fp_register_loads':sum(op in ('movsd','movss','vmovsd','vmovss') and '(' in args.split(',%') [0] and bool(re.search(r',%xmm\d+$',args)) for op,args in ops),'fp_folded_mul':sum(op in ('mulsd','mulss','vmulsd','vmulss') and '(' in args for op,args in ops),'cl_shifts':sum(op.startswith(('shl','shr','sar')) and '%cl' in args for op,args in ops),'bmi2_shifts':sum(op.startswith(('shlx','shrx','sarx')) for op,args in ops)})
  rows.sort(key=lambda r:-r['samples_in_blocks'])
  out={'case':p['case'],'engine':p['engine'],'event':{k:v for k,v in event.items() if k!='pc_offsets'},'reachable_instructions':len(reached),'unresolved_reachable':[a for a in unresolved if a in reached],'loops':rows,'note':'Natural loops from final native CFG, not pre-RA layout; static instruction counts; samples assigned by block byte intervals; nested loops overlap.'}
  result.append(out)
Path('work/combined-optimization/v2/native-loops.json').write_text(json.dumps(result,indent=2)+'\n')
for r in result:
 if r['event']['samples']>=20:print(r['case'],r['engine'],r['event']['name'],r['event']['samples'],r['loops'][:2])
