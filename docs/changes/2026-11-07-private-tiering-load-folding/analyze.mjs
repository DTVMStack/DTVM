// node analyze.mjs <evidence/cohort>; process-paired, pointwise exploratory CIs.
import fs from 'node:fs';
import zlib from 'node:zlib';
const dir = process.argv[2];
const manifest = JSON.parse(fs.readFileSync(`${dir}/manifest.json`));
const rows = zlib.gunzipSync(fs.readFileSync(`${dir}/samples.jsonl.gz`))
  .toString().trim().split('\n').map(JSON.parse);
const median = xs => {
  const a = [...xs].sort((a, b) => a - b);
  return (a[(a.length - 1) >> 1] + a[a.length >> 1]) / 2;
};
function estimate(xs) {
  let z = 6461199;
  const random = () => {
    z ^= z << 13; z ^= z >>> 17; z ^= z << 5;
    return (z >>> 0) / 4294967296;
  };
  const boot = xs.length >= 5 ? Array.from({length: 10000}, () =>
    median(xs.map(() => xs[Math.floor(random() * xs.length)])))
    .sort((a, b) => a - b) : null;
  return {median: median(xs), ci95: boot ? [boot[249], boot[9749]] : null};
}
const comparisons = [['private','main'], ['combined','main'],
  ['combined','private'], ['main_tier','main'],
  ['private_tier','main_tier'], ['combined_tier','main_tier'],
  ['combined_tier','private_tier'], ['combined_tier','main'],
  ['combined_tier','combined'], ['combined','wt45'], ['combined_tier','wt45']];
const result = [];
for (const name of [...new Set(rows.map(r => r.case))]) {
  const rs = rows.filter(r => r.case === name);
  const variants = Object.keys(manifest.binaries);
  const g = Object.fromEntries(variants.map(v => [v,
    new Map(rs.filter(r => r.variant === v).map(r => [r.round,r]))]));
  if (rs.length !== variants.reduce((n,v) => n+g[v].size, 0))
    throw Error(`duplicate ${name}`);
  const failed = rs.some(r => r.exit !== 0 || r.timeout);
  const warmup = manifest.excluded_warmup === -1 ? [-1] : [];
  const expected = failed ? warmup : [...warmup,
    ...Array.from({length:manifest.rounds}, (_,i) => i)];
  for (const v of variants)
    if (g[v].size !== expected.length || expected.some(i => !g[v].has(i)))
      throw Error(`incomplete ${name} ${v}`);
  if (failed) { result.push({case:name,failed:true}); continue; }
  if (!['fortune','uuid'].includes(name))
    for (const stream of ['stdout','stderr'])
      if (new Set(rs.map(r => r[`${stream}_sha256`])).size !== 1)
        throw Error(`output mismatch ${name} ${stream}`);
  const rounds = Array.from({length:manifest.rounds}, (_,i) => i);
  const item = {case:name,n:manifest.rounds,medians_ms:{},paired:{}};
  for (const v of variants)
    item.medians_ms[v] = median(rounds.map(i => g[v].get(i).wall_ms));
  for (const [a,b] of comparisons)
    if (g[a] && g[b]) item.paired[`${a}/${b}`] =
      estimate(rounds.map(i => g[a].get(i).wall_ms/g[b].get(i).wall_ms));
  result.push(item);
}
fs.writeFileSync(`${dir}/summary.json`, JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result,null,2));
