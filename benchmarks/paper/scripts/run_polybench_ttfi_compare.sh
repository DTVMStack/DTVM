#!/usr/bin/env bash
# PolyBench/C TTFI (Total compilation time) — same metric as WAPM scripts.
#
# Parses stdout:
#   Total compilation time: <ms> ms (<µs> μs)
#   Execution N: <ms> ms
#
# Usage:
#   run_polybench_ttfi_compare.sh <runtime> [profile] [repeats] [out_dir]
#   runtime: dtvm | wasmtime | wasmer
#   profile: dtvm multipass_greedy_mt | wasmer singlepass|cranelift|llvm | wasmtime default
set -euo pipefail

RUNTIME="${1:?runtime: dtvm|wasmtime|wasmer}"
PROFILE="${2:-default}"
REPEATS="${3:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CASE_DIR="${CASE_DIR:-$ROOT/benchmarks/polybenchc}"

if [[ $# -ge 4 && -n "${4:-}" ]]; then
  OUT="${4}"
else
  tag="$RUNTIME"
  [[ "$RUNTIME" == wasmer ]] && tag="wasmer_${PROFILE}"
  [[ "$RUNTIME" == dtvm ]] && tag="dtvm_${PROFILE}"
  OUT="$ROOT/raw_data/benchs/polybench_${tag}_ttfi_$(date +%Y%m%d_%H%M%S)"
fi
[[ "$OUT" != /* ]] && OUT="$ROOT/$OUT"

DTVM="${DTVM:-$ROOT/runtimes/dtvm_main/dtvm}"
source "$ROOT/scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
WASMTIME="${WASMTIME:-$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime}"
WASMER="${WASMER:-$ROOT/runtimes/wasmer-7.1.0/out/wasmer}"
WASMTIME_CACHE_DIR="${WASMTIME_CACHE_DIR:-$HOME/.cache/wasmtime}"
CLEAR_WASMTIME_CACHE="${CLEAR_WASMTIME_CACHE:-1}"

export WASMTIME_CACHE=0

mkdir -p "$OUT/logs"

mapfile -t CASES < <(find "$CASE_DIR" -maxdepth 1 -name '*.wasm' -printf '%f\n' | sed 's/\.wasm$//' | sort)

clear_wasmtime_cache() {
  if [[ "$CLEAR_WASMTIME_CACHE" == "1" ]]; then
    rm -rf "$WASMTIME_CACHE_DIR"
  fi
}

run_one() {
  local case="$1" log="$2"
  case "$RUNTIME" in
    dtvm)
      case "$PROFILE" in
        multipass_greedy_mt)
          "$DTVM" "${case}.wasm" -m multipass --enable-statistics \
            >"$log" 2>&1 || true
          ;;
        lazy)
          # WAPM paper: multipass lazy, greedy RA + MT off
          "$DTVM" "${case}.wasm" -m multipass --enable-multipass-lazy \
            --disable-multipass-greedyra --disable-multipass-multithread \
            --enable-statistics >"$log" 2>&1 || true
          ;;
        lazy_greedy_mt)
          "$DTVM" "${case}.wasm" -m multipass --enable-multipass-lazy --enable-statistics \
            >"$log" 2>&1 || true
          ;;
        multipass)
          "$DTVM" "${case}.wasm" -m multipass \
            --disable-multipass-greedyra --disable-multipass-multithread \
            --enable-statistics >"$log" 2>&1 || true
          ;;
        *)
          echo "unknown dtvm profile: $PROFILE" >&2
          return 2
          ;;
      esac
      ;;
    wasmtime)
      clear_wasmtime_cache
      "$WASMTIME" run "$CASE_DIR/${case}.wasm" --invoke main >"$log" 2>&1 || true
      ;;
    wasmer)
      "$WASMER" run "--${PROFILE}" --cache-dir=/dev/null \
        "$CASE_DIR/${case}.wasm" -q >"$log" 2>&1 || true
      ;;
    *)
      echo "unknown runtime: $RUNTIME" >&2
      return 2
      ;;
  esac
}

echo "PolyBench TTFI -> $OUT"
echo "  runtime: $RUNTIME  profile: $PROFILE"
echo "  repeats: $REPEATS"
case "$RUNTIME" in
  dtvm) echo "  binary: $DTVM" ;;
  wasmtime)
    echo "  binary: $WASMTIME"
    echo "  WASMTIME_CACHE=0  clear_cache=$CLEAR_WASMTIME_CACHE"
    ;;
  wasmer) echo "  binary: $WASMER  --cache-dir=/dev/null" ;;
esac
echo "  cases: ${#CASES[@]}"
echo ""

cd "$CASE_DIR"
for case in "${CASES[@]}"; do
  echo ">> $case"
  for ((r = 1; r <= REPEATS; r++)); do
    run_one "$case" "$OUT/logs/${case}_${r}.log"
  done
done

RUNTIME="$RUNTIME" PROFILE="$PROFILE" REPEATS="$REPEATS" OUT="$OUT" python3 <<'PY'
import re
from pathlib import Path
from statistics import mean

runtime = __import__("os").environ["RUNTIME"]
profile = __import__("os").environ["PROFILE"]
repeats = int(__import__("os").environ["REPEATS"])
out = Path(__import__("os").environ["OUT"])

compile_re = re.compile(r"Total compilation time: \d+ ms \((\d+) [μµ]s\)")
exec_re = re.compile(r"Execution \d+: ([\d.]+) ms")

cases = sorted({p.stem.rsplit("_", 1)[0] for p in out.glob("logs/*.log")})
rows = []
for case in cases:
    compiles, execs = [], []
    for r in range(1, repeats + 1):
        log = out / "logs" / f"{case}_{r}.log"
        if not log.exists():
            continue
        text = log.read_text(encoding="utf-8", errors="replace")
        cm = compile_re.search(text)
        if cm:
            compiles.append(int(cm.group(1)) / 1000.0)
        em = exec_re.search(text)
        if em:
            execs.append(float(em.group(1)))
    if not compiles:
        rows.append((case, None, None))
        continue
    rows.append((case, mean(compiles), mean(execs) if execs else None))

csv = out / "results.csv"
with csv.open("w") as f:
    f.write("case,compile_ms,execution_ms\n")
    for case, c, e in rows:
        cs = "" if c is None else f"{c:.3f}"
        es = "" if e is None else f"{e:.3f}"
        f.write(f"{case},{cs},{es}\n")

md = [
    f"# PolyBench TTFI (`{runtime}`",
]
if runtime != "wasmtime":
    md[0] += f" / `{profile}`"
md[0] += ")\n\n"
md += [
    f"- Repeats: **{repeats}** per case\n",
    "- **compile**: `Total compilation time` in stdout (WAPM metric)\n",
    "- **exec**: first `Execution N` line\n",
    "\n| case | compile ms | exec ms |\n",
    "|---|---:|---:|\n",
]
ok = 0
for case, c, e in rows:
    if c is None:
        md.append(f"| {case} | n/a | n/a |\n")
    else:
        ok += 1
        es = f"{e:.3f}" if e is not None else "n/a"
        md.append(f"| {case} | {c:.3f} | {es} |\n")
compiles = [c for _, c, _ in rows if c is not None]
if compiles:
    md.append(f"\n**Cases with compile line:** {ok}/{len(rows)}\n")
    md.append(f"**Median compile ms:** {sorted(compiles)[len(compiles)//2]:.3f}\n")
    md.append(f"**Mean compile ms:** {mean(compiles):.3f}\n")
(out / "COMPARE.md").write_text("".join(md))
print(f"Wrote {csv}")
print(f"Wrote {out / 'COMPARE.md'}")
PY

echo ""
echo "Done: $OUT/COMPARE.md"
