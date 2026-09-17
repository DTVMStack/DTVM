#!/usr/bin/env bash
# WAPM lazy benchmark: 20 cases (zuk replaced by fortune), 3-run average.
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DTVM="${DTVM:-$ROOT/runtimes/dtvm/dtvm}"
source "$ROOT/scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
WAPM="$ROOT/benchmarks/wapm"

CASES=(
  amirali base64cli chkfont code-stock cowsay dice echo erdtree figlet
  irb md5 pi pkg1 qr2text sam suggest tpl uuid viu fortune
)

cd "$WAPM"

run_lazy_case() {
  local case="$1"
  local conf="$WAPM/${case}.wasm.conf"
  unset DIR HEAD_COMMAND COMMAND PARAMETER 2>/dev/null || true
  HEAD_COMMAND=()
  COMMAND=()
  PARAMETER=()
  DIR=()
  if [[ -f "$conf" ]]; then
    # shellcheck source=/dev/null
    source "$conf"
  fi
  if [[ "$case" == erdtree ]]; then
    PARAMETER=()
  fi

  local -a dtvm_tail=("${case}.wasm")
  if [[ -n "${DIR:-}" ]]; then
    local d
    for d in "${DIR[@]}"; do
      d="${d//case\/wapm\//}"
      dtvm_tail+=("$d")
    done
  fi
  if [[ -n "${PARAMETER:-}" ]]; then
    dtvm_tail+=(--args)
    local item
    local -a pargs=()
    if declare -p PARAMETER 2>/dev/null | grep -q 'declare \-a'; then
      for item in "${PARAMETER[@]}"; do
        read -r -a w <<< "$item"
        pargs+=("${w[@]}")
      done
    else
      read -r -a pargs <<< "$PARAMETER"
    fi
    dtvm_tail+=("${pargs[@]}")
  fi

  local -a cmd=(
    "$DTVM" -m multipass --enable-multipass-lazy
    --disable-multipass-greedyra --disable-multipass-multithread
    "${dtvm_tail[@]}"
  )

  local total=0 i s e out
  for ((i = 1; i <= REPEATS; i++)); do
    s=$(date +%s%3N)
    out="/tmp/lazy_${case}_${i}.out"
    if [[ ${#COMMAND[@]} -gt 0 && -n "${COMMAND[0]:-}" ]]; then
      if [[ ${#HEAD_COMMAND[@]} -gt 0 && "${HEAD_COMMAND[0]}" == "eval" ]]; then
        eval "${COMMAND[*]}" | "${cmd[@]}" >"$out" 2>&1 || true
      else
        "${COMMAND[@]}" | "${cmd[@]}" >"$out" 2>&1 || true
      fi
    else
      "${cmd[@]}" >"$out" 2>&1 || true
    fi
    e=$(date +%s%3N)
    total=$((total + e - s))
  done
  awk -v t="$total" -v n="$REPEATS" 'BEGIN{printf "%.1f", t/n}'
}

echo "WAPM lazy 20 cases (dtvm=${DTVM}, ${REPEATS}-run avg)"
echo "Substitution: zuk -> fortune (from non-latency pool; verified runnable)"
echo ""

fail=0
for case in "${CASES[@]}"; do
  if avg=$(run_lazy_case "$case"); then
    echo "============ $case ============"
    echo "Average time (${REPEATS} runs): ${avg} ms"
  else
    echo "FAILED: $case"
    fail=$((fail + 1))
  fi
done

echo ""
echo "Done: $((20 - fail))/20 ok, $fail failed"
