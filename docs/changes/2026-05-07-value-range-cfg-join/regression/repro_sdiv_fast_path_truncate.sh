#!/usr/bin/env bash
# Reproduce the SDIV soundness divergence between evmone reference and
# DTVM multipass on a bytecode that crosses a lifted JUMPDEST and feeds
# a bothFitU64-gated ADD.  See README.md for the bytecode breakdown.
#
# Without arguments: runs both VMs under current code, expects equal output.
# With --buggy (after `git revert --no-commit 5d46f7e` + rebuild in the
# parent worktree), expects DIVERGENT output.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEX_FILE="$HERE/sdiv_sign_mismatch_repro.hex"
WORKTREE_ROOT="$(cd "$HERE/../../../.." && pwd)"
DTVM_SO="$WORKTREE_ROOT/build/lib/libdtvmapi.so"
EVMONE_BIN="${EVMONE_BIN:-$HOME/evmone/build/bin/evmc}"
EVMONE_SO="${EVMONE_SO:-$HOME/evmone/build/lib/libevmone.so}"

if [[ ! -f "$DTVM_SO" ]]; then
  echo "ERROR: DTVM library not found at $DTVM_SO" >&2
  echo "       run \`cmake --build build --target dtvmapi\` in $WORKTREE_ROOT first." >&2
  exit 2
fi
if [[ ! -x "$EVMONE_BIN" || ! -f "$EVMONE_SO" ]]; then
  echo "ERROR: evmone reference VM not found (looked for $EVMONE_BIN / $EVMONE_SO)" >&2
  exit 2
fi

CODE="$(cat "$HEX_FILE")"

extract_output() {
  local vm_arg="$1"
  "$EVMONE_BIN" run --vm "$vm_arg" "0x$CODE" 2>&1 | awk '/^Output:/ {print $2}'
}

echo "Bytecode: $CODE"
echo "Expected real result:                     fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc  (-4 in signed 256-bit)"
echo "Buggy truncated (low 64 bits only):       000000000000000000000000000000000000000000000000fffffffffffffffc"
echo

REF_OUT="$(extract_output "$EVMONE_SO")"
DTVM_OUT="$(extract_output "$DTVM_SO,mode=multipass")"

printf '%-40s  %s\n' "evmone (spec reference)" "$REF_OUT"
printf '%-40s  %s\n' "DTVM multipass" "$DTVM_OUT"

if [[ "${1:-}" == "--buggy" ]]; then
  if [[ "$DTVM_OUT" == "$REF_OUT" ]]; then
    echo
    echo "FAIL: --buggy mode expected divergence but DTVM matched reference."
    echo "      Did the SDIV/SMOD fix in commit 5d46f7e actually get reverted?"
    exit 1
  fi
  echo
  echo "PASS: DTVM diverges from evmone reference as expected under the buggy build."
else
  if [[ "$DTVM_OUT" != "$REF_OUT" ]]; then
    echo
    echo "FAIL: DTVM multipass output does not match evmone reference."
    echo "      If commit 5d46f7e is currently reverted, run with --buggy."
    exit 1
  fi
  echo
  echo "PASS: DTVM multipass matches evmone reference."
fi
