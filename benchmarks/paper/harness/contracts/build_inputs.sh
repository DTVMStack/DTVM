#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../../.." && pwd)
out=${1:?usage: build_inputs.sh OUTPUT_DIR}
mkdir -p "$out"
for case_name in merkle_proof generative_nft fibonacci_30; do
  wat2wasm --enable-annotations "$root/benchmarks/paper/benchmarks/contracts/bench_wat/$case_name.wat" -o "$out/$case_name.wasm"
done
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export=call -Wl,--export-memory -Wl,--allow-undefined \
  "$root/benchmarks/paper/benchmarks/contracts/bench_c/merkle_valid.c" -o "$out/merkle_valid.wasm"
wasm2wat "$out/merkle_valid.wasm" -o "$out/merkle_valid.wat"
for case_name in host_vectors host_oob host_copy host_code invalid_signature; do
  wat2wasm "$root/benchmarks/paper/harness/contracts/fixtures/$case_name.wat" -o "$out/$case_name.wasm"
done
sha256sum "$out/"*.wasm > "$out/SHA256SUMS"
