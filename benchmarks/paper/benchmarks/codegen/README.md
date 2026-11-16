# Compiler diagnostic benchmarks

`wide_compare.wat` performs dynamic lexicographic comparisons of two unsigned
128-bit values represented by i64 limbs. Input N controls iteration count;
values change on every iteration. The result is a deterministic checksum.
This is a synthetic compiler diagnostic, not a contract or an application.

Rebuild the checked-in Wasm using WABT:

```sh
wat2wasm benchmarks/paper/benchmarks/codegen/wide_compare.wat \
  -o benchmarks/paper/benchmarks/codegen/wide_compare.wasm
```

The existing paper harness accepts both catalog entries. From the repo root:

```sh
python3 benchmarks/paper/harness/run.py \
  --cases wide_compare_dev,wide_compare_paper \
  --dtvm /path/to/dtvm --wasmtime /path/to/wasmtime-45 \
  --dtvm-modes singlepass,lazy-F-ST,lazy-G-MT,multipass-G-ST \
  --warmup 2 --repeats 7 --require-wasmtime --out /tmp/wide-compare-harness
```

Dev uses 5 million iterations (checksum 2499920); paper uses 50 million (checksum 24999969).
`docs/changes/2026-11-16-wide-integer-compare/benchmark.py` provides an independent
Python oracle for both sizes and randomized paired main/candidate/WT45 samples.
No overflow imports, custom host mocks or CPU feature flags are required.
