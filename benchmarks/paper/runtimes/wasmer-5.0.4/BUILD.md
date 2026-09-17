# Wasmer 5.0.4 (WAPM paper TTFI)

## Source patch

Instrumented tree (default): `/path/to/wasmer-5.0.4`

- `lib/wasix/src/ttfi_report.rs` — `Readfile time`, `compile time`, `Total compilation time`, `Module execution`, `Execution N`
- `lib/wasix/src/runtime/mod.rs` — compile timer around `Module::new`
- `lib/cli/src/commands/run/mod.rs` — readfile timer
- `lib/wasix/src/state/builder.rs` — instantiate + guest execution timers

Run flags (paper): `wasmer run --<engine> --cache-dir=/dev/null <case>.wasm …`

## Build

```bash
./runtimes/wasmer-5.0.4/build.sh
```

- Always builds **cranelift** + **singlepass**.
- **llvm** only if LLVM 18 is available (`llvm-config-18` or `LLVM_SYS_180_PREFIX`).

## Compare

```bash
./scripts/run_wasmer_ttfi_compare.sh 3   # cranelift (default)
./scripts/run_wasmer_ttfi_compare.sh 3 '' singlepass
```

Metric aligned with paper `avg_compile_time.py`: **`Total compilation time`** (microseconds in parentheses).
