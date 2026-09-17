# DTVM (paper-version `dtvm`)

The paper's `dtvm` CLI (multipass JIT, `--enable-multipass-lazy`, etc.).

## Experiment Commits

| Purpose | Commit | Notes |
|---------|--------|-------|
| **Paper PolyBench / WAPM wall-clock** | **`882c83155`** | see [`BUILD.md`](BUILD.md) |
| **PolyBench / WAPM TTFI mainline** | main HEAD (with `Total compilation time` instrumentation) | see `../dtvm_main/version.txt`; build steps in [`../../docs/POLYBENCH_TTFI_REPRODUCE.md`](../../docs/POLYBENCH_TTFI_REPRODUCE.md) §3.1 |
| **overflow / fib(30)** | latest fast commit (example `e532db3e2`) | see [`../../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md`](../../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md) |

## Artifacts in This Directory

Binaries are not committed; copy them manually per `BUILD.md`:

- `dtvm` — Release build @ the paper commit (`.gitignore`)
- `CMakeCache.txt` — snapshot of the paper build configuration (`.gitignore`)
- `version.txt` — `./dtvm --help` excerpt + `commit=…` + `build_dir=…`

## PolyBench Multipass CLI (paper)

```bash
# main (multipass)
dtvm -m multipass --disable-multipass-greedyra --disable-multipass-multithread case.wasm
# lazy
dtvm -m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread case.wasm
```

## Open Items

- Which CLI / build flags correspond to the xlsx column `dtvm multipass + exit optimization`
- Original benchmark logs and timing script (`Average time` style)
