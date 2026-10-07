# DTVM (historical `dtvm`)

Historical `dtvm` CLI pin for earlier PolyBench / WAPM wall-clock captures (multipass JIT, `--enable-multipass-lazy`, etc.). Current paper experiments use **`c3c3fd856`** under [`../dtvm_main/`](../dtvm_main/).

## Experiment Commits

| Purpose | Commit | Notes |
|---------|--------|-------|
| **Current paper PolyBench / TTFI** | **`c3c3fd856`** | see [`../dtvm_main/`](../dtvm_main/); build steps in [`../../docs/POLYBENCH_TTFI_REPRODUCE.md`](../../docs/POLYBENCH_TTFI_REPRODUCE.md) §3.1 |
| **overflow / fib(30)** | latest fast commit (example `e532db3e2`) | see [`../../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md`](../../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md) |
| **Historical PolyBench / WAPM wall-clock** | **`882c83155`** | this directory; see [`BUILD.md`](BUILD.md) |

## Artifacts in This Directory

Binaries are not committed; copy them manually per `BUILD.md`:

- `dtvm` — Release build @ the historical commit (`.gitignore`)
- `CMakeCache.txt` — snapshot of the historical build configuration (`.gitignore`)
- `version.txt` — `./dtvm --help` excerpt + `commit=…` + `build_dir=…`

## PolyBench Multipass CLI

```bash
# main (multipass)
dtvm -m multipass --disable-multipass-greedyra --disable-multipass-multithread case.wasm
# lazy
dtvm -m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread case.wasm
```

## Open Items

- Which CLI / build flags correspond to the xlsx column `dtvm multipass + exit optimization`
- Original benchmark logs and timing script (`Average time` style)
