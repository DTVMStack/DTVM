# DTVM (`dtvm`) — main HEAD

The mainline version for PolyBench TTFI / WAPM TTFI (with `Total compilation time` instrumentation).

## Commit

See [`version.txt`](version.txt) (example `c3c3fd856`, 2026-05-29). The paper baseline `882c83155` is under [`../dtvm/`](../dtvm/).

## Build

```bash
cd /path/to/DTVM
cmake -B build_main -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON
cmake --build build_main -j"$(nproc)"

cp build_main/dtvm <repo>/benchmarks/paper/runtimes/dtvm_main/dtvm
chmod +x <repo>/benchmarks/paper/runtimes/dtvm_main/dtvm
git log -1 --format='%H %ci %s' \
  > <repo>/benchmarks/paper/runtimes/dtvm_main/version.txt
```

## Confirm TTFI Is Compiled In

```bash
strings ./dtvm | grep -F 'Total compilation time'
```

## Usage

```bash
./dtvm case.wasm -m multipass \
  --enable-multipass-lazy \
  --disable-multipass-greedyra \
  --disable-multipass-multithread \
  --enable-statistics
```

See [`../../docs/POLYBENCH_TTFI_REPRODUCE.md`](../../docs/POLYBENCH_TTFI_REPRODUCE.md) §3.1 and [`../../docs/WAPM_TTFI_REPRODUCTION.md`](../../docs/WAPM_TTFI_REPRODUCTION.md) §3.1.
