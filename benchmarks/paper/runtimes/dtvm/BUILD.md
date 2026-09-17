# DTVM (dtvm) — Paper Reproduction Build

Paper experiments use commit **`882c83155`** (DTVM source fork).

## Prerequisites

- Linux x86_64
- `cmake`, `ninja`, GCC C++17
- LLVM **15** for multipass JIT, e.g. `/opt/llvm15/lib/cmake/llvm`
- Network or pre-populated `build_paper/_deps` (asmjit, CLI11, spdlog)

## Recommended: git worktree (keeps main checkout untouched)

```bash
cd /path/to/DTVM
git worktree add ../DTVM_paper_882c83155 882c83155
cd ../DTVM_paper_882c83155
```

## Configure & build

```bash
cmake -S . -B build_paper -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_CHECKED_ARITHMETIC=ON

cmake --build build_paper -j"$(nproc)"
cp build_paper/dtvm build_paper/dtvm
```

If `FetchContent` cannot reach GitHub, download asmjit zip and point CMake:

```bash
curl -fsSL -o /tmp/asmjit.zip \
  https://codeload.github.com/asmjit/asmjit/zip/3577608cab0bc509f856ebf6e41b2f9d9f71acc4
unzip -q /tmp/asmjit.zip -d build_paper/_deps
mv build_paper/_deps/asmjit-3577608cab0bc509f856ebf6e41b2f9d9f71acc4 build_paper/_deps/asmjit-src

cmake ... \
  -DFETCHCONTENT_SOURCE_DIR_ASMJIT="$PWD/build_paper/_deps/asmjit-src" \
  -DFETCHCONTENT_SOURCE_DIR_CLI11="$PWD/build_paper/_deps/cli11-src" \
  -DFETCHCONTENT_SOURCE_DIR_SPDLOG="$PWD/build_paper/_deps/spdlog-src"
```

(Extract `build_deps.tar.gz` from a sibling DTVM tree for CLI11/spdlog if needed.)

## Install proof artifacts into this repo

```bash
DATA=<repo>/benchmarks/paper/runtimes/dtvm
cp build_paper/dtvm "$DATA/dtvm"
cp build_paper/CMakeCache.txt "$DATA/CMakeCache.txt"
./build_paper/dtvm --help > "$DATA/version.txt" 2>&1 || true
echo "commit=882c83155" >> "$DATA/version.txt"
```

## PolyBench multipass CLI (inferred from xlsx + ACI)

```bash
dtvm -m multipass --disable-multipass-greedyra --disable-multipass-multithread case.wasm
dtvm -m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread case.wasm
```

**Not available at 882c83155:** public CLI for xlsx column `dtvm multipass + exit optimization` — ask the original experimenters.

## Verify

```bash
./build_paper/dtvm -m multipass --disable-multipass-greedyra --disable-multipass-multithread \
  <repo>/benchmarks/paper/benchmarks/polybenchc/atax.wasm
```

Should exit 0 and print `==BEGIN DUMP_ARRAYS==` output.
