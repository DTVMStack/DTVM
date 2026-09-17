# Wasmtime 31.0.0 Build Notes

The paper's Wasmtime baseline (Cranelift backend).

- Version: **31.0.0**
- Upstream: https://github.com/bytecodealliance/wasmtime
- Target tag: **release-31.0.0**
- Source-build script: [`build.sh`](build.sh)

This repository does **not** commit prebuilt binaries; use the official release package or a local `cargo build`.

---

## 1. Prebuilt Package (recommended)

### Download

| Item | Value |
|------|-------|
| File | `wasmtime-v31.0.0-x86_64-linux.tar.xz` |
| URL | https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz |
| Release | https://github.com/bytecodealliance/wasmtime/releases/tag/v31.0.0 |

```bash
curl -LO https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz
tar xf wasmtime-v31.0.0-x86_64-linux.tar.xz
```

Example extracted location:

```bash
/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime
```

### Verify

```bash
/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime --version

/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime run \
  --invoke add /path/to/add.wasm 1 3
```

`add.wasm` was a smoke-test path on the experiment machine and is **not** included in this repository.

---

## 2. Source Build (optional)

### Get the Source

```bash
git clone https://github.com/bytecodealliance/wasmtime.git
cd wasmtime
git checkout release-31.0.0
git submodule update --init
```

Or use the script in this directory:

```bash
cd runtimes/wasmtime-31.0.0
chmod +x build.sh
./build.sh clone
```

### Requirements

| Item | Requirement |
|------|-------------|
| **Rust** | `rustc` **1.85.0** or later |
| System | `cargo`, `rustup` |

```bash
rustc --version
rustup update stable
```

### Build

```bash
cd wasmtime
cargo build --release
# artifact: target/release/wasmtime
```

One shot:

```bash
./build.sh all
./build.sh version
```

### WAPM Paper Timing Instrumentation (`ttfi-report`)

`./build.sh clone` automatically applies `git apply patches/ttfi-report.patch` (based on **release-31.0.0**).
The build artifact is installed to `out/wasmtime`; instrumented stdout looks like:

```text
Creating mmap for file took: …µs
mmap success:
Total compilation time: … ms (… µs)
…
Execution 1: ….… ms
```

When reproducing, use `export WASMTIME_CACHE=0` and pass case arguments the same way as the paper (e.g. `echo.wasm 1234567890`).

---

## 3. `wasmtime` Paths Used by This Repo

| Scenario | `wasmtime` path |
|----------|-----------------|
| WAPM paper instrumented build | `runtimes/wasmtime-31.0.0/out/wasmtime` |
| `benchmarks/overflow/build.sh` | `/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime` |
| Experiment-machine example | `/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime` |

Paths vary by deployment; extract the official package to `/opt/...` or `$HOME/workspace/...` and adjust script paths accordingly.

---

## 4. PolyBench / webassembly-testsuites

Configuration lives in `scripts/webassembly-testsuites/configuration/`; run with:

```bash
./runtest_webassembly.py -r wasmtime -s polybenchc
```

`wasmtime` must be on `PATH`, or the configuration should point at the install path above.
