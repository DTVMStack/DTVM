# Wasmtime 31.0.0

The paper's Wasmtime baseline (Cranelift backend).

## Quick Install (official prebuilt package)

```bash
curl -LO https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz
tar xf wasmtime-v31.0.0-x86_64-linux.tar.xz
/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime --version
```

## Verification Example

```bash
/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime run \
  --invoke add /path/to/add.wasm 1 3
```

## Docs

- [`BUILD.md`](BUILD.md) — prebuilt package, source build, path notes
- [`build.sh`](build.sh) — source clone / automatic `git apply patches/ttfi-report.patch` / `cargo build --release` / install to `out/`
- [`patches/ttfi-report.patch`](patches/) — the paper's `Total compilation time` instrumentation (based on `release-31.0.0`)

> The current TTFI / overflow / fib mainline has moved to Wasmtime **45.0.0**; see [`../wasmtime-45.0.0/`](../wasmtime-45.0.0/).

## Version Pin

| Item | Value |
|------|-------|
| Version | **31.0.0** |
| Git tag | `release-31.0.0` |
| Prebuilt package | [v31.0.0 x86_64-linux](https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz) |
| Rust (source build) | >= 1.85.0 |

## Notes

The `wasmtime` binary is not committed to this repository. `benchmarks/overflow/build.sh` defaults to `/opt/wasmtime-v31.0.0-x86_64-linux/wasmtime`.
