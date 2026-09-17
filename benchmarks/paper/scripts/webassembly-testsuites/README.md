# webassembly-testsuites Runner (snapshot)

A snapshot of the test-runner framework from `webassembly-testsuites`, used to reproduce the runner commands for the polybenchc / wapm suites.

## Files

- `runtest_webassembly.py` — main test entry
- `configuration/` — iwasm / wasmtime / wasmer / dtvm runtime configs

## Usage

Must run inside a complete `webassembly-testsuites` directory layout (`case/benchmark/...` paths). This repo's benchmark binaries live under `benchmarks/`; symlink them in or clone the full testsuite and replace the corresponding directory.

```bash
# at the webassembly-testsuites root
./runtest_webassembly.py -r iwasm -s polybenchc
./runtest_webassembly.py -r wasmtime -s polybenchc
./runtest_webassembly.py -r dtvm -s polybenchc
./runtest_webassembly.py -r "wasmer run" -s polybenchc
```

## Source

Mirrored from the webassembly-testsuites repository.
