# Contract benchmark host and smoke runner

- **Status**: Implemented (smoke scope)
- **Date**: 2026-11-10
- **Tier**: Full

## Overview

Add a native host and runner to execute the same rebuilt contract Wasm under
DTVM interpreter, singlepass, eager/lazy multipass and Wasmtime 45. The host
implements deterministic calldata, termination, Ethereum Keccak and 256-bit
big-endian modular arithmetic. It deliberately does not implement stateful
blockchain semantics or assert equivalence to the archived testbed.

## Implementation and validation

- Rebuilt the three archived WAT cases and added a separate C-to-Wasm
  consistent eight-level Merkle proof with a corrupted-input negative case.
- Added cross-engine runners, host arithmetic/Keccak/calldata/bounds fixtures,
  an independent Python reference and explicit result/trace comparison.
- Release DTVM built at 790351b; final smoke validation passed 65 engine/case
  checks using Wasmtime 45 C API, WABT 1.0.36 and Clang 16.0.6.
- The WAT and adjacent Merkle Solidity source differ: the WAT's root builder
  handles left/right positions while the source's root builder does not. The
  former returns true for its fixture, the latter false in the independent
  model. The WAT, which uses eight levels, also differs from the archived hex;
  the paper call note's ten levels cannot be applied blindly.
- Ran 21-process screens and independent 31-process confirmations before and
  after runner review, comparing DTVM singlepass, eager and lazy multipass to
  Wasmtime 45 with the shared native host. See `evidence/` for raw data and the
  harness README for medians and measurement boundaries.

## Scope and remaining work

See `benchmarks/paper/harness/contracts/README.md` for commands, dependencies,
input/output hashes, observed semantics and exclusions. This is a standalone
smoke harness and preliminary process-level screen. The general build and full
repository test suite were not run, and no original-testbed equivalence claim
is made. Future
benchmarking needs an explicit repeat/state-reset design, compilation versus
execution boundaries, host cost accounting, independent process samples and
broader contract cases. Lazy mode relies on the current DTVM internal runtime
configuration/opaque handle implementation; no stable public API was changed.
