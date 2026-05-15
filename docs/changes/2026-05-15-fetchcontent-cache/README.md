# Change: actions/cache for FetchContent on DTVM CI

- **Status**: Proposed
- **Date**: 2026-05-15
- **Tier**: Light
- **Branch**: ci/fetchcontent-cache (continues commit `96707a2`)

## Overview

Add `actions/cache@v4` step to the two DTVM CMake-building CI workflows
(EVM + WASM) to cache the populated FetchContent sources across runs.
First run pays full download; every subsequent run with unchanged
`third_party/AddDeps.cmake` hits the cache and skips downloads
entirely. This completes the work begun in commit `96707a2` (boost URL
swap + CMakeLists env hook).

## Motivation

Each DTVM CI run currently downloads 8 FetchContent deps from scratch
(`spdlog`, `asmjit` (WASM only), `CLI11`, `intx`, `boost`, `rapidjson`,
+ conditional `googletest`/`yaml-cpp`). Any single 504 kills the
pipeline (e.g., PR #499 run `25897803413` died on rapidjson).

`actions/cache@v4` is the canonical 2025 pattern for FetchContent
caching (verified against `vowpal_wabbit` and `colmap` workflows —
both cache around `FetchContent` paths keyed on dep manifest hashes).

The earlier image-bake approach was investigated but Docker is
unavailable in the implementation environment for verification.
`actions/cache` does not require Docker and is verifiable directly via
PR CI runs.

## Impact

### Affected modules

- `.github/workflows/dtvm_evm_test_x86.yml` — add cache step + env to
  ~10 container-image build jobs
- `.github/workflows/dtvm_wasm_test_x86.yml` — same for ~4 container
  jobs
- `docs/changes/2026-05-15-fetchcontent-cache/README.md` — this doc;
  drop image-bake content from prior iteration

### Affected contracts

None. CI infrastructure only.

### Compatibility

Fully backwards-compatible. Cache miss falls through to current
behavior (live FetchContent download). No workflow logic changes
beyond the new cache step and job-level env.

## Implementation

### 1. Cache step per workflow

**Coverage** (14 distinct jobs total):
- **EVM (10 jobs)**: 8 `bash .ci/run_test_suite.sh` callers + 2 matrix
  instances of `performance_regression_check` (which runs both a base
  build via direct cmake AND a PR-HEAD build via `run_test_suite.sh`).
- **WASM (4 jobs)**: 3 `bash .ci/run_test_suite.sh` callers +
  `build_test_evmabi_mock_cli_on_x86` (uses inline `cmake -S . -B build`
  directly, not via `run_test_suite.sh`).

All 14 need the cache step. The inline-cmake job in WASM and the
direct-cmake baseline build in `performance_regression_check` also
inherit `FETCHCONTENT_BASE_DIR` from the env block — no special
handling required.

Add to each container job, between `actions/checkout` and the
build/test step:

```yaml
- name: Cache FetchContent deps
  uses: actions/cache@v4
  with:
    path: /github/home/.fetchcontent
    key: ${{ runner.os }}-fc-${{ github.workflow }}-v1-${{ hashFiles('third_party/AddDeps.cmake') }}
```

**Key composition rationale:**
- `runner.os` — standard practice (Ubuntu vs other).
- `github.workflow` — **necessary**: EVM workflow runs with
  `SINGLEPASS_JIT=OFF` (no asmjit), WASM workflow includes
  `SINGLEPASS_JIT=ON` (needs asmjit). Sharing one key causes a
  partial-hit churn: EVM saves 7 deps → WASM restores 7, populates 1,
  but `actions/cache@v4` skips same-key save (logs a warning, does
  not fail the job) → WASM re-downloads asmjit every run.
  Workflow-prefixed key avoids this.
- `v1` namespace — **manual escape hatch**. Bump to `v2` when
  `dtvmdev1/dtvm-dev-x64:main` is rebuilt with materially different
  CMake/compiler/Ninja/tar/zstd versions. The `:main` tag is mutable
  and our key does not auto-invalidate on image bumps.
- `hashFiles('third_party/AddDeps.cmake')` — auto-invalidates on any
  dep change (URL/hash/tag/new dep).
- **No `restore-keys`**. Partial cache hits across different dep
  versions can yield silently-stale source (FetchContent stamps say
  "populated", URL_HASH may not match the cached tarball if user
  changed URL but kept hash). Cold start is the lesser evil.

### 2. Job env

Add to each container job's `env:` block (where the build runs):

```yaml
env:
  FETCHCONTENT_BASE_DIR: /github/home/.fetchcontent
```

The CMakeLists env-hook from commit `96707a2` (lines 8-18; executable
`if/set/endif` block at lines 11-18) picks up the env var when no `-D`
is passed on the cmake command line. No changes needed to
`.ci/run_test_suite.sh`.

### 3. Drop image-bake content from this change doc

Previous iteration's `docs/changes/.../README.md` had a "Deferred"
section describing the image-bake design. Replace with this file
focused on actions/cache.

## Validation

### Local

- `tools/format.sh check` — pass.
- YAML lint via `python -c "import yaml; yaml.safe_load(open('.github/workflows/dtvm_evm_test_x86.yml'))"` — pass.
- Diff inspection: each modified job has cache step + env block.

### CI (post-push)

The cache behavior is GH-runner-side; can only be observed in a real
CI run.

## Acceptance Criteria

1. **AC-A: PR CI first run is cache-miss.** Workflow log shows
   "Cache not found for input keys: ..." followed at end-of-job by
   "Cache saved with key: ...".
2. **AC-B: PR CI re-run is cache-hit.** Re-running the same workflow
   (no commit change) shows "Cache restored from key: ..." in cache
   step output. Build log shows zero `^-- Downloading` lines from
   FetchContent. (Note: explicit "restored from key" line is the
   primary AC; absence of `-- Downloading` is corroborating.)
3. **AC-C: No regression.** All jobs that pass on `main` today pass
   with cache step active.
4. **AC-D: Cache key invalidates on AddDeps change.** A no-op edit to
   `third_party/AddDeps.cmake` (trailing newline) in a follow-up
   commit produces a new key (visible in workflow log as different
   key hash).
5. **AC-E: EVM and WASM caches don't interfere.** EVM cache key
   contains `DTVM-EVM` (workflow `name:` field value, with hyphen),
   WASM contains `DTVM-WASM`. Verify via workflow log key string.

## Risks

- **R1: actions/cache@v4 itself unavailable / quota exhausted.**
  Mitigation: cache miss is non-fatal; CI falls back to live
  FetchContent download (current behavior). No regression.

- **R2: 10GB repo cache cap proximity.**
  Per-key size ~820MB. With 10 active feature branches × 2 workflows
  = ~16GB of potential cache load — over the cap. GitHub LRU-evicts
  caches not accessed in 7 days, so steady-state should hover around
  3-5 active keys (~3-4GB). Not "well under" the cap; close but
  acceptable. Monitor via `gh cache list` if eviction thrashing
  becomes visible.

- **R3: Image churn invalidation.**
  `dtvmdev1/dtvm-dev-x64:main` is a mutable tag. If the image is
  rebuilt with a materially different CMake / compiler / Ninja
  version, the cached `<name>-build/` artifacts could mismatch.
  Mitigation: manually bump the `v1` namespace in the cache key
  (becomes `v2`, etc.) when the image is rebuilt with material
  changes. Documented in this section.

- **R4: Cache-key hash misses other dep-affecting files.**
  Today only `third_party/AddDeps.cmake` controls FetchContent
  declarations. If a future PR moves declares elsewhere or adds new
  conditional logic in `CMakeLists.txt` flags, update the cache key.

- **R5: Boost URL transition single-point-of-failure.**
  (Carried from commit `96707a2`.) First CI run hits new boost URL
  live; if 504, re-run. Cache then captures it for subsequent runs.

## Out of scope

- Image-baking deps into `dtvmdev1/dtvm-dev-x64:main` — deferred
  (Docker unavailable for verification in current environment).
- Pinning `:main` image by digest in cache key — would tighten R3
  but adds maintenance cost; bump-`v1`-on-image-rebuild is simpler.
- Migration to Hunter / submodules / CPM.
- Pinning `GIT_TAG` to commit SHAs.

## Provenance

- Commit `96707a2` ("build(deps): swap boost mirror + honor
  FETCHCONTENT_BASE_DIR env") already adds the env-hook + boost URL
  prerequisites this change builds on.
- Prior Phase 0.5 v2 round 1 reviews:
  - `reviews/motivation-v2-1-opus.md` (cite: cache-key churn,
    AC-B log line check)
  - `reviews/motivation-v2-1-codex.md` (cite: image churn, 10GB cap
    wording, canonical pattern confirmation)
- All cited refinements absorbed into this spec; iter=2 skipped
  because the refinements are spec-level fixes, not direction changes.
