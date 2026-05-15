# Change: Local FetchContent cache convention + boost mirror swap

- **Status**: Proposed
- **Date**: 2026-05-15
- **Tier**: Light
- **Branch**: ci/fetchcontent-cache

## Overview

Two narrow, locally-verifiable changes:

1. Top-level `CMakeLists.txt` honors `FETCHCONTENT_BASE_DIR` from the
   environment so developers can share a single populated cache
   (`~/.cache/cmake-fetchcontent`) across worktrees and clean builds.
2. Swap boost's sourceforge URL for the official `archives.boost.io`
   mirror. URL_HASH unchanged.

A complementary follow-up to pre-bake the deps into
`dtvmdev1/dtvm-dev-x64:main` (image-side cache for CI) was scoped out of
this PR because Docker is not available in the implementation
environment for end-to-end verification. The image-bake design is
preserved as a follow-up note (see "Deferred").

## Motivation

`third_party/AddDeps.cmake` declares 8 FetchContent entries
(spdlog/asmjit/CLI11/intx/boost/rapidjson + conditional googletest/yaml-cpp).
Clean builds and CI jobs re-download all of them every time.

- CI flakiness example: PR #499 run `25897803413` died on a rapidjson
  download.
- boost is hosted on SourceForge — historically the most flaky of the
  8 hosts.
- Local clean builds (new worktrees, new contributors, fresh container
  starts) pay the full download cost on every reset.

Boost URL swap fixes the single biggest cold-start failure mode in CI
even without an image-side cache. The env-hook lets local developers
opt into a shared cache trivially (one-line export in shell rc).

## Impact

### Affected modules

- `CMakeLists.txt` — env-var hook (between line 6 and line 8)
- `third_party/AddDeps.cmake` — boost URL swap; drop `DOWNLOAD_NAME`;
  light reference comment to `docs/start.md`
- `docs/start.md` — "Build dependency cache" section

### Affected contracts

None. Build-system download semantics only.

### Compatibility

Fully backwards-compatible:
- No env var set → identical to today.
- New boost URL has same `URL_HASH`, so byte-identical content.
- CI workflows unchanged.

## Implementation

### 1. CMakeLists.txt env hook

Insert between line 6 (`project(...)`) and line 8
(`set(CMAKE_CXX_STANDARD 17)`):

```cmake
# Honor FETCHCONTENT_BASE_DIR from environment when not set on cmd line.
if(DEFINED ENV{FETCHCONTENT_BASE_DIR} AND NOT DEFINED CACHE{FETCHCONTENT_BASE_DIR})
  set(FETCHCONTENT_BASE_DIR "$ENV{FETCHCONTENT_BASE_DIR}" CACHE PATH
      "Shared FetchContent cache (from env)")
endif()
```

Mirrors the pattern already present at
`.worktrees/feat-gas-check-placement/CMakeLists.txt:8-15`. Active only
when env is set AND `-D` not passed; otherwise no-op.

### 2. Boost URL swap

In `third_party/AddDeps.cmake`, replace:
```cmake
URL https://sourceforge.net/projects/boost/files/boost/1.67.0/boost_1_67_0.tar.bz2/download
DOWNLOAD_NAME boost_1_67_0.tar.bz2
```
with:
```cmake
URL https://archives.boost.io/release/1.67.0/source/boost_1_67_0.tar.bz2
```

- `URL_HASH SHA256=2684c97...adba` unchanged.
- `DOWNLOAD_NAME` dropped because the new URL ends in the canonical
  filename (per `cmake --help-module ExternalProject` `DOWNLOAD_NAME`
  default).
- `archives.boost.io` is the official Boost archive (cross-referenced
  on `boost.org/users/history/version_1_67_0.html`).

### 3. Documentation

`docs/start.md` adds a "Build dependency cache" section explaining the
env-var convention and the SGX local-cache caveat (asmjit gets patched
under SGX; mixing patched/unpatched in one cache breaks).

## Validation (local)

Verified in implementation worktree:

- **boost URL reachable + correct bytes:**
  `curl -sIL https://archives.boost.io/release/1.67.0/source/boost_1_67_0.tar.bz2`
  → HTTP 200, content-length 87336566 (matches canonical 1.67.0 tarball),
  last-modified 2018-04-11.
- **env-hook fires when expected:** With `FETCHCONTENT_BASE_DIR=/tmp/fc`
  exported and `command cmake -S . -B build-test`, FetchContent
  populates at `/tmp/fc/<name>-src/` (note: directly under BASE_DIR,
  not under `_deps/` — that's only the default segment).
- **Boost content after URL swap:** populated `boost-src/boost/version.hpp`
  contains `#define BOOST_VERSION 106700` (== 1.67.0). URL_HASH
  validates so byte-identity is enforced.
- **Format check pass.**

## Deferred (image-side cache; future PR)

The original design also included a `docker/bake/CMakeLists.txt` driver
plus a Dockerfile bake stage that would pre-populate
`/opt/cmake-fetchcontent` inside `dtvmdev1/dtvm-dev-x64:main`. This
would eliminate per-CI-run downloads entirely for the EVM and WASM
container jobs.

Reason for deferral: Docker is not available in this implementation
environment, so the bake stage cannot be verified end-to-end (image
build, COPY semantics, layer cache behavior). Shipping unverified
Docker code carries an asymmetric cost — a broken image republish would
affect every CI run.

The design is preserved for a follow-up PR:
- Standalone `docker/bake/CMakeLists.txt` driver with `LANGUAGES NONE`
  and inlined `FetchContent_Declare` blocks (NO `include(AddDeps.cmake)`
  to avoid re-loading FetchContent which would clobber the override).
- Dockerfile bake stage placed after `foundryup` (line 47), sets
  `ENV FETCHCONTENT_BASE_DIR=/opt/cmake-fetchcontent`.
- Sync burden: bake CMakeLists must be updated when `AddDeps.cmake`
  changes.

## Risks

- **Boost URL transition single-point-of-failure.** The PR's first CI
  run is the first hit on `archives.boost.io` from DTVM CI. If 504,
  PR fails. Mitigation: manually re-run; if persistent, revert URL
  swap in a single-line hotfix.
- **`archives.boost.io` outage.** Mitigation: official Boost archive
  (verified). If down long-term, switch to a self-hosted GH release.

## Acceptance Criteria

1. PR CI passes every job that passes on `main` today.
2. PR CI's first hit on `archives.boost.io` succeeds (no 504); boost
   downloads correctly with unchanged `URL_HASH`.
3. Local: `FETCHCONTENT_BASE_DIR=/tmp/fc cmake -S . -B build` produces
   `/tmp/fc/<name>-src/` (env hook honored).
4. `docs/start.md` has the cache section.

## Out of scope

- Pre-bake into dev image (deferred — needs Docker verification).
- `actions/cache` for CI (not needed without image-bake).
- GIT_TAG → commit SHA pinning (separable).
- Hunter / submodules / CPM migration (heavyweight).
- CMake version bump (separable).
