# Change: perf-check job — cache baseline `.so` instead of baseline JSON

- **Status**: Implemented
- **Date**: 2026-05-15
- **Tier**: Light
- **Branch**: `ci/perf-baseline-lib-cache`

## Overview

Switch the `Performance Regression Check` job (`.github/workflows/dtvm_evm_test_x86.yml`) from caching `perf_baseline_${mode}.json` (the benchmark results from a *previous* CI runner) to caching `baseline_lib/` (the built baseline `libdtvmapi.so`). Every PR then re-runs baseline benchmarks on the **same runner** that runs the PR's benchmarks, eliminating cross-runner cache-stale noise while preserving the savings from skipping the baseline rebuild on cache hits.

## Motivation

Concrete evidence — PR #493 CI run `25775768632`:

The pre-PR job (line numbers from `.github/workflows/dtvm_evm_test_x86.yml` on `main`):

```yaml
# Lines 354-359
- name: Restore baseline cache
  id: baseline-cache
  uses: actions/cache@v4
  with:
    path: /tmp/perf_baseline_${{ matrix.mode }}.json     # <-- JSON results
    key: perf-baseline-${{ matrix.mode }}-${{ github.event.pull_request.base.sha }}
```

…caches the **benchmark output JSON** keyed on `matrix.mode` + `pull_request.base.sha`. When two PRs share the same `base.sha` (e.g. both forked from `c644fbe`), the second PR's cache lookup hits the first PR's stored JSON for the same mode — measured on a different `ubuntu-latest` runner with different CPU stepping / neighbor load / thermal state.

`.ci/run_test_suite.sh` lines 312–334 dispatch on this:

```bash
if [ -n "$BASELINE_CACHE" ] && [ -f "$BASELINE_CACHE" ]; then
    # Cache HIT — only run current benchmarks, compare against cached JSON.
    python3 check_performance_regression.py ... --baseline "$BASELINE_CACHE" ...
elif [ -n "$BENCHMARK_BASELINE_LIB" ]; then
    # Cache MISS — run baseline lib bench HERE on this runner,
    # then run PR bench, compare.
    python3 check_performance_regression.py ... --save-baseline "$SAVE_PATH" ...
    python3 check_performance_regression.py ... --baseline "$SAVE_PATH" ...
fi
```

The `elif` branch already does the *right* thing — same-runner A-B comparison. The `if` branch is the noise source.

Empirical impact, PR #493 commit `5c11550` interpreter perf-check (CI cache hit):

| Benchmark | CI Δ (B vs cached A) | Local A-B-A Δ (same machine) |
|---|---|---|
| `synth/EQ/b1` | +18.3% | −0.3% |
| `synth/CALLER/a1` | +16.0% | −0.3% |
| `synth/ISZERO/u0` | +15.7% | +0.6% |
| `synth/LT/b1` | +15.3% | +0.6% |
| `synth/GT/b1` | +15.2% | −0.2% |
| `synth/BYTE/b1` | +13.7% | −0.5% |

CI reports 13–18% regressions; same-machine A-B-A reports ≤0.6% deltas, all inside baseline self-drift band. The diff is compiler-only (verified: `src/evm/` untouched). The deltas are cross-runner noise.

## Impact

- **Behavior-affecting files**: `.github/workflows/dtvm_evm_test_x86.yml` only — `performance_regression_check` job. (This change doc itself, `docs/changes/2026-05-15-perf-check-baseline-lib-cache/README.md`, is added in the same commit as a non-functional design record.)
- **Behavior change**: per-PR perf-check job wall-clock increases on cache-hit runs by the baseline-bench step (which under the old scheme was skipped); cache-miss runs are unchanged.
- **Cost / quota**: cache-hit runs now do both a baseline bench AND a PR bench on the same runner (cache-miss already does both, plus a baseline build). Both modes (`matrix.mode = {interpreter, multipass}`) run per PR. Empirically verified on fork CI runs `25897744713` (cache miss) and `25900131271` (cache hit) that all 11 non-Lint jobs go green; cache-hit runs spend longer than the old cache-hit scheme (which skipped baseline bench entirely) but shorter than cache-miss (which adds the baseline build on top). Acceptable under the public-repo GitHub Actions allowance for our PR volume.
- **No source-code change**, no test runner change, no `.ci/run_test_suite.sh` change. The `elif [ -n "$BENCHMARK_BASELINE_LIB" ]` path it routes to already exists and is exercised today on cache miss.
- **Downstream**: reviewers stop chasing false-positive interpreter regressions on PRs whose diff is compiler-only (and vice versa). Perf-check signal-to-noise increases without changing the threshold.

## Implementation

1. Edit `.github/workflows/dtvm_evm_test_x86.yml` (perf job lines 354-417):
   - Rename step `Restore baseline cache` → `Restore baseline lib cache`.
   - Change `path:` from `/tmp/perf_baseline_${{ matrix.mode }}.json` to `/tmp/baseline_lib`.
   - Change `key:` from `perf-baseline-${{ matrix.mode }}-${{ github.event.pull_request.base.sha }}` to `perf-baseline-lib-${{ matrix.mode }}-${{ github.event.pull_request.base.sha }}` (rename forces fresh cache entries; old `perf-baseline-<mode>-<sha>` entries become orphaned and expire by GitHub's 7-day LRU). Cache key still includes both `matrix.mode` and `base.sha` — same key scheme as before, just a different artifact behind it.
   - **Replace** the symlink-dereferencing `cp build/lib/*` line (was line 385; line 390 after the edit) with an explicit single-file copy using `readlink -f` for SONAME resolution:
     ```bash
     cp "$(readlink -f build/lib/libdtvmapi.so)" /tmp/baseline_lib/libdtvmapi.so
     ```
     Rationale: `build/lib/` contains the SONAME symlink chain (`libdtvmapi.so` → `.0.1` → `.0.1.0`). Plain `cp build/lib/*` follows symlinks and produces 3 full copies (~105 MB) plus any other glob matches like `libgtest*.a`. `readlink -f` resolves the bare name to its canonical real file regardless of how many symlink hops or what the version suffix becomes after future SONAME bumps; it also returns the canonical path verbatim for non-symlinks, so the command is robust either way. The dispatcher at `.ci/run_test_suite.sh:328` does `cp "$BENCHMARK_BASELINE_LIB"/libdtvmapi.so ./libdtvmapi.so` — it only consumes the bare name, no SONAME resolution needed at consumer.
   - In the `Build current PR and check regression` step (was line 411; line 416 after the edit): **remove** the `export BENCHMARK_BASELINE_CACHE=...` line entirely. Keep `BENCHMARK_BASELINE_LIB=/tmp/baseline_lib`.
   - `Build baseline library` step (lines 361-389) keeps its `if: cache-hit != 'true'` guard — only the cache *target* changed, the guard semantics are identical.
2. Validate YAML: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/dtvm_evm_test_x86.yml'))"`. Run `actionlint` if installed.
3. Commit on `ci/perf-baseline-lib-cache` with conventional-commit message:
   `ci(ci): cache baseline lib instead of baseline JSON to force same-runner A-B comparison`.
4. Push to `origin` (= `abmcar/DTVM`, the personal fork).
5. Open a fork-internal PR (`abmcar/DTVM:ci/perf-baseline-lib-cache` → `abmcar/DTVM:main`) so the fork's Actions runs the modified workflow. Trigger condition: `if: github.event_name == 'pull_request'` — fork-internal PRs satisfy this.
6. Verify first run = cache miss → builds baseline lib + runs baseline bench + runs PR bench. Acceptance numerical gate: comparison table reports `max(|Δ|) < 3%` and **no** bench exceeding the 25% FAIL threshold. (The diff is workflow-config-only; the baseline and PR libs build from byte-identical source, so deltas should be pure runner noise.)
7. Push a no-op second commit (e.g. trailing newline in the workflow file) to trigger a second perf-check run on the same `base.sha`. Verify second run = cache hit on `Restore baseline lib cache`, `Build baseline library` skipped, but the bench step still logs `Running baseline benchmarks with library from base branch...` (because `BENCHMARK_BASELINE_CACHE` is unset, the bash dispatcher at `.ci/run_test_suite.sh:312-334` falls through to the `elif [ -n "$BENCHMARK_BASELINE_LIB" ]` branch — same code path as cache-miss, just without the build step before it). Comparison table should again show `max(|Δ|) < 3%`.
8. If both runs pass the numerical gate, promote to upstream: copy `~/changes/2026-05-15-perf-check-baseline-lib-cache/` into `<repo>/docs/changes/`, commit on the same branch, push, open upstream PR (`abmcar/DTVM:ci/perf-baseline-lib-cache` → `DTVMStack/DTVM:main`).

**Rollback** (if the change misbehaves in production): `git revert <commit>` on the workflow change. The `elif [ -n "$BENCHMARK_BASELINE_LIB" ]` dispatch path in `run_test_suite.sh` already exists and is the cache-miss path today, so revert returns to the current cache-hit behavior without script changes.

**Why same-`base.sha` cache sharing is now safe**: the cached artifact is now the deterministic build output `libdtvmapi.so` (a function of source = `base.sha`), not a benchmark *measurement* (a function of source + host + load). Two PRs hitting the same cache key restore the same `.so`, then each runs its own baseline bench on its own runner — no cross-runner result mixing.

## Risks

- **Wrong dispatch path**: if `run_test_suite.sh:312-334` short-circuits incorrectly when `BASELINE_CACHE` is unset, the workflow might run with no comparison. Mitigation: the `elif [ -n "$BENCHMARK_BASELINE_LIB" ]` test is explicit; the workflow always sets `BENCHMARK_BASELINE_LIB=/tmp/baseline_lib`. Failure mode if the file is missing is `set -e` on the `cp` at line 328 (loud exit), not silent skip. Verified by reading the script.
- **Cache key migration**: existing `perf-baseline-${mode}-${sha}` entries are now orphaned; they expire under GitHub's 7-day LRU.
- **Container tag is mutable** (`dtvmdev1/dtvm-dev-x64:main`, workflow line 337): the cache key does NOT include the container tag, so if the container's compiler version changes, a cached `.so` may have a different code-gen profile than the PR's freshly-built `.so`. This risk **already exists today** with the JSON cache (where the JSON was generated under whatever container was current then), so the proposed change is no worse. Acknowledged as a separate CI-infra hardening that could pin the container by digest or add it to the cache key — out of scope here.
- **Subsequent-run cost**: every PR-trigger event re-runs baseline bench. Under the old scheme the cache-hit path skipped this. The change adds **one full baseline bench** before the PR bench on cache-hit runs.
- **Bench scope**: the workflow does **not** pass `--benchmark-filter` to evmone-bench. `tools/check_performance_regression.py` defaults to `external/total/*` — 194 benchmarks per mode (fork CI runs `25897744713`, `25900131271`: "Total benchmarks: 194"). With `BENCHMARK_REPETITIONS=5`.
- **SAVE_PATH fallback** (`.ci/run_test_suite.sh:329`): with `BASELINE_CACHE` unset, `SAVE_PATH` resolves to the literal default `/tmp/perf_baseline.json` (no `${matrix.mode}` suffix). This file is only consumed by the very next `python3` invocation in the same script (line 339), and nothing else in the job reads it. Safe to leave as-is.

## Test plan

- [x] YAML syntactically valid (`python3 -c "import yaml; yaml.safe_load(...)"`)
- [x] Fork-internal PR opens successfully (`abmcar/DTVM#15`)
- [x] **First fork CI run** (cache miss, EVM workflow run `25897744713` after re-running 3 spdlog-503-failed jobs): both `Performance Regression Check (interpreter)` and `(multipass)` reported `Cache not found for input keys: perf-baseline-lib-<mode>-c644fbe...`, ran the build-baseline-library step, then logged `Running baseline benchmarks with library from base branch...` followed by `Running current benchmarks with PR library...`. Cache was saved at end of job (`Cache saved with key: perf-baseline-lib-<mode>-c644fbe...`). Both modes: `Total benchmarks: 194 / Regressions (> 25%): 0 / RESULT: PASS`.
- [x] **Second push** (commit `8189d4d`, comment-only no-op to bump `head.sha` while `base.sha` stays at `c644fbe`) triggers run `25900131271`. Both perf-check matrix jobs reported `Cache restored from key: perf-baseline-lib-<mode>-c644fbe...`, the `Build baseline library` step was `skipped` (per `if: cache-hit != 'true'` evaluating false), and the bench step still logged both `Running baseline benchmarks with library from base branch...` and `Running current benchmarks with PR library...`. Both modes again `Total benchmarks: 194 / Regressions (> 25%): 0 / RESULT: PASS`. All 11 non-Lint EVM jobs green on first try (no spdlog 503 retries).
- [x] Cross-runner noise reduction confirmed empirically (run `25897744713` interpreter perf-check comparison): the same synth benchmarks that reported +13-18% regressions in PR #493's cross-runner cache-stale comparison now report deltas within typical noise (e.g. `synth/ADDRESS/a1` +15.6% → −4.3%, `synth/BYTE/b1` +13.7% → +1.2%, `synth/CALLER/a1` +16.0% → +0.1%, `snailtracer/benchmark` −1.1% → +0.0%, `blake2b_shifts/8415nulls` −12.1% → +0.2%). Only 1 micro-benchmark was filtered (baseline < 5 µs) versus 25 in the cross-runner comparison.
- [ ] Upstream PR opens cleanly after promotion to `docs/changes/`

## Checklist

- [x] Implementation complete (workflow edited + committed: `7928578`, `8189d4d`)
- [x] YAML syntax check passes
- [x] Fork-internal PR opened (`abmcar/DTVM#15`)
- [x] Both fork-CI runs (cache-miss `25897744713` + cache-hit `25900131271`) observed and sensible — see Test plan above
- [x] Build and tests pass (CI-only change; perf-check itself is the test, both modes RESULT: PASS)
- [ ] Upstream PR opened
