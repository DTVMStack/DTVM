# Change: Establish Frontier-Osaka EVM conformance

- **Status**: Accepted
- **Date**: 2026-08-22
- **Tier**: Full
- **Tracking PR**: [#600](https://github.com/DTVMStack/DTVM/pull/600)

## Overview

Extend DTVM's revision-aware EVM execution and conformance evidence from
Frontier-Cancun through Prague and Osaka. The result must support every
mainnet EVM revision exposed by EVMC from `EVMC_FRONTIER` through
`EVMC_OSAKA`, run the same explicit revision in interpreter and multipass
modes, and validate the result against a pinned official fixture release.

This change is complete only when the evidence supports the following scoped
claim:

> DTVM supports the EVM execution semantics of every Ethereum mainnet revision
> from Frontier through Osaka under the EVMC execution boundary, validated in
> interpreter and multipass modes against the applicable EEST v5.4.0 develop
> state-test cases.

The claim covers VM execution, revision-gated opcodes, precompile calls handled
by the test execution environment, transaction admission rules represented by
state fixtures, and gas accounting observable at the EVMC boundary. It does
not claim that DTVM is a full Ethereum consensus or networking client.

## Motivation

The previous continuous-integration state-test job passed `fork_Cancun` to
evmone's `-k` option. That option filters top-level test names rather than
protocol revisions, so it did not establish Cancun-only or complete fork
coverage. DTVM also had partial Prague and Osaka code and imported tests, but
partial code presence is not evidence of conformance. Unknown state-test fork
labels could fall back to the Cancun default, which could produce false-green
results. For a contemporary systems evaluation, DTVM needs reproducible
evidence for all mainnet EVM revisions through the current Osaka revision.

The frozen external oracle is:

- Repository: `ethereum/execution-spec-tests`
- Release: `v5.4.0` (final Osaka release)
- Asset: `fixtures_develop.tar.gz`
- URL: `https://github.com/ethereum/execution-spec-tests/releases/download/v5.4.0/fixtures_develop.tar.gz`
- SHA-256: `3e2b02d49fe903eda4fd8caca5cbf0d139c470e97e1de9a85299b1b034f97099`
- State-test driver: `DTVMStack/evmone@a4a0e47aff903a47a6be133c67ad106c706fe566`

The release's `fixtures_stable.tar.gz` asset is not sufficient for this
change: inspection of its state-test `post` keys found Prague but no Osaka
cases. The pinned `fixtures_develop.tar.gz` asset from the same immutable final
Osaka release contains both Prague and Osaka cases. "Develop" is the upstream
asset name, not a mutable branch or URL in this design.

Mutable `latest` or branch-qualified fixture URLs are not valid evidence for
the final PR or paper artifact.

## Goals

1. Recognize and propagate every mainnet EVMC revision from Frontier through
   Osaka without silently substituting Cancun.
2. Complete Prague and Osaka VM-visible opcode, gas, transaction, and
   precompile-boundary behavior required by applicable EEST v5.4.0 fixtures.
3. Produce separate interpreter and multipass conformance results from the
   same pinned fixture archive.
4. Report exact loaded, applicable, executed, passed, failed, errored, and
   excluded case counts per revision and mode.
5. Keep every exclusion outside the DTVM EVMC boundary explicit and auditable;
   no DTVM-caused failure may be reclassified as a skip.

## Non-Goals

- Ethereum consensus, fork choice, validator, P2P, or PeerDAS implementation.
- Full execution-client block processing outside the EVMC VM boundary,
  including client-owned system-call scheduling or networking behavior.
- Performance claims or benchmark results.
- Importing generated fixture archives into Git history.
- Refactoring unrelated interpreter, compiler, runtime, or test code.

## Impact

### Affected Modules

- `evm`: revision-gated opcode and gas semantics; current default revision.
- `tests`: fork parsing, fixture admission, state transitions, mocked execution
  environment, precompile boundaries, result accounting, and regressions.
- `compiler`: propagation of the requested revision through multipass analysis,
  instruction tables, lowering, and fallback.
- `runtime`: preservation of the requested revision in modules and instances.
- `vm-interface`: EVMC revision propagation, module cache identity, and
  interpreter/multipass parity.
- `cli`: explicit `prague` and `osaka` selection and current-mainnet default.
- CI scripts and workflows: pinned fixtures and the Frontier-Osaka matrix.

### Affected Contracts

- A recognized state-test fork label maps to exactly one `evmc_revision`.
- An unrecognized or unsupported fork label fails before execution; it never
  returns `DEFAULT_REVISION`.
- The revision received at the EVMC entry is the revision used for instruction
  availability, gas tables, precompile rules, interpreter execution,
  multipass analysis/lowering, cache identity, and fallback.
- The CLI accepts both `prague` and `osaka` explicitly.
- `DEFAULT_REVISION` advances from Cancun to Osaka. Callers that require
  historical behavior must continue to pass an explicit revision.
- Fixture acquisition verifies the pinned SHA-256 before extraction.

### Compatibility

No EVMC ABI or public C API shape changes. Advancing the default revision is an
intentional behavior change for callers that omit the revision; explicit
historical revisions remain supported. Tests and documentation that rely on
Cancun defaults must name Cancun explicitly.

## Design

### Revision Selection and Propagation

Use one fail-closed fork parser for canonical fixture names and documented
transition aliases. Keep the parser separate from `DEFAULT_REVISION` so an
unknown label cannot acquire valid-looking Cancun or Osaka semantics. Carry
the parsed revision through the existing EVMC/runtime/module/instance path and
use it for interpreter and multipass instruction tables, analyzer decisions,
gas metering, fallback, and cache keys.

### Prague and Osaka Semantics

Treat the pinned fixtures as the behavioral oracle. For each first failing
boundary, add a focused regression that fails for the missing semantic rule,
then make the smallest production change that passes it. Cover, as exercised
by applicable fixtures:

- Prague transaction-type and authorization-list activation boundaries;
- Prague calldata floor, blob schedule, delegation, and precompile behavior;
- Osaka `CLZ` availability and result semantics;
- Osaka transaction gas-limit and `MODEXP` gas changes;
- Osaka revision-gated precompile behavior; and
- exact pre-fork rejection or legacy behavior at every activation boundary.

Precompile behavior supplied by the state-test host must be identified as test
environment support in the evidence report. The production EVMC VM continues
to honor its existing host boundary; the paper must not recast host-provided
behavior as an internal DTVM implementation.

### Fixture Runner and Evidence

Download the pinned develop archive outside the source tree, verify its digest,
and run every discovered state-test case in one unfiltered
`evmone-statetest` invocation per mode, with DTVM loaded as the external EVMC
VM. Explicitly override evmone's default slow-test exclusions. This keeps
execution-client state transition and precompile responsibilities in the test
driver while testing DTVM's VM-visible execution and gas behavior at the EVMC
boundary. The repository's lightweight state-test host remains useful for
focused regression tests, but is not the full-conformance oracle.

The EEST v5.4.0 corpus has non-empty `post` sections for 12 canonical fork
labels. It does not publish dedicated sections for Tangerine Whistle, Spurious
Dragon, or the pre-Petersburg Constantinople revision; those EVMC revisions
remain protected by explicit revision-selection and historical regression
tests. `ConstantinopleFix` is the EEST label for Petersburg. The runner fails
if any of the 12 expected labels is empty, if an unexpected label appears, if
the semantic case-set digest changes, or if any test case fails.

Run the identical complete case set in interpreter and multipass modes. A
mode-specific pass list is invalid evidence. Persist machine-readable
manifests containing the release and archive digest, semantic case-set digest,
per-revision case counts and digests, DTVM commit, execution mode, and aggregate
passed, failed, errored, and excluded counts.

### CI

Make the state-test runner ignore the workflow's legacy `fork_Cancun` name
filter, acquire the pinned corpus, and perform two unfiltered full-corpus runs,
one per DTVM execution mode. Use deterministic multipass without asynchronous
profile-guided recompilation; the separate profile-guided JIT job retains that
coverage. Pin the evmone state-test driver commit as well as the fixture corpus.
Record the result in machine-readable manifests and the GitHub job summary.
Preserve existing interpreter, multipass release/debug, gas-register, evmone
unit, fallback, and performance regression jobs. CI may cache the archive by
its digest but must verify the digest on every restoration.

## Implementation Plan

### Phase 1: Fail-closed revision coverage

- [x] Add failing tests for Osaka mapping, unknown-fork rejection, CLI Prague
  selection, and explicit default semantics.
- [x] Implement one canonical mapping and propagate Osaka through all existing
  state-test selection paths.
- [x] Advance and document the default revision after explicit-revision tests
  protect historical execution.

### Phase 2: Prague and Osaka behavior

- [x] Run the pinned fixture corpus in interpreter mode without suppressing
  cases; no additional VM semantic failure was exposed.
- [x] Confirm existing Prague and Osaka opcode, gas, transaction-admission, and
  precompile-boundary cases pass the official oracle.
- [x] Repeat the identical case set in multipass mode; no mode-specific
  revision-propagation or lowering difference was exposed.

### Phase 3: Reproducible evidence and CI

- [x] Pin the fixture URL, archive SHA-256, and semantic case-set SHA-256 in the
  runner used by the existing state-test workflow.
- [x] Add fail-closed corpus validation and machine-readable manifests.
- [x] Run the complete applicable EEST corpus in both modes and record exact
  per-revision counts.
- [ ] Run all existing DTVM EVM CI-equivalent build, format, unit, fallback,
  differential, and performance-regression gates.
- [ ] Update module specifications, the PR title/body, and the release note to
  match the verified behavior and evidence.

### Acceptance Evidence

The pinned corpus contains 2,723 JSON files and 63,556 cases. Its semantic
case-set SHA-256 is
`461395b7f284c4c262d4c09fa17aab73c3816af7caaeecac4d1a3bcf3009961c`.

| EEST revision label | Cases |
| --- | ---: |
| Frontier | 363 |
| Homestead | 373 |
| Byzantium | 454 |
| ConstantinopleFix (Petersburg) | 463 |
| Istanbul | 608 |
| Berlin | 1,249 |
| London | 1,504 |
| Paris | 1,564 |
| Shanghai | 1,745 |
| Cancun | 16,847 |
| Prague | 18,869 |
| Osaka | 19,517 |

Both acceptance runs loaded the same 63,556-case corpus:

| DTVM mode | Passed | Failed | Errored | Excluded |
| --- | ---: | ---: | ---: | ---: |
| interpreter | 63,556 | 0 | 0 | 0 |
| multipass | 63,556 | 0 | 0 | 0 |

### Commit Strategy

Use as many Conventional Commits as needed to keep each change independently
reviewable and reversible. Prefer one logical commit for each completed test
and implementation boundary or CI/evidence unit. Every implementation commit
must leave the branch buildable and include or reference the regression that
proves its behavior. There is no fixed maximum commit count for PR #600.

## Verification Gates

The implementation is complete only when all conditions hold:

1. The pinned archive digest matches the value above.
2. All 15 EVMC mainnet revisions from Frontier through Osaka are recognized
   explicitly, and every one of the 12 revision labels present in EEST v5.4.0
   has a non-empty case set.
3. Every applicable case passes in both modes: zero failures and zero errors.
4. There are zero unexplained skips; every out-of-scope fixture is listed with
   a boundary-based reason and excluded before the applicable denominator.
5. Focused activation-boundary tests pass immediately before and at Prague and
   Osaka for every implemented rule.
6. Existing Cancun and historical-fork tests remain green with explicit
   revisions.
7. Formatting, `git diff --check`, commit lint, builds, unit tests, fallback,
   differential tests, and existing performance-regression gates pass.
8. The evidence manifest is reproducible from documented commands at the PR
   head commit.

## Compatibility Notes

The default moves to Osaka so an unspecified revision follows the current
mainnet EVM revision represented by the frozen oracle. Consumers that need
Cancun or another historical fork must request it explicitly. Unknown textual
fork names become hard errors rather than inheriting a default.

## Risks

- **Scope inflation in PR #600**: Group work into logical Conventional Commits
  aligned with the implementation phases; do not impose an artificial commit
  limit or mix unrelated refactoring into the branch.
- **False-green coverage**: Fail on unknown forks, empty selections, accounting
  mismatches, digest mismatches, and DTVM-caused skips.
- **Fixture drift**: Use the immutable v5.4.0 URL and SHA-256, never `latest`.
- **Host/VM claim confusion**: Tag host-provided precompile behavior in the
  evidence manifest and retain the EVMC-boundary wording in the paper.
- **Interpreter/JIT divergence**: Execute the identical fixture identifiers in
  both modes and treat any result mismatch as a failure.
- **Default-revision compatibility**: Protect every historical revision with
  explicit-revision regressions and document the behavior change.
