<!--
Copyright (C) 2025 the DTVM authors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
-->

# X86 Cg Peephole Foundation

## Scope Decision

Phase 1 keeps the declarative peephole framework at the existing `CgIR/x86`
layer.

- Rule matching still runs inside `X86CgPeephole`
- Rules live in
  `src/compiler/target/x86/x86_cg_peephole_rules.json`
- The rule file is compiled into C++ at build time by
  `tools/generate_x86_cg_peephole.py`

This keeps the first migration aligned with the current optimization layer and
avoids introducing a new dMIR pass before timing baselines exist.

## Rule DSL

Each rule is a JSON object with these fields:

- `name`: stable identifier used in reports and tests
- `stage`: `instruction` or `block_end`
- `priority`: higher priority rules are emitted first
- `pattern`: ordered instruction match window
- `when`: optional block-level side conditions
- `action`: deterministic rewrite steps

Supported `pattern` matchers:

- `predicate`: call a `CgInstruction` predicate such as `isCompare`
- `opcode`: match a single x86 opcode
- `opcode_any`: match one opcode from a fixed set
- `capture`: bind an operand field for later reuse
- `require`: constrain operand fields to captures, enums, or booleans

Supported operand fields:

- `reg`
- `imm`
- `is_mbb`

Supported `when` conditions:

- `target_is_next_block`

Supported `action` steps:

- `erase`
- `set_imm`

Each rule also carries validation metadata:

- `validation.modes`: declared validation styles for the rule
- `validation.coverage`: concrete test coverage entries

`tools/check_x86_cg_peephole_validation.py` rejects rule files that add rewrites
without validation metadata. When given `--gtest-binary`, it also verifies that
each coverage entry names a real gtest case.

The generated matcher is linear in the number of emitted rules. There is no
runtime search, SMT solving, or e-graph exploration in the JIT path.

Validation coverage can be exported as a machine-readable report:

```bash
python3 tools/report_x86_cg_peephole_validation.py \
  --rules src/compiler/target/x86/x86_cg_peephole_rules.json \
  --gtest-binary ./build-peephole/x86CgPeepholeTests \
  --out /tmp/x86-cg-peephole-validation.json
```

The report summarizes:

- rule count
- per-stage rule counts
- per-mode validation counts
- per-rule coverage completeness against the current gtest binary

## Conflict Checks

The generator emits a rule report and rejects rules that share the same
normalized pattern and priority. The report is generated at build time:

- `build/.../generated/target/x86/x86_cg_peephole_report.txt`

## Compiler Pass Timing Baseline

Compiler-pass timing is written when
`DTVM_COMPILER_PASS_TIMING_JSON=/path/to/file.json` is present.

Recommended baseline workflow:

```bash
python3 tools/collect_compiler_pass_timings.py \
  --dtvm ./build-peephole/dtvm \
  --manifest tests/evm_asm/compiler_pass_timing_manifest.json \
  --runs 5 \
  --output /tmp/dtvm-pass-timing.json \
  -- --format evm -m multipass --compile-only \
     --num-extra-compilations 4 --evm-revision cancun
```

`--compile-only` avoids execution-side noise and keeps the benchmark focused on
module loading and JIT compilation.

The aggregated JSON includes:

- per-case total compile time
- per-pass timing statistics
- `p95` pass-time and pass-share data for budget checks
- per-pass share of total compile time
- manifest-level aggregate summary

Rule operand indices may count from the end of the explicit operand list when
negative. For example, `-1` refers to the last explicit operand, which is
useful for two-address x86 opcodes whose immediate operand is not at a fixed
absolute index once implicit operands such as `EFLAGS` are present.

Budget validation workflow:

```bash
python3 tools/check_compiler_pass_timing_budget.py \
  --budget tests/evm_asm/compiler_pass_timing_budget_x86_cg_peephole.json \
  --report /tmp/dtvm-pass-timing.json
```

Budget refresh workflow:

```bash
python3 tools/update_compiler_pass_timing_budget.py \
  --report /tmp/dtvm-pass-timing.json \
  --budget-in tests/evm_asm/compiler_pass_timing_budget_x86_cg_peephole.json \
  --out tests/evm_asm/compiler_pass_timing_budget_x86_cg_peephole.json \
  --rules src/compiler/target/x86/x86_cg_peephole_rules.json \
  --runs 5 \
  --num-extra-compilations 4
```

Phase 1 uses these outputs to set the peephole budget thresholds:

- max share of function compile time
- max pass wall time
- CI regression threshold
- linear growth check against rule count

`tests/evm_asm/compiler_pass_timing_budget_x86_cg_peephole.json` is an initial local baseline.
It should be recalibrated on the target CI runner before enforcing tighter
regression gates.

## Rule Validation

Current validation coverage is split into two layers:

- structural rewrite tests in `src/tests/x86_cg_peephole_tests.cpp`
- semantics fuzzing for compare/setcc folding in the same test target

The first execution-backed harness is now in place for the
`cmp/setcc/test/jne -> cmp/jcc` rewrite. It executes both the original and
rewritten x86 sequences with inline assembly across edge cases and randomized
inputs, then compares the observed branch result.
