# dtvm_polybench.xlsx — Table Format Notes (issue log)

## Conclusion

Do **not** directly compare the `bench_polybench_timing.sh` wall time (one whole-process invocation) against the xlsx columns as a "reproduction" ratio, unless the following are confirmed with the experimenters first:

1. Whether each cell is **compile time** or **total time** (or some other definition);
2. **Which row group** of the sheet is being used (the same case names repeat in multiple groups);
3. Whether the unit is **ms** or **seconds** (some compile cells are fractions, e.g. `0.935`).

## Table Structure (as observed)

### Group 1 (roughly rows 2–31)

- Row label: `case/benchmark/polybenchc/<case>.wasm`
- Columns B–K: headers still show row 1's `dtvm multipass`, `dtvm multipass + lazy`, `wasmtime`, etc.
- **Each config has only one numeric column**, not labeled compile / total
  - Example: `2mm`'s `dtvm multipass` = **3314.16** (magnitude looks like ms; semantics unlabeled)

### Group 2 (from roughly row 76)

- Row 76 sub-headers (alternating column pairs):
  - **B** = `Compile time (ms)` → belongs to column name **dtvm multipass**
  - **C** = `Total time (ms)` → belongs to column name **dtvm multipass + lazy**
  - **D/E, F/G…** likewise alternate **Compile / Total**
- So within the same data row, **column B is multipass's compile and column C is lazy's total** — not a "compile + total" pair for the same config.

Example: `2mm` (row 77)

| Column | Column name (row 1) | Sub-header (row 76) | Value | Meaning (per experimenter feedback) |
|--------|---------------------|---------------------|-------|--------------------------------------|
| B | dtvm multipass | Compile time | **0.935** | **compile time** (seconds; ×1000 ≈ 935 ms) |
| C | dtvm multipass + lazy | Total time | **3283.55** | lazy **total time** (ms) |

The earlier script incorrectly treated **B = 0.935×1000 = 935** as multipass "total time" when comparing against local wall time.

### Duplicate Rows

The same `case` appears **multiple times** in the sheet (e.g. `2mm` at least 4 rows). The old script scanned row by row and **later rows overwrote earlier ones**, easily landing on the compile row at row 76+ rather than row 2's 3314.16.

## What the Local Timing Script Measures

`bench_polybench_timing.sh`:

- Each run: `dtvm … case.wasm` in a **separate process**
- Measure: `date` **wall time (ms)** = typically **JIT compile + execution** (+ process startup)
- Per case: 1× warmup + 3× timed, median reported

This is **not the same metric** as the xlsx's compile-only or total-only cells.

## Status of Previous Comparison Tables

The **ratios in the following files are historical records only** — until the xlsx semantics are clarified they **must not be read as reproduction success/failure**:

- `polybench_paired_compare_20260526.csv` / `.md` (not included)
- `polybench_all_runtimes_compare_20260526.md` / `.csv` (not included)
- `polybench_local_vs_paper_*` (not included)

## Recommended Reading (DTVM vs Wasmtime vs Wasmer-LLVM relative relationship)

- `polybench_runtime_compare_20260526.md` / `.csv` (not included) — **`DTVM/Wasm/LLVM`** (e.g. `1/1.02/7.03`) normalized comparison (main document)

## Total-only Absolute Comparison (auxiliary)

- `polybench_total_only_compare_20260526.csv` / `.md` (not included)

Extraction summary:

| Config | Total source |
|--------|--------------|
| dtvm multipass | group 1 rows 2–31, column B (this group has no Compile/Total sub-header) |
| dtvm multipass+lazy | group 2 rows 77–106, column C (row 76 marks **Total time**) |
| wasmtime | group 1 rows 2–31, column F |
| wasmer llvm | group 2 rows 77–106, column I (**Total time**) |

**Do not** use group-2 column B's 0.935 (Compile).

## If the Numbers Still Do Not Line Up

1. Confirm with the experimenters whether group-1 columns B/F are really **total** (rather than another metric).
2. Split compile / execute locally, or restore the paper's `Average time` script.
3. Check whether dtvm contains an `exit optimization` matching xlsx columns D/E.
