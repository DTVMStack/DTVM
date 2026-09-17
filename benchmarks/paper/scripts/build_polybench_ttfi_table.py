#!/usr/bin/env python3
"""Merge PolyBench TTFI results.csv files into one comparison table."""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parents[1]


def load_compile(path: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    with path.open() as f:
        for row in csv.DictReader(f):
            if row.get("compile_ms"):
                out[row["case"]] = float(row["compile_ms"])
    return out


def main() -> None:
    bench_root = Path(os.environ["BENCH_ROOT"])
    out_dir = Path(os.environ.get("OUT_DIR", bench_root / "table"))
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "dtvm": Path(os.environ["DTVM_CSV"]),
        "wasmtime45": Path(os.environ["WT_CSV"]),
        "wasmer_sp": Path(os.environ["WASMER_SP_CSV"]),
        "wasmer_cf": Path(os.environ["WASMER_CF_CSV"]),
        "wasmer_llvm": Path(os.environ["WASMER_LLVM_CSV"]),
    }
    greedy_path = os.environ.get("DTVM_GREEDY_CSV")
    greedy: dict[str, float] | None = None
    if greedy_path:
        greedy = load_compile(Path(greedy_path))

    data = {k: load_compile(p) for k, p in paths.items()}
    case_sets = [set(d.keys()) for d in data.values()]
    if greedy:
        case_sets.append(set(greedy.keys()))
    cases = sorted(set.intersection(*case_sets))
    if not cases:
        print("No overlapping cases", file=sys.stderr)
        sys.exit(1)

    csv_path = out_dir / "polybench_ttfi_compare.csv"
    rows = []
    for case in cases:
        row = {"case": case}
        for k, d in data.items():
            row[f"{k}_compile_ms"] = d[case]
        if greedy and case in greedy:
            row["dtvm_greedy_mt_compile_ms"] = greedy[case]
        row["dtvm_over_wt"] = data["dtvm"][case] / data["wasmtime45"][case]
        row["dtvm_over_wasmer_llvm"] = data["dtvm"][case] / data["wasmer_llvm"][case]
        rows.append(row)

    fields = ["case"] + [f"{k}_compile_ms" for k in paths] + [
        "dtvm_over_wt",
        "dtvm_over_wasmer_llvm",
    ]
    if greedy:
        fields.insert(2, "dtvm_greedy_mt_compile_ms")

    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    def med_ratio(num: str, den: str, src: dict[str, dict[str, float]] | None = None) -> float:
        d = src or data
        rs = [d[num][c] / d[den][c] for c in cases]
        return median(rs)

    dtvm_ver = (
        Path(os.environ["DTVM_VERSION"]).read_text().strip()
        if os.environ.get("DTVM_VERSION")
        else "dtvm_main"
    )
    md_path = out_dir / "polybench_ttfi_compare.md"
    md = [
        "# PolyBench TTFI (Total compilation time)\n",
        "\nMetric: WAPM `Total compilation time` line (load + post-loading compile before first execution).\n",
        "\n## Runtimes\n",
        "- DTVM: **multipass lazy** (same as WAPM: `--enable-multipass-lazy`, greedy/MT off, `--enable-statistics`)\n",
        f"  - commit: `{dtvm_ver}`\n",
        "- Wasmtime: **45.0.0** (`WASMTIME_CACHE=0`, cold cache per repeat)\n",
        "- Wasmer: **7.1.0** singlepass / cranelift / llvm (`--cache-dir=/dev/null`)\n",
        f"\n**Data dir:** `{bench_root}`\n",
    ]
    if greedy:
        md.append(
            "\n> Note: the `dtvm_greedy_mt` column is an earlier eager `-m multipass` result (not directly comparable to the WAPM lazy metric).\n"
        )
    md += [
        "\n## Median compile (ms) ratios (DTVM lazy)\n",
        f"| DTVM lazy / Wasmtime 45 | **{med_ratio('dtvm', 'wasmtime45'):.3f}** |\n",
        f"| DTVM lazy / Wasmer singlepass | **{med_ratio('dtvm', 'wasmer_sp'):.3f}** |\n",
        f"| DTVM lazy / Wasmer cranelift | **{med_ratio('dtvm', 'wasmer_cf'):.3f}** |\n",
        f"| DTVM lazy / Wasmer llvm | **{med_ratio('dtvm', 'wasmer_llvm'):.3f}** |\n",
        f"| Wasmtime / Wasmer llvm | **{med_ratio('wasmtime45', 'wasmer_llvm'):.3f}** |\n",
        "\nNormalized **DTVM lazy / Wasm45 / Wasmer-LLVM**: "
        f"**1 / {med_ratio('wasmtime45', 'dtvm'):.2f} / {med_ratio('wasmer_llvm', 'dtvm'):.2f}**\n",
    ]
    if greedy:
        gdata = {"dtvm": greedy, **{k: v for k, v in data.items() if k != "dtvm"}}
        md.append(
            f"\n(reference) DTVM greedy_mt / Wasmtime 45 median: **{med_ratio('dtvm', 'wasmtime45', gdata):.3f}**\n"
        )
    md += [
        "\n## Per-case compile ms\n",
        "\n| case | DTVM lazy | "
        + ("DTVM greedy_mt | " if greedy else "")
        + "Wasm45 | Wasmer SP | Wasmer CF | Wasmer LLVM | lazy/WT | lazy/LLVM |\n",
        "|---|---:|"
        + ("---:|" if greedy else "")
        + "---:|---:|---:|---:|---:|---:|\n",
    ]
    for case in cases:
        greedy_col = f"{greedy[case]:.1f} | " if greedy and case in greedy else ""
        md.append(
            f"| {case} | {data['dtvm'][case]:.1f} | {greedy_col}"
            f"{data['wasmtime45'][case]:.1f} | "
            f"{data['wasmer_sp'][case]:.1f} | {data['wasmer_cf'][case]:.1f} | "
            f"{data['wasmer_llvm'][case]:.1f} | "
            f"{data['dtvm'][case]/data['wasmtime45'][case]:.2f} | "
            f"{data['dtvm'][case]/data['wasmer_llvm'][case]:.2f} |\n"
        )
    md.append(f"\nFull CSV: [`{csv_path.name}`]({csv_path.name})\n")
    md_path.write_text("".join(md))
    print(f"Wrote {csv_path}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
