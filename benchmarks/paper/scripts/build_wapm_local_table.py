#!/usr/bin/env python3
"""Merge local WAPM TTFI runs into a paper-style table (compile_ms + ratios)."""

from __future__ import annotations

import csv
import os
import re
from collections import defaultdict
from pathlib import Path
from statistics import mean

ROOT = Path(os.environ.get("ROOT", Path(__file__).resolve().parents[1]))
WAPM = ROOT / "benchmarks" / "wapm"
OUT_DIR = Path(
    os.environ.get(
        "OUT_DIR",
        ROOT / "raw_data" / "benchs" / "wapm_local_table",
    )
)
PAPER_MD = ROOT / "raw_data" / "benchs" / "latencytofirstinvocation.md"

DTVM_LOG_DIR = Path(
    os.environ.get(
        "DTVM_LOG_DIR",
        ROOT / "raw_data" / "benchs" / "wapm_dtvm_wt_compile_20260528_v2" / "logs" / "dtvm",
    )
)
WT_CSV = Path(
    os.environ.get(
        "WT_CSV",
        ROOT / "raw_data" / "benchs" / "wapm_dtvm_wt_compile_20260528_v2" / "wt" / "results.csv",
    )
)
WASMER_CR_CSV = Path(
    os.environ.get(
        "WASMER_CR_CSV",
        ROOT / "raw_data" / "benchs" / "wasmer_cranelift_ttfi_20260528" / "results.csv",
    )
)
WASMER_SP_CSV = Path(
    os.environ.get(
        "WASMER_SP_CSV",
        ROOT / "raw_data" / "benchs" / "wasmer_singlepass_ttfi_20260528" / "results.csv",
    )
)
WASMER_LLVM_CSV = Path(
    os.environ.get(
        "WASMER_LLVM_CSV",
        ROOT / "raw_data" / "benchs" / "wasmer_llvm_ttfi_20260528" / "results.csv",
    )
)
TTFI_EST_CSV = Path(
    os.environ.get(
        "TTFI_EST_CSV",
        ROOT / "raw_data" / "benchs" / "wapm_lazy_ttfi_est_20260528" / "results.csv",
    )
)

CASES = [
    "amirali",
    "base64cli",
    "chkfont",
    "code-stock",
    "cowsay",
    "dice",
    "echo",
    "erdtree",
    "figlet",
    "irb",
    "md5",
    "pi",
    "pkg1",
    "qr2text",
    "sam",
    "suggest",
    "tpl",
    "uuid",
    "viu",
    "fortune",
]

COMPILE_RE = re.compile(r"Total compilation time: \d+ ms \((\d+) [μµ]s\)")


def avg_compile_from_logs(log_dir: Path) -> dict[str, float]:
    by: dict[str, list[float]] = defaultdict(list)
    if not log_dir.is_dir():
        return {}
    for log in sorted(log_dir.glob("*.log")):
        case = log.stem.rsplit("_", 1)[0]
        m = COMPILE_RE.search(log.read_text(encoding="utf-8", errors="replace"))
        if m:
            by[case].append(int(m.group(1)) / 1000.0)
    return {c: mean(v) for c, v in by.items() if v}


def load_csv_compile(path: Path) -> dict[str, float]:
    if not path.is_file():
        return {}
    out: dict[str, float] = {}
    with path.open() as f:
        for row in csv.DictReader(f):
            if row.get("compile_ms"):
                out[row["case"]] = float(row["compile_ms"])
    return out


def avg_ttfi_est(path: Path) -> dict[str, float]:
    if not path.is_file():
        return {}
    by: dict[str, list[float]] = defaultdict(list)
    with path.open() as f:
        for row in csv.DictReader(f):
            by[row["case"]].append(float(row["ttfi_est_ms"]))
    return {c: mean(v) for c, v in by.items() if v}


def wasm_size_kb(case: str) -> float:
    p = WAPM / f"{case}.wasm"
    return p.stat().st_size / 1024.0 if p.is_file() else 0.0


def parse_paper_table() -> dict[str, dict[str, float]]:
    """Parse latencytofirstinvocation.md paper columns."""
    paper: dict[str, dict[str, float]] = {}
    if not PAPER_MD.is_file():
        return paper
    for line in PAPER_MD.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r"case/wapm/([\w-]+)\.wasm", line)
        if not m or "avg" in line.lower():
            continue
        case = m.group(1)
        plain = re.sub(r"<[^>]+>", "", line)
        cells = [c.strip() for c in plain.split("|") if c.strip()]
        if len(cells) >= 7:
            try:
                paper[case] = {
                    "dtvm": float(cells[2]),
                    "wasmtime": float(cells[3]),
                    "wasmer_cranelift": float(cells[4]),
                    "wasmer_llvm": float(cells[5]),
                    "wasmer_singlepass": float(cells[6]),
                }
            except ValueError:
                pass
    return paper


def ratio(a: float | None, b: float | None) -> str:
    if a is None or b is None or b == 0:
        return ""
    return f"{a / b:.3f}"


def main() -> None:
    dtvm = avg_compile_from_logs(DTVM_LOG_DIR)
    ttfi_est = avg_ttfi_est(TTFI_EST_CSV)
    dtvm_proxy: list[str] = []
    for case in CASES:
        if case not in dtvm and case in ttfi_est:
            dtvm[case] = ttfi_est[case]
            dtvm_proxy.append(case)

    wt = load_csv_compile(WT_CSV)
    cr = load_csv_compile(WASMER_CR_CSV)
    sp = load_csv_compile(WASMER_SP_CSV)
    ll = load_csv_compile(WASMER_LLVM_CSV)
    paper = parse_paper_table()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    for case in CASES:
        z = dtvm.get(case)
        w = wt.get(case)
        c = cr.get(case)
        s = sp.get(case)
        llv = ll.get(case)
        rows.append(
            {
                "case": case,
                "wasm_kb": wasm_size_kb(case),
                "dtvm": z,
                "wasmtime": w,
                "wasmer_cranelift": c,
                "wasmer_llvm": llv,
                "wasmer_singlepass": s,
                "wt_over_dtvm": float(ratio(w, z)) if ratio(w, z) else None,
                "cr_over_dtvm": float(ratio(c, z)) if ratio(c, z) else None,
                "ll_over_dtvm": float(ratio(llv, z)) if ratio(llv, z) else None,
                "sp_over_dtvm": float(ratio(s, z)) if ratio(s, z) else None,
                "paper_dtvm": paper.get(case, {}).get("dtvm"),
                "paper_wasmtime": paper.get(case, {}).get("wasmtime"),
                "paper_wasmer_cranelift": paper.get(case, {}).get("wasmer_cranelift"),
                "paper_wasmer_llvm": paper.get(case, {}).get("wasmer_llvm"),
                "paper_wasmer_singlepass": paper.get(case, {}).get("wasmer_singlepass"),
            }
        )

    csv_path = OUT_DIR / "wapm_local_latency_table.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "case",
                "wasm_kb",
                "dtvm_compile_ms",
                "wasmtime_compile_ms",
                "wasmer_cranelift_ms",
                "wasmer_llvm_ms",
                "wasmer_singlepass_ms",
                "wt_over_dtvm",
                "cr_over_dtvm",
                "ll_over_dtvm",
                "sp_over_dtvm",
                "paper_dtvm",
                "paper_wasmtime",
                "paper_wasmer_cr",
                "paper_wasmer_llvm",
                "paper_wasmer_sp",
            ]
        )
        for r in rows:
            w.writerow(
                [
                    r["case"],
                    f"{r['wasm_kb']:.3f}",
                    f"{r['dtvm']:.3f}" if r["dtvm"] is not None else "",
                    f"{r['wasmtime']:.3f}" if r["wasmtime"] is not None else "",
                    f"{r['wasmer_cranelift']:.3f}" if r["wasmer_cranelift"] is not None else "",
                    f"{r['wasmer_llvm']:.3f}" if r["wasmer_llvm"] is not None else "",
                    f"{r['wasmer_singlepass']:.3f}" if r["wasmer_singlepass"] is not None else "",
                    f"{r['wt_over_dtvm']:.3f}" if r["wt_over_dtvm"] is not None else "",
                    f"{r['cr_over_dtvm']:.3f}" if r["cr_over_dtvm"] is not None else "",
                    f"{r['ll_over_dtvm']:.3f}" if r["ll_over_dtvm"] is not None else "",
                    f"{r['sp_over_dtvm']:.3f}" if r["sp_over_dtvm"] is not None else "",
                    r["paper_dtvm"] or "",
                    r["paper_wasmtime"] or "",
                    r["paper_wasmer_cranelift"] or "",
                    r["paper_wasmer_llvm"] or "",
                    r["paper_wasmer_singlepass"] or "",
                ]
            )

    def fmt(v: float | None, proxy: bool = False) -> str:
        if v is None:
            return "—"
        s = f"{v:.3f}"
        if proxy:
            s += "†"
        return s

    md_lines = [
        "# WAPM local latency table (compile / TTFI)\n",
        "\n",
        "Same layout as paper `latencytofirstinvocation.md`. "
        "All runtime columns are **`Total compilation time`** (ms, from stdout), "
        "3-run local average unless noted.\n",
        "\n",
        "**Data sources**\n",
        f"- dtvm: `{DTVM_LOG_DIR}`\n",
        f"- wasmtime: `{WT_CSV}`\n",
        f"- wasmer cranelift: `{WASMER_CR_CSV}`\n",
        f"- wasmer singlepass: `{WASMER_SP_CSV}`\n",
        (
            f"- wasmer llvm: `{WASMER_LLVM_CSV}`\n"
            if WASMER_LLVM_CSV.is_file()
            else "- wasmer llvm: not built (requires LLVM 21)\n"
        ),
        "\n",
    ]
    if dtvm_proxy:
        md_lines.append(
            f"† dtvm for **{', '.join(dtvm_proxy)}**: no `Total compilation time` in dtvm logs; "
            f"filled with **`ttfi_est`** from `{TTFI_EST_CSV.name}` "
            "(different formula — re-run with instrumented `dtvm` for strict compare).\n\n"
        )

    md_lines.append(
        "| case | wasm KB | dtvm lazy (dtvm) | wasmtime | wasmer cranelift | wasmer llvm | wasmer singlepass | wt/dtvm | cr/dtvm | ll/dtvm | sp/dtvm |\n"
    )
    md_lines.append("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")

    ratios_wt, ratios_cr, ratios_ll, ratios_sp = [], [], [], []
    for r in rows:
        proxy = r["case"] in dtvm_proxy
        md_lines.append(
            f"| case/wapm/{r['case']}.wasm | {r['wasm_kb']:.3f} | "
            f"{fmt(r['dtvm'], proxy)} | {fmt(r['wasmtime'])} | {fmt(r['wasmer_cranelift'])} | "
            f"{fmt(r['wasmer_llvm'])} | {fmt(r['wasmer_singlepass'])} | "
            f"{fmt(r['wt_over_dtvm']) if r['wt_over_dtvm'] else '—'} | "
            f"{fmt(r['cr_over_dtvm']) if r['cr_over_dtvm'] else '—'} | "
            f"{fmt(r['ll_over_dtvm']) if r['ll_over_dtvm'] else '—'} | "
            f"{fmt(r['sp_over_dtvm']) if r['sp_over_dtvm'] else '—'} |\n"
        )
        if r["wt_over_dtvm"] is not None:
            ratios_wt.append(r["wt_over_dtvm"])
        if r["cr_over_dtvm"] is not None:
            ratios_cr.append(r["cr_over_dtvm"])
        if r["ll_over_dtvm"] is not None:
            ratios_ll.append(r["ll_over_dtvm"])
        if r["sp_over_dtvm"] is not None:
            ratios_sp.append(r["sp_over_dtvm"])

    md_lines.append(
        f"| **avg** | | | | | | | **{mean(ratios_wt):.3f}** | **{mean(ratios_cr):.3f}** | "
        f"**{mean(ratios_ll):.3f}** | **{mean(ratios_sp):.3f}** |\n"
        if ratios_ll
        else f"| **avg** | | | | | | | **{mean(ratios_wt):.3f}** | **{mean(ratios_cr):.3f}** | — | **{mean(ratios_sp):.3f}** |\n"
    )

    md_lines.append("\n## Local vs paper (compile ms ratio)\n\n")
    md_lines.append(
        "| case | dtvm L/P | wt L/P | wasmer-cr L/P | wasmer-llvm L/P | wasmer-sp L/P |\n"
    )
    md_lines.append("| :--- | ---: | ---: | ---: | ---: | ---: |\n")
    zr, wr, cr_r, ll_r, sr = [], [], [], [], []

    def lp_ratio(local: float | None, paper: float | None) -> str:
        if local is None or paper is None or paper == 0:
            return "—"
        return f"{local / paper:.2f}"

    for r in rows:
        zc = lp_ratio(r["dtvm"], r["paper_dtvm"])
        wc = lp_ratio(r["wasmtime"], r["paper_wasmtime"])
        cc = lp_ratio(r["wasmer_cranelift"], r["paper_wasmer_cranelift"])
        lc = lp_ratio(r["wasmer_llvm"], r["paper_wasmer_llvm"])
        sc = lp_ratio(r["wasmer_singlepass"], r["paper_wasmer_singlepass"])
        if r["dtvm"] and r["paper_dtvm"]:
            zr.append(r["dtvm"] / r["paper_dtvm"])
        if r["wasmtime"] and r["paper_wasmtime"]:
            wr.append(r["wasmtime"] / r["paper_wasmtime"])
        if r["wasmer_cranelift"] and r["paper_wasmer_cranelift"]:
            cr_r.append(r["wasmer_cranelift"] / r["paper_wasmer_cranelift"])
        if r["wasmer_llvm"] and r["paper_wasmer_llvm"]:
            ll_r.append(r["wasmer_llvm"] / r["paper_wasmer_llvm"])
        if r["wasmer_singlepass"] and r["paper_wasmer_singlepass"]:
            sr.append(r["wasmer_singlepass"] / r["paper_wasmer_singlepass"])
        md_lines.append(f"| {r['case']} | {zc} | {wc} | {cc} | {lc} | {sc} |\n")

    if zr:
        ll_mean = f", wasmer-llvm {mean(ll_r):.2f}×" if ll_r else ""
        md_lines.append(
            f"\n**Mean local/paper:** dtvm {mean(zr):.2f}×, wasmtime {mean(wr):.2f}×, "
            f"wasmer-cr {mean(cr_r):.2f}×{ll_mean}, wasmer-sp {mean(sr):.2f}× "
            f"({len(zr)} cases with paper dtvm; fortune replaces paper zuk).\n"
        )

    md_path = OUT_DIR / "wapm_local_latency_table.md"
    md_path.write_text("".join(md_lines))
    print(f"Wrote {csv_path}")
    print(f"Wrote {md_path}")
    if dtvm_proxy:
        print(f"DTVM proxy (ttfi_est): {', '.join(dtvm_proxy)}")


if __name__ == "__main__":
    main()
