# WAPM Manifest

Source: `webassembly-testsuites/case/wapm/` (experiment archive; upstream artifacts are compiled WAPM registry packages).

## Contents

| Type | Count |
|------|-------|
| `.wasm` | 21 (paper's 20 cases + `fortune`, see below) |
| `*_config.py` / `*.wasm.conf` | per-case run parameters |
| `runtest_wapm.sh` | test runner script |
| `iwasm.conf` / `wasmtime.conf` | runtime configs |
| `fonts/` | dependency of chkfont.wasm / figlet.wasm |
| `parallel-small.png` | input image for viu.wasm |

## Paper Cases (20)

Every case that has Time-to-First-Invocation data in the paper's lazy-latency table:

```
amirali, base64cli, chkfont, code-stock, cowsay, dice, echo, erdtree,
figlet, irb, md5, pi, pkg1, qr2text, sam, suggest, tpl, uuid, viu, zuk
```

Also includes `fortune.wasm`: the reproduction scripts (`run_lazy_*.sh`, `run_*_ttfi_compare.sh`, etc.) use it **in place of zuk** for the TTFI rerun (script comment: `zuk -> fortune (from non-latency pool; verified runnable)`), and the output is mapped back onto the paper's `zuk` row during comparison.

## Non-migrated Upstream Cases (9)

The upstream archive had 30 wasm files; the following 9 were not used in the paper and are not included here:

```
greg, jq, jyt, main, pee, python, spidermonkey, sqlite, wasm3
(plus python.wasm's runtime dependency lib/python3.6/ and wasm3's sub-module benchmark/des.wasm)
```

## Integrity

See `SHA256SUMS` in this directory (covers all 21 wasm files, `fonts/`, and `parallel-small.png`).

## Notes

This directory contains the wasm binaries and test configs actually used in the paper experiments. It does **not** include WAPM registry package names/versions or download scripts (absent from the archive).
