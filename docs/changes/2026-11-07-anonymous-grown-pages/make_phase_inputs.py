#!/usr/bin/env python3
"""Derived diagnostic inputs; preserve original exports and main init/free."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
p.add_argument("--counts", default="1,8,30")
a = p.parse_args()
out = Path(a.out)
out.mkdir(parents=True, exist_ok=True)
meta = {}
sha = lambda x: hashlib.sha256(x).hexdigest()
for case in ["atax", "bicg"]:
    canonical = Path("benchmarks/paper/benchmarks/polybenchc") / (case + ".wasm")
    raw = out / (case + "-canonical.wat")
    subprocess.run(["wasm-dis", str(canonical), "-o", str(raw)], check=True)
    original = raw.read_text()
    exports = re.findall(r"^ \(export .+$", original, re.M)
    assert '(export "_start" (func $_start))' in original
    pos = original.index(" (global ")
    text = (
        original[:pos]
        + ' (import "wasi_snapshot_preview1" "clock_time_get" (func $research_clock (param i32 i64 i32) (result i32)))\n'
        + original[pos:]
    )
    start = text.index(" (func $main ")
    end = text.index("\n (func ", start + 2)
    body = text[start:end]
    marks = [
        ("  (global.set $global$0", 16, 2),
        ("  (loop $label$1", 24, 1),
        ("  (loop $label$2", 32, 1),
        ("  (local.set $12\n   (i32.const 0)", 40, 1),
        ("  (drop\n   (call $fwrite\n    (i32.const 1024)", 48, 1),
    ]
    for needle, addr, count in marks:
        assert body.count(needle) == count, (case, addr, body.count(needle))
        body = body.replace(
            needle, f"  (call $research_mark (i32.const {addr}))\n" + needle, 1
        )
    ret = "  (i32.const 0)\n )"
    assert body.rstrip().endswith(ret), (case, body[-100:])
    pos = body.rfind(ret)
    body = body[:pos] + "  (call $research_finish)\n" + body[pos:]
    text = text[:start] + body + text[end:]
    helper = """
 (func $research_mark (param $p i32)
  (if (call $research_clock (i32.const 1) (i64.const 1) (local.get $p))
   (then (unreachable))))
 (func $research_finish
  (call $research_mark (i32.const 56))
  (i32.store (i32.const 64) (i32.const 8))
  (i32.store (i32.const 68) (i32.const 56))
  (if (call $__wasi_fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 72))
   (then (unreachable))))
"""
    text = text[: text.rfind(")")] + helper + text[text.rfind(")") :]
    for count in map(int, a.counts.split(",")):
        assert count > 0
        variant = text
        start = variant.index(" (func $_start\n")
        end = variant.index("\n (func ", start + 2)
        body = variant[start:end]
        local = "  (local $0 i32)"
        assert body.count(local) == 1
        body = body.replace(local, local + "\n  (local $research_left i32)")
        call = "  (local.set $0\n   (call $__original_main)\n  )"
        assert body.count(call) == 1
        repeat = f"""  (local.set $research_left (i32.const {count}))
  (block $research_done
   (loop $research_calls
    (call $research_mark (i32.const 8))
    (local.set $0 (call $__original_main))
    (br_if $research_done (local.get $0))
    (local.set $research_left (i32.sub (local.get $research_left) (i32.const 1)))
    (br_if $research_calls (local.get $research_left))))"""
        body = body.replace(call, repeat)
        variant = variant[:start] + body + variant[end:]
        assert re.findall(r"^ \(export .+$", variant, re.M) == exports
        wat = out / f"{case}-phases-r{count}.wat"
        wasm = wat.with_suffix(".wasm")
        wat.write_text(variant)
        subprocess.run(["wasm-as", str(wat), "-o", str(wasm)], check=True)
        meta[f"{case}:{count}"] = {
            "case": case,
            "count": count,
            "canonical": str(canonical.resolve()),
            "canonical_sha256": sha(canonical.read_bytes()),
            "canonical_wat_sha256": sha(original.encode()),
            "wasm": str(wasm.resolve()),
            "wasm_sha256": sha(wasm.read_bytes()),
            "exports": exports,
            "scratch_bytes": [8, 76],
            "stamps": [
                "original_main pre-call",
                "main entry",
                "allocation complete",
                "vector initialization complete",
                "matrix initialization complete",
                "numeric kernel complete",
                "output/free/stack restore complete",
            ],
            "notes": [
                "Original exported _start stays exported; main stays private; no new exports/background seed functions.",
                "Constructors execute once, original_main repeats in same instance, destructors execute once.",
                "Each original main call retains its original allocation/initialization/free/stack reset and stderr output.",
                "Research calls are outside all original main loops, including qualifying FP loop subtrees.",
                "Pre-call to main entry includes original_main wrapper/args work and demand compilation, not pure compiler time.",
                "First stamp packet is a parent-observed result event before main returns, not a pure function-return timestamp.",
                "Extra host-clock helper compile is excluded from the first internal pre-call timestamp, included in process-first-result/total.",
            ],
        }
(out / "phase-inputs.json").write_text(json.dumps(meta, indent=2) + "\n")
print("Generated", len(meta), "derived inputs; original exports preserved")
