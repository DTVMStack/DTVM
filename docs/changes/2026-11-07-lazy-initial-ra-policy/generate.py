#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import subprocess, json, hashlib
import argparse

p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
a = p.parse_args()
b = Path(a.out)
b.mkdir(parents=True, exist_ok=True)
locals_ = " ".join(f"(local $a{i} i32)" for i in range(20))
init = "\n".join(
    f"(local.set $a{i} (i32.mul (local.get $n) (i32.const {i+1})))" for i in range(20)
)
updates = "\n".join(
    f"(local.set $a{i} (i32.add (local.get $a{i}) (i32.mul (local.get $b) (i32.const {i+1}))))"
    for i in range(20)
)
sum_ = "(local.get $a0)"
for i in range(1, 20):
    sum_ = f"(i32.add {sum_} (local.get $a{i}))"
step = f"(local.set $a (i32.load (i32.const 0)))\n(local.set $b (i32.load (i32.const 8)))\n{updates}\n(i32.store (i32.const 0) (i32.add (local.get $a) {sum_}))"
for v in reversed(["i", "j", "k"]):
    step = f"(local.set ${v} (i32.const 0))\n(loop ${v}\n{step}\n(br_if ${v} (i32.lt_u (local.tee ${v} (i32.add (local.get ${v}) (i32.const 1))) (local.get $n))))"
kernel = f"""(func $kernel (param $n i32) (param $marker i32) (result i32)
(local $i i32) (local $j i32) (local $k i32) (local $a i32) (local $b i32) {locals_}
(call $emit (local.get $marker))
(i32.store (i32.const 0) (i32.const 0)) (i32.store (i32.const 8) (i32.const 1))
{init}
(if (local.get $n) (then {step}))
(i32.load (i32.const 0)))"""
common = """(module
(import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
(import "wasi_snapshot_preview1" "args_sizes_get" (func $sizes (param i32 i32) (result i32)))
(import "wasi_snapshot_preview1" "args_get" (func $args (param i32 i32) (result i32)))
(memory (export "memory") 1)
(func $emit (param $c i32)
 (i32.store8 (i32.const 128) (local.get $c))
 (i32.store (i32.const 64) (i32.const 128)) (i32.store (i32.const 68) (i32.const 1))
 (drop (call $write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 72))))
(func $result (param $r i32)
 (i32.store (i32.const 256) (local.get $r))
 (i32.store (i32.const 64) (i32.const 256)) (i32.store (i32.const 68) (i32.const 4))
 (drop (call $write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 72))))
(func $parse (param $p i32) (result i32) (local $n i32) (local $c i32)
 (block $end (loop $loop
 (local.set $c (i32.load8_u (local.get $p)))
 (br_if $end (i32.eqz (local.get $c)))
 (local.set $n (i32.add (i32.mul (local.get $n) (i32.const 10)) (i32.sub (local.get $c) (i32.const 48))))
 (local.set $p (i32.add (local.get $p) (i32.const 1))) (br $loop))) (local.get $n))
"""
start = """(func (export "_start") (local $n i32) (local $r i32)
 (drop (call $sizes (i32.const 512) (i32.const 516)))
 (drop (call $args (i32.const 520) (i32.const 2048)))
 (local.set $n (call $parse (i32.load (i32.const 524))))
 (call $emit (i32.const 69))
 (local.set $r (call $kernel (local.get $n) (i32.const 75)))
 (call $emit (i32.const 68)) (call $result (local.get $r))
 (local.set $r (call $kernel (local.get $n) (i32.const 107)))
 (call $emit (i32.const 100)) (call $result (local.get $r)))
"""
meta = {}
for label, cold in [("small", 0), ("large", 3000)]:
    table = (
        f'(table (export "cold_table") {cold} funcref)\n(elem (i32.const 0) '
        + " ".join(f"$cold{i}" for i in range(cold))
        + ")\n"
        if cold
        else ""
    )
    text = (
        common
        + table
        + kernel
        + "\n"
        + start
        + "\n"
        + "\n".join(kernel.replace("$kernel", f"$cold{i}") for i in range(cold))
        + ")\n"
    )
    wat = b / f"{label}.wat"
    wasm = b / f"{label}.wasm"
    wat.write_text(text)
    subprocess.run(["wat2wasm", str(wat), "-o", str(wasm)], check=True)
    meta[label] = {
        "cold_table_functions": cold,
        "wasm_bytes": wasm.stat().st_size,
        "sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
    }
(b / "modules.json").write_text(json.dumps(meta, indent=2) + "\n")
print(meta)
