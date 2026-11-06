;; Multi-input word update regions; reject mixed, read-only and irregular loops.
(module (memory 1)
(func $word (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8))))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $wide (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i64.store (i32.const 0) (i64.const 0))
(i64.store (i32.const 8) (i64.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i64.store (i32.const 0) (i64.add (i64.load (i32.const 0)) (i64.load (i32.const 8))))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.wrap_i64 (i64.load (i32.const 0))))
(func $shallow (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $bytes (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store8 (i32.const 0) (i32.const 0))
(i32.store8 (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i32.store8 (i32.const 0) (i32.add (i32.load8_u (i32.const 0)) (i32.load8_u (i32.const 8))))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load8_u (i32.const 0)))
(func $registers (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)

(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(local.set $s (i32.add (local.get $s) (i32.const 1)))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(local.get $s))
(func $callful (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8))))
(block (drop (call $one)))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $one (result i32) (i32.const 1))
(func $blocks (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(block (block (block (i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8)))))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $cold (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8))))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $oversized (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop 
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8))))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $readonly (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(local.set $s (i32.add (local.get $s) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8)))))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(local.get $s))
(func $mixed (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(i32.store8 (i32.const 16) (i32.const 0))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i32.store (i32.const 0) (i32.add (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8))) (i32.load8_u (i32.const 16))))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $single (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.const 1)))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func $deepcall (param $n i32) (result i32) (local $i i32) (local $j i32) (local $k i32) (local $h i32) (local $s i32)
(i32.store (i32.const 0) (i32.const 0))
(i32.store (i32.const 8) (i32.const 1))
(local.set $i (i32.const 0))
(loop $i
(local.set $j (i32.const 0))
(loop $j
(local.set $k (i32.const 0))
(loop $k
(local.set $h (i32.const 0))
(loop $h
(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.load (i32.const 8))))
(br_if $h (i32.lt_u (local.tee $h (i32.add (local.get $h) (i32.const 1))) (local.get $n))))
(drop (call $one))
(br_if $k (i32.lt_u (local.tee $k (i32.add (local.get $k) (i32.const 1))) (local.get $n))))
(br_if $j (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
(br_if $i (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
(i32.load (i32.const 0)))
(func (export "entry") (export "alias") (param $which i32) (param $n i32) (result i32)
(if (i32.eq (local.get $which) (i32.const 0)) (then (return (call $word (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 1)) (then (return (call $wide (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 2)) (then (return (call $shallow (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 3)) (then (return (call $bytes (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 4)) (then (return (call $registers (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 5)) (then (return (call $callful (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 6)) (then (return (call $blocks (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 7)) (then (return (call $oversized (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 8)) (then (return (call $readonly (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 9)) (then (return (call $mixed (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 10)) (then (return (call $single (local.get $n)))))
(if (i32.eq (local.get $which) (i32.const 11)) (then (return (call $deepcall (local.get $n)))))
(i32.const 0))
)
