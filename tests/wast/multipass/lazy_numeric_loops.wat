;; First-call allocator selection without names or repeated calls.
(module
 (type $one_t (func (result f64)))
 (table 1 funcref)
 (elem (i32.const 0) $one)
 (func $nested (param $n i32) (result f64)
  (local $i i32) (local $j i32) (local $sum f64)
  
  (drop (call $one)) ;; Calls outside the numeric loop must not disqualify it.
  (loop $outer
   (local.set $j (i32.const 0))
   (loop $inner
    (local.set $sum (f64.add (local.get $sum) (f64.const 1)))
    (br_if $inner (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $outer (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $sum))
 (func $siblings (param $n i32) (result f64) (local $i i32) (local $s f64)
  (loop $a
   (local.set $s (f64.add (local.get $s) (f64.const 1)))
   (br_if $a (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.set $i (i32.const 0))
  (loop $b
   (local.set $s (f64.add (local.get $s) (f64.const 1)))
   (br_if $b (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $s))
 (func $blocks (param $n i32) (result f64) (local $i i32) (local $s f64)
  (loop $a
   (block (block (local.set $s (f64.add (local.get $s) (f64.const 1)))))
   (br_if $a (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $s))
 (func $outside (param $n i32) (result f64) (local $i i32) (local $j i32) (local $s i32)
  (loop $a
   (local.set $j (i32.const 0))
   (loop $b
    (local.set $s (i32.add (local.get $s) (i32.const 1)))
    (br_if $b (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $a (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (f64.add (f64.convert_i32_u (local.get $s)) (f64.const 0.5)))
 (func $nested32 (param $n i32) (result f32)
  (local $i i32) (local $j i32) (local $sum f32)
  
  (loop $outer
   (drop (call $one)) ;; The inner loop remains call-free.
   (local.set $j (i32.const 0))
   (loop $inner
    (local.set $sum (f32.add (local.get $sum) (f32.const 1)))
    (br_if $inner (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $outer (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $sum))
 (func $oversized (param $n i32) (result f64)
  (local $i i32) (local $j i32) (local $sum f64)
  ;; Source-size guard: body between 2 KiB and 4 KiB, with no runtime work.
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
  (loop $outer
   (local.set $j (i32.const 0))
   (loop $inner
    (local.set $sum (f64.add (local.get $sum) (f64.const 1)))
    (br_if $inner (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $outer (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $sum))
 (func $cold (param $n i32) (result f64)
  (local $i i32) (local $j i32) (local $sum f64)
  
  (loop $outer
   (local.set $j (i32.const 0))
   (loop $inner
    (local.set $sum (f64.add (local.get $sum) (f64.const 1)))
    (br_if $inner (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $outer (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $sum))
 (func (export "entry") (export "alias") (param $which i32) (param $n i32) (result f64)
  (if (i32.eqz (local.get $which)) (then (return (call $nested (local.get $n)))))
  (if (i32.eq (local.get $which) (i32.const 1)) (then (return (call $siblings (local.get $n)))))
  (if (i32.eq (local.get $which) (i32.const 2)) (then (return (call $blocks (local.get $n)))))
  (if (i32.eq (local.get $which) (i32.const 3)) (then (return (call $outside (local.get $n)))))
  (if (i32.eq (local.get $which) (i32.const 4)) (then (return (f64.promote_f32 (call $nested32 (local.get $n))))))
  (if (i32.eq (local.get $which) (i32.const 6)) (then (return (call $callful (local.get $n)))))
  (if (i32.eq (local.get $which) (i32.const 7)) (then (return (call $indirect_callful (local.get $n)))))
  (if (i32.eq (local.get $which) (i32.const 8)) (then (return (call $pressure (local.get $n) (f64.const 1) (f64.const 2) (f64.const 3) (f64.const 4) (f64.const 5) (f64.const 6) (f64.const 7) (f64.const 8) (f64.const 9) (f64.const 10) (f64.const 11) (f64.const 12) (f64.const 13) (f64.const 14) (f64.const 15) (f64.const 16) (f64.const 17) (f64.const 18) (f64.const 19) (f64.const 20)))))
  (call $oversized (local.get $n)))
 (func $callful (param $n i32) (result f64)
  (local $i i32) (local $j i32) (local $s f64)
  (loop $a
   (local.set $j (i32.const 0))
   (loop $b
    (block
     (local.set $s (f64.add (local.get $s) (f64.const 1)))
     (drop (call $one))) ;; A call after FP arithmetic must prevent selection.
    (br_if $b (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $a (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $s))
 (func $one (result f64) (f64.const 1))

 (func $indirect_callful (param $n i32) (result f64)
  (local $i i32) (local $j i32) (local $s f64)
  (loop $a
   (local.set $j (i32.const 0))
   (loop $b
    (local.set $s (f64.add (local.get $s) (f64.const 1)))
    (drop (call_indirect (type $one_t) (i32.const 0)))
    (br_if $b (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $a (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (local.get $s))

 ;; Pure pressure case overlaps initial Greedy and private-tier eligibility.
 (func $pressure (param $n i32) (param $v0 f64) (param $v1 f64) (param $v2 f64) (param $v3 f64) (param $v4 f64) (param $v5 f64) (param $v6 f64) (param $v7 f64) (param $v8 f64) (param $v9 f64) (param $v10 f64) (param $v11 f64) (param $v12 f64) (param $v13 f64) (param $v14 f64) (param $v15 f64) (param $v16 f64) (param $v17 f64) (param $v18 f64) (param $v19 f64) (result f64)
  (local $i i32) (local $j i32)
  (loop $a
   (local.set $j (i32.const 0))
   (loop $b
    (local.set $v0 (f64.add (local.get $v0) (f64.const 1)))
(local.set $v1 (f64.add (local.get $v1) (f64.const 1)))
(local.set $v2 (f64.add (local.get $v2) (f64.const 1)))
(local.set $v3 (f64.add (local.get $v3) (f64.const 1)))
(local.set $v4 (f64.add (local.get $v4) (f64.const 1)))
(local.set $v5 (f64.add (local.get $v5) (f64.const 1)))
(local.set $v6 (f64.add (local.get $v6) (f64.const 1)))
(local.set $v7 (f64.add (local.get $v7) (f64.const 1)))
(local.set $v8 (f64.add (local.get $v8) (f64.const 1)))
(local.set $v9 (f64.add (local.get $v9) (f64.const 1)))
(local.set $v10 (f64.add (local.get $v10) (f64.const 1)))
(local.set $v11 (f64.add (local.get $v11) (f64.const 1)))
(local.set $v12 (f64.add (local.get $v12) (f64.const 1)))
(local.set $v13 (f64.add (local.get $v13) (f64.const 1)))
(local.set $v14 (f64.add (local.get $v14) (f64.const 1)))
(local.set $v15 (f64.add (local.get $v15) (f64.const 1)))
(local.set $v16 (f64.add (local.get $v16) (f64.const 1)))
(local.set $v17 (f64.add (local.get $v17) (f64.const 1)))
(local.set $v18 (f64.add (local.get $v18) (f64.const 1)))
(local.set $v19 (f64.add (local.get $v19) (f64.const 1)))
    (br_if $b (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 1))) (local.get $n))))
   (br_if $a (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (local.get $n))))
  (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (f64.add (local.get $v0) (local.get $v1)) (local.get $v2)) (local.get $v3)) (local.get $v4)) (local.get $v5)) (local.get $v6)) (local.get $v7)) (local.get $v8)) (local.get $v9)) (local.get $v10)) (local.get $v11)) (local.get $v12)) (local.get $v13)) (local.get $v14)) (local.get $v15)) (local.get $v16)) (local.get $v17)) (local.get $v18)) (local.get $v19)))

)
