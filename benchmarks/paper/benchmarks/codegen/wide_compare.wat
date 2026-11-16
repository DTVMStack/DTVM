(module
 (func (export "run") (param $n i32) (result i64)
  (local $i i64) (local $a i64) (local $b i64)
  (local $h i64) (local $k i64) (local $sum i64)
  (block $done
   (loop $loop
    (br_if $done (i64.ge_u (local.get $i) (i64.extend_i32_u (local.get $n))))
    (local.set $a (i64.mul (local.get $i) (i64.const -7046029254386353131)))
    (local.set $b (i64.rotl (local.get $a) (i64.const 17)))
    (local.set $h (i64.and (local.get $i) (i64.const 31)))
    (local.set $k (i64.and (i64.shr_u (local.get $i) (i64.const 5)) (i64.const 31)))
    (local.set $sum (i64.add (local.get $sum)
     (i64.extend_i32_u
      (select
       (i64.lt_u (local.get $a) (local.get $b))
       (i64.lt_u (local.get $h) (local.get $k))
       (i64.eq (local.get $h) (local.get $k))))))
    (local.set $i (i64.add (local.get $i) (i64.const 1)))
    (br $loop)))
  (local.get $sum)))
