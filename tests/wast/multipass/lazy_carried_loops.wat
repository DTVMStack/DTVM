(module
  (memory 1)
  (func $carried (param $n i32) (result i32)
    (local $a i32) (local $b i32) (local $c i32)
    (local.set $a (i32.const 1))
    (local.set $b (i32.const 2))
    (local.set $c (i32.const 3))
    (if (local.get $n)
      (then
        (loop $next
          (local.set $a (i32.add (local.get $a) (local.get $b)))
          (local.set $b (i32.add (local.get $b) (local.get $c)))
          (local.set $c (i32.add (local.get $c) (local.get $a)))
          (br_if $next (local.tee $n (i32.sub (local.get $n) (i32.const 1)))))))
    (i32.add (i32.add (local.get $a) (local.get $b)) (local.get $c)))

  (func $temps (param $n i32) (result i32)
    (local $a i32) (local $b i32) (local $c i32)
    (loop $next
      (local.set $a (i32.add (local.get $n) (i32.const 1)))
      (local.set $b (i32.add (local.get $a) (i32.const 1)))
      (local.set $c (i32.add (local.get $b) (i32.const 1)))
      (br_if $next (local.tee $n (i32.sub (local.get $n) (i32.const 1)))))
    (i32.add (i32.add (local.get $a) (local.get $b)) (local.get $c)))

  (func $memory_loop (param $n i32) (result i32)
    (local $a i32) (local $b i32) (local $c i32)
    (local.set $a (i32.const 1))
    (local.set $b (i32.const 2))
    (local.set $c (i32.const 3))
    (loop $next
      (i32.store (i32.const 0) (local.get $a))
      (local.set $a (i32.add (local.get $a) (local.get $b)))
      (local.set $b (i32.add (local.get $b) (local.get $c)))
      (local.set $c (i32.add (local.get $c) (local.get $a)))
      (br_if $next (local.tee $n (i32.sub (local.get $n) (i32.const 1)))))
    (i32.add (i32.add (local.get $a) (local.get $b)) (local.get $c)))

  (func (export "entry") (param $arg i32) (result i32)
    (if (result i32) (i32.lt_u (local.get $arg) (i32.const 10))
      (then (call $carried (local.get $arg)))
      (else
        (if (result i32) (i32.lt_u (local.get $arg) (i32.const 20))
          (then (call $temps (i32.sub (local.get $arg) (i32.const 10))))
          (else (call $memory_loop (i32.sub (local.get $arg) (i32.const 20)))))))))
