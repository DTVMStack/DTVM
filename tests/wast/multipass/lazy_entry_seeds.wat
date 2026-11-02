;; Only $start and $entry should be compiled in the background. The direct
;; call graph and speculative indirect targets must not be prefetched.
(module
  (type $unary (func (param i32) (result i32)))
  (global $initialized (mut i32) (i32.const 0))
  (table 2 funcref)
  (elem (i32.const 0) $indirect $unused_indirect)

  ;; 0: an unexported start function must still be a background seed.
  (func $start (call $init))
  (start $start)
  ;; 1: reached only when the start function runs during instantiation.
  (func $init (global.set $initialized (i32.const 10)))
  ;; 2, 3: a nested direct-call chain.
  (func $leaf (type $unary) (param i32) (result i32)
    (i32.add (local.get 0) (i32.const 1)))
  (func $direct (type $unary) (param i32) (result i32)
    (call $leaf (local.get 0)))
  ;; 4, 5: both match call_indirect, but only the first is invoked.
  (func $indirect (type $unary) (param i32) (result i32)
    (i32.mul (local.get 0) (i32.const 2)))
  (func $unused_indirect (type $unary) (param i32) (result i32)
    (i32.add (local.get 0) (i32.const 1000)))
  ;; 6: unrelated cold body.
  (func $cold (type $unary) (param i32) (result i32)
    (i32.sub (local.get 0) (i32.const 3)))
  ;; 7: two export names must enqueue only one background task.
  (func $entry (export "entry") (export "entry_alias")
    (type $unary) (param i32) (result i32)
    (i32.add
      (global.get $initialized)
      (i32.add
        (call $direct (local.get 0))
        (call_indirect (type $unary) (local.get 0) (i32.const 0)))))
)
