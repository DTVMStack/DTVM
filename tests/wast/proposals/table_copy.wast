;; Test table.copy instruction

(module
  (table 10 funcref)
  (elem (i32.const 0) $f0 $f1 $f2)
  (type $sig (func (result i32)))

  (func $f0 (result i32) (i32.const 0))
  (func $f1 (result i32) (i32.const 1))
  (func $f2 (result i32) (i32.const 2))

  (func (export "copy") (param $dest i32) (param $src i32) (param $size i32)
    (table.copy
      (local.get $dest)
      (local.get $src)
      (local.get $size))
  )

  (func (export "call_indirect") (param $idx i32) (result i32)
    (call_indirect (type $sig) (local.get $idx))
  )
)

;; Basic copy
(invoke "copy" (i32.const 3) (i32.const 0) (i32.const 3))
(assert_return (invoke "call_indirect" (i32.const 3)) (i32.const 0))
(assert_return (invoke "call_indirect" (i32.const 4)) (i32.const 1))
(assert_return (invoke "call_indirect" (i32.const 5)) (i32.const 2))

;; Overlapping copy (forward)
(invoke "copy" (i32.const 1) (i32.const 0) (i32.const 3))
(assert_return (invoke "call_indirect" (i32.const 1)) (i32.const 0))
(assert_return (invoke "call_indirect" (i32.const 2)) (i32.const 1))
(assert_return (invoke "call_indirect" (i32.const 3)) (i32.const 2))

;; Zero-length copy (should succeed)
(invoke "copy" (i32.const 0) (i32.const 0) (i32.const 0))

;; Zero-length copy at end of table (should succeed)
(invoke "copy" (i32.const 10) (i32.const 10) (i32.const 0))

;; Out of bounds copy
(assert_trap (invoke "copy" (i32.const 8) (i32.const 0) (i32.const 3)) "out of bounds table access")
(assert_trap (invoke "copy" (i32.const 0) (i32.const 8) (i32.const 3)) "out of bounds table access")
