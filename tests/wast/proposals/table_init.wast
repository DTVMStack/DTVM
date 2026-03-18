;; Test table.init instruction

(module
  (table 10 funcref)
  (type $sig (func (result i32)))

  (func $f0 (result i32) (i32.const 0))
  (func $f1 (result i32) (i32.const 1))
  (func $f2 (result i32) (i32.const 2))

  (elem func $f0 $f1 $f2)

  (func (export "init") (param $dest i32) (param $src i32) (param $size i32)
    (table.init 0
      (local.get $dest)
      (local.get $src)
      (local.get $size))
  )

  (func (export "drop")
    (elem.drop 0)
  )

  (func (export "call_indirect") (param $idx i32) (result i32)
    (call_indirect (type $sig) (local.get $idx))
  )
)

;; Basic init from passive element segment
(invoke "init" (i32.const 0) (i32.const 0) (i32.const 3))
(assert_return (invoke "call_indirect" (i32.const 0)) (i32.const 0))
(assert_return (invoke "call_indirect" (i32.const 1)) (i32.const 1))
(assert_return (invoke "call_indirect" (i32.const 2)) (i32.const 2))

;; Partial init with offset
(invoke "init" (i32.const 5) (i32.const 1) (i32.const 2))
(assert_return (invoke "call_indirect" (i32.const 5)) (i32.const 1))
(assert_return (invoke "call_indirect" (i32.const 6)) (i32.const 2))

;; Zero-length init (should succeed)
(invoke "init" (i32.const 0) (i32.const 0) (i32.const 0))

;; Out of bounds init (source)
(assert_trap (invoke "init" (i32.const 0) (i32.const 2) (i32.const 2)) "out of bounds table access")

;; Out of bounds init (dest)
(assert_trap (invoke "init" (i32.const 9) (i32.const 0) (i32.const 2)) "out of bounds table access")

;; Drop then init should trap
(invoke "drop")
(assert_trap (invoke "init" (i32.const 0) (i32.const 0) (i32.const 1)) "out of bounds table access")

;; Zero-length init after drop with offset 0 should succeed
(invoke "init" (i32.const 0) (i32.const 0) (i32.const 0))
