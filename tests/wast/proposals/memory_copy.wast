;; Test memory.copy instruction

(module
  (memory 1)

  (func (export "copy") (param $dest i32) (param $src i32) (param $size i32)
    (memory.copy
      (local.get $dest)
      (local.get $src)
      (local.get $size))
  )

  (func (export "store8") (param $addr i32) (param $val i32)
    (i32.store8 (local.get $addr) (local.get $val))
  )

  (func (export "load8_u") (param $addr i32) (result i32)
    (i32.load8_u (local.get $addr))
  )
)

;; Setup: store some values
(invoke "store8" (i32.const 0) (i32.const 0xAA))
(invoke "store8" (i32.const 1) (i32.const 0xBB))
(invoke "store8" (i32.const 2) (i32.const 0xCC))
(invoke "store8" (i32.const 3) (i32.const 0xDD))

;; Basic copy (non-overlapping)
(invoke "copy" (i32.const 10) (i32.const 0) (i32.const 4))
(assert_return (invoke "load8_u" (i32.const 10)) (i32.const 0xAA))
(assert_return (invoke "load8_u" (i32.const 11)) (i32.const 0xBB))
(assert_return (invoke "load8_u" (i32.const 12)) (i32.const 0xCC))
(assert_return (invoke "load8_u" (i32.const 13)) (i32.const 0xDD))

;; Overlapping copy (forward: dest > src)
(invoke "copy" (i32.const 1) (i32.const 0) (i32.const 3))
(assert_return (invoke "load8_u" (i32.const 0)) (i32.const 0xAA))
(assert_return (invoke "load8_u" (i32.const 1)) (i32.const 0xAA))
(assert_return (invoke "load8_u" (i32.const 2)) (i32.const 0xBB))
(assert_return (invoke "load8_u" (i32.const 3)) (i32.const 0xCC))

;; Zero-length copy (should succeed)
(invoke "copy" (i32.const 0) (i32.const 0) (i32.const 0))

;; Zero-length copy at end of memory (should succeed)
(invoke "copy" (i32.const 65536) (i32.const 65536) (i32.const 0))

;; Out of bounds copy
(assert_trap (invoke "copy" (i32.const 65534) (i32.const 0) (i32.const 3)) "out of bounds memory access")
(assert_trap (invoke "copy" (i32.const 0) (i32.const 65534) (i32.const 3)) "out of bounds memory access")
