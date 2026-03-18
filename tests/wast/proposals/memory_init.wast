;; Test memory.init instruction

(module
  (memory 1)
  (data "\aa\bb\cc\dd\ee")

  (func (export "init") (param $dest i32) (param $src i32) (param $size i32)
    (memory.init 0
      (local.get $dest)
      (local.get $src)
      (local.get $size))
  )

  (func (export "load8_u") (param $addr i32) (result i32)
    (i32.load8_u (local.get $addr))
  )
)

;; The data segment is active (format 0 with no explicit offset means passive
;; in this case since there's no offset expression). Actually this is passive
;; because there's no (i32.const X) offset.

;; Basic init from passive segment
(invoke "init" (i32.const 0) (i32.const 0) (i32.const 5))
(assert_return (invoke "load8_u" (i32.const 0)) (i32.const 0xAA))
(assert_return (invoke "load8_u" (i32.const 1)) (i32.const 0xBB))
(assert_return (invoke "load8_u" (i32.const 2)) (i32.const 0xCC))
(assert_return (invoke "load8_u" (i32.const 3)) (i32.const 0xDD))
(assert_return (invoke "load8_u" (i32.const 4)) (i32.const 0xEE))

;; Partial init with offset
(invoke "init" (i32.const 10) (i32.const 2) (i32.const 3))
(assert_return (invoke "load8_u" (i32.const 10)) (i32.const 0xCC))
(assert_return (invoke "load8_u" (i32.const 11)) (i32.const 0xDD))
(assert_return (invoke "load8_u" (i32.const 12)) (i32.const 0xEE))

;; Zero-length init (should succeed)
(invoke "init" (i32.const 0) (i32.const 0) (i32.const 0))

;; Out of bounds init (source)
(assert_trap (invoke "init" (i32.const 0) (i32.const 3) (i32.const 3)) "out of bounds memory access")

;; Out of bounds init (dest)
(assert_trap (invoke "init" (i32.const 65534) (i32.const 0) (i32.const 3)) "out of bounds memory access")
