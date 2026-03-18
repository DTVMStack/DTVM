;; Test memory.fill instruction

(module
  (memory 1)

  (func (export "fill") (param $dest i32) (param $val i32) (param $size i32)
    (memory.fill
      (local.get $dest)
      (local.get $val)
      (local.get $size))
  )

  (func (export "load8_u") (param $addr i32) (result i32)
    (i32.load8_u (local.get $addr))
  )
)

;; Basic fill
(invoke "fill" (i32.const 1) (i32.const 0xFF) (i32.const 3))
(assert_return (invoke "load8_u" (i32.const 0)) (i32.const 0))
(assert_return (invoke "load8_u" (i32.const 1)) (i32.const 0xFF))
(assert_return (invoke "load8_u" (i32.const 2)) (i32.const 0xFF))
(assert_return (invoke "load8_u" (i32.const 3)) (i32.const 0xFF))
(assert_return (invoke "load8_u" (i32.const 4)) (i32.const 0))

;; Fill value is truncated to single byte
(invoke "fill" (i32.const 0) (i32.const 0xABCD) (i32.const 2))
(assert_return (invoke "load8_u" (i32.const 0)) (i32.const 0xCD))
(assert_return (invoke "load8_u" (i32.const 1)) (i32.const 0xCD))

;; Zero-length fill (should succeed)
(invoke "fill" (i32.const 0) (i32.const 0) (i32.const 0))

;; Zero-length fill at end of memory (should succeed)
(invoke "fill" (i32.const 65536) (i32.const 0) (i32.const 0))

;; Out of bounds fill
(assert_trap (invoke "fill" (i32.const 65534) (i32.const 0) (i32.const 3)) "out of bounds memory access")

;; Way out of bounds
(assert_trap (invoke "fill" (i32.const 65537) (i32.const 0) (i32.const 1)) "out of bounds memory access")
