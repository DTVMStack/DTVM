;; Test elem.drop instruction

(module
  (table 10 funcref)
  (type $sig (func (result i32)))

  (func $f0 (result i32) (i32.const 0))
  (func $f1 (result i32) (i32.const 1))
  (func $f2 (result i32) (i32.const 2))

  (elem func $f0 $f1 $f2)

  (func (export "drop_elem")
    (elem.drop 0)
  )

  (func (export "init_elem") (param $dest i32) (param $src i32) (param $size i32)
    (table.init 0
      (local.get $dest)
      (local.get $src)
      (local.get $size))
  )
)

;; Init from passive element segment works before drop
(invoke "init_elem" (i32.const 0) (i32.const 0) (i32.const 3))

;; Drop element segment
(invoke "drop_elem")

;; Double drop should succeed
(invoke "drop_elem")

;; Init after drop should trap
(assert_trap (invoke "init_elem" (i32.const 0) (i32.const 0) (i32.const 1)) "out of bounds table access")

;; Zero-length init after drop with offset 0 should succeed
(invoke "init_elem" (i32.const 0) (i32.const 0) (i32.const 0))
