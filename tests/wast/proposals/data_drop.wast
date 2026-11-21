;; Test data.drop instruction

(module
  (memory 1)
  (data (i32.const 0) "\01\02")  ;; active segment 0
  (data "\aa\bb\cc")             ;; passive segment 1

  (func (export "drop_passive")
    (data.drop 1)
  )

  (func (export "init_passive") (param $dest i32) (param $src i32) (param $size i32)
    (memory.init 1
      (local.get $dest)
      (local.get $src)
      (local.get $size))
  )
)

;; Init from passive segment works before drop
(invoke "init_passive" (i32.const 0) (i32.const 0) (i32.const 3))

;; Drop passive segment
(invoke "drop_passive")

;; Double drop should succeed
(invoke "drop_passive")

;; Init after drop should trap
(assert_trap (invoke "init_passive" (i32.const 0) (i32.const 0) (i32.const 1)) "out of bounds memory access")

;; Zero-length init after drop with offset 0 should succeed
(invoke "init_passive" (i32.const 0) (i32.const 0) (i32.const 0))
