;; Wrap-safe add-imm LEA: i32.add(dyn, imm) becomes LEA64_32r, not x86-64
;; [zext(dyn)+imm] folded into a load/store displacement.
;; wrap32(x+C) must still be the wasm address (see also DTVMStack #626).

(module
  (memory 1)
  (data (i32.const 0) "\aa")
  (data (i32.const 16) "\bb")

  (func (export "add_wrap_value") (param i32) (result i32)
    (i32.add (local.get 0) (i32.const 0x10)))

  ;; wrap(0xfffffff0 + 0x10) = 0; load byte 0. A 64-bit disp fold would OOB.
  (func (export "wrap_add_to_zero_dyn") (param i32) (result i32)
    (i32.load8_u offset=0
      (i32.add (local.get 0) (i32.const 0x10))))

  ;; wrap(0xfffffff0 + 0x20) = 0x10; load byte 16.
  (func (export "wrap_add_to_sixteen_dyn") (param i32) (result i32)
    (i32.load8_u offset=0
      (i32.add (local.get 0) (i32.const 0x20))))

  ;; wrap(0xfffffff0+0x8)=0xfffffff8, + offset 0x10 = 0x100000008 → OOB.
  (func (export "add_imm_then_offset_oob_dyn") (param i32) (result i32)
    (i32.load offset=0x10
      (i32.add (local.get 0) (i32.const 0x8))))

  (func (export "no_wrap_add_imm") (param i32) (result i32)
    (i32.load8_u offset=4
      (i32.add (local.get 0) (i32.const 12))))
)

(assert_return (invoke "add_wrap_value" (i32.const 0xfffffff0)) (i32.const 0))
(assert_return (invoke "add_wrap_value" (i32.const 5)) (i32.const 21))
(assert_return (invoke "wrap_add_to_zero_dyn" (i32.const 0xfffffff0)) (i32.const 0xaa))
(assert_return (invoke "wrap_add_to_sixteen_dyn" (i32.const 0xfffffff0)) (i32.const 0xbb))
(assert_trap (invoke "add_imm_then_offset_oob_dyn" (i32.const 0xfffffff0)) "out of bounds memory access")
(assert_return (invoke "no_wrap_add_imm" (i32.const 0)) (i32.const 0xbb))
