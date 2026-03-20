;; Test: store with immediate base where (uint64_t)base + offset overflows
;; 32-bit arithmetic. The effective address exceeds memory size and MUST trap.
;;
;; base(unsigned) = 0xFFDFFFFF = 4292870143, offset = 1257956348
;; Effective address = 4292870143 + 1257956348 = 5550826491
;; Memory size = 32769 * 65536 = 2147549184
;; 5550826491 + 2 > 2147549184 => out-of-bounds, MUST trap.

(module
  (memory (;0;) 32769)

  ;; const base + offset overflows 32-bit => OOB
  (func (export "i64_store16_const_base_overflow_oob")
    i32.const -2097153
    i64.const 0
    i64.store16 offset=1257956348 align=1)

  ;; dynamic base (same value via param) + offset overflows 32-bit => OOB
  (func (export "i64_store16_param_base_overflow_oob") (param i32)
    local.get 0
    i64.const 0
    i64.store16 offset=1257956348 align=1)

  ;; const base + offset overflows 32-bit for load => OOB
  (func (export "i64_load16_u_const_base_overflow_oob") (result i64)
    i32.const -2097153
    i64.load16_u offset=1257956348 align=1)
)

(assert_trap (invoke "i64_store16_const_base_overflow_oob") "out of bounds memory access")
(assert_trap (invoke "i64_store16_param_base_overflow_oob" (i32.const -2097153)) "out of bounds memory access")
(assert_trap (invoke "i64_load16_u_const_base_overflow_oob") "out of bounds memory access")
