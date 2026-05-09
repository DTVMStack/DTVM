;; Test that register tracking in copyParam works correctly.
;; This exercises the code path where multiple register parameters
;; are copied during a function call, ensuring GpRegUsed/FpRegUsed
;; tracking is not lost (regression test for side-effect inside ZEN_ASSERT).

(module
  ;; Function with many integer parameters to exercise GP register tracking
  (func $sum_i32_6 (param i32 i32 i32 i32 i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
    local.get 2
    i32.add
    local.get 3
    i32.add
    local.get 4
    i32.add
    local.get 5
    i32.add)

  ;; Function with many f64 parameters to exercise FP register tracking
  (func $sum_f64_4 (param f64 f64 f64 f64) (result f64)
    local.get 0
    local.get 1
    f64.add
    local.get 2
    f64.add
    local.get 3
    f64.add)

  ;; Caller that passes distinct values to verify correct register assignment
  (func (export "test_gp_reg_tracking") (result i32)
    i32.const 1
    i32.const 2
    i32.const 3
    i32.const 4
    i32.const 5
    i32.const 6
    call $sum_i32_6)

  (func (export "test_fp_reg_tracking") (result f64)
    f64.const 1.5
    f64.const 2.5
    f64.const 3.5
    f64.const 4.5
    call $sum_f64_4)

  ;; Mixed integer and float parameters
  (func $mixed (param i32 f64 i32 f64) (result f64)
    local.get 0
    f64.convert_i32_s
    local.get 1
    f64.add
    local.get 2
    f64.convert_i32_s
    f64.add
    local.get 3
    f64.add)

  (func (export "test_mixed_reg_tracking") (result f64)
    i32.const 10
    f64.const 20.5
    i32.const 30
    f64.const 40.5
    call $mixed)
)

(assert_return (invoke "test_gp_reg_tracking") (i32.const 21))
(assert_return (invoke "test_fp_reg_tracking") (f64.const 12.0))
(assert_return (invoke "test_mixed_reg_tracking") (f64.const 101.0))
