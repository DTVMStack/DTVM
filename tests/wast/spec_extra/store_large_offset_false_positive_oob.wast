;; Test: f64.store with offset > INT32_MAX (i.e. >= 0x80000000) on large memory
;; should NOT trap.
;;
;; When offset >= 0x80000000, x86-64 disp32 sign-extends to a negative 64-bit
;; value, causing the effective address to go before MemBase. The JIT must
;; compute the full 64-bit address explicitly to avoid this.
;;
;; Effective address = memory.size(65131) + offset(4268353288) = 4268418419
;; Memory size = 65131 * 65536 = 4268425216
;; 4268418419 + 8 <= 4268425216 => in-bounds, should NOT trap.

(module
  (memory (;0;) 65131)

  ;; dynamic base (memory.size result) + large offset: in-bounds store
  (func (export "f64_store_dynamic_base_large_offset")
    memory.size
    f64.const -5.44203
    f64.store offset=4268353288)

  ;; dynamic base via parameter + large offset: in-bounds store
  (func (export "f64_store_param_base_large_offset") (param i32)
    local.get 0
    f64.const 1.0
    f64.store offset=4268353288)

  ;; dynamic base (memory.size result) + large offset: in-bounds load
  (func (export "f64_load_dynamic_base_large_offset") (result f64)
    memory.size
    f64.load offset=4268353288)

  ;; large offset store that IS out-of-bounds must still trap
  (func (export "f64_store_large_offset_oob") (param i32)
    local.get 0
    f64.const 0.0
    f64.store offset=4294967295)
)

;; These should all succeed without trapping
(assert_return (invoke "f64_store_dynamic_base_large_offset"))
(assert_return (invoke "f64_store_param_base_large_offset" (i32.const 65131)))
(assert_return (invoke "f64_load_dynamic_base_large_offset") (f64.const 1.0))

;; Large offset that actually exceeds memory should still trap
(assert_trap (invoke "f64_store_large_offset_oob" (i32.const 65131)) "out of bounds memory access")
