;; Issue #421 / disp32: memarg offset > INT32_MAX (>= 0x80000000) must not mis-address.
;; x86-64 disp32 sign-extends; the JIT must materialize the full 64-bit EA.
;;
;; This file uses 32769 pages (~2 GiB), not 65131 (~4 GiB): same bug class with lower
;; allocation pressure (see PR review on calloc / non-mmap CI).
;; memarg offset = 2147483648 (0x80000000); memory bytes = 32769 * 65536 = 2147549184.
;;
;; In-bounds (dynamic base = memory.size = 32769):
;;   EA = 32769 + 2147483648 = 2147516417; +8 <= 2147549184.
;; In-bounds (imm base 0):
;;   EA = 2147483648; +8 <= 2147549184.

(module
  (memory (;0;) 32769)

  ;; dynamic base (memory.size) + large offset
  (func (export "f64_store_dynamic_base_large_offset")
    memory.size
    f64.const -5.44203
    f64.store offset=2147483648)

  (func (export "f64_store_param_base_large_offset") (param i32)
    local.get 0
    f64.const 1.0
    f64.store offset=2147483648)

  ;; immediate base i32.const 0 + large offset (distinct codegen path under WASI)
  (func (export "f64_store_imm_base_large_offset")
    i32.const 0
    f64.const 3.0
    f64.store offset=2147483648)

  (func (export "f64_load_dynamic_base_large_offset") (result f64)
    memory.size
    f64.load offset=2147483648)

  (func (export "f64_load_imm_base_large_offset") (result f64)
    i32.const 0
    f64.load offset=2147483648)

  (func (export "f64_store_large_offset_oob") (param i32)
    local.get 0
    f64.const 0.0
    f64.store offset=4294967295)
)

(assert_return (invoke "f64_store_dynamic_base_large_offset"))
(assert_return (invoke "f64_store_param_base_large_offset" (i32.const 32769)))
(assert_return (invoke "f64_store_imm_base_large_offset"))
(assert_return (invoke "f64_load_dynamic_base_large_offset") (f64.const 1.0))
(assert_return (invoke "f64_load_imm_base_large_offset") (f64.const 3.0))

(assert_trap (invoke "f64_store_large_offset_oob" (i32.const 32769)) "out of bounds memory access")
