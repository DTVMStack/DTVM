;; Verify the explicit prefixed-code representation and zero padding.
(module
  (import "env" "getCodeSize" (func $size (result i32)))
  (import "env" "codeCopy" (func $copy (param i32 i32 i32)))
  (import "env" "finish" (func $finish (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "call")
    (call $copy (i32.const 0) (i32.const 0) (i32.const 8))
    (i32.store (i32.const 8) (call $size))
    (call $copy (i32.const 12) (i32.const -1) (i32.const 4))
    (call $finish (i32.const 0) (i32.const 16))))
