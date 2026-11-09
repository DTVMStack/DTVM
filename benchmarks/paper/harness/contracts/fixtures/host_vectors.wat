;; Tests full-width big-endian addmod/mulmod, zero modulus and Ethereum Keccak.
(module
  (import "env" "addmod" (func $add (param i32 i32 i32 i32)))
  (import "env" "mulmod" (func $mul (param i32 i32 i32 i32)))
  (import "env" "keccak256" (func $hash (param i32 i32 i32)))
  (import "env" "finish" (func $finish (param i32 i32)))
  (memory (export "memory") 1)
  ;; max_u256, 2, max_u256 - 188
  (data (i32.const 0) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (i32.const 63) "\02")
  (data (i32.const 64) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\43")
  (func (export "call")
    (call $add (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 96))
    (call $mul (i32.const 0) (i32.const 0) (i32.const 64) (i32.const 128))
    (call $hash (i32.const 0) (i32.const 0) (i32.const 160))
    (call $mul (i32.const 0) (i32.const 0) (i32.const 224) (i32.const 192))
    (call $finish (i32.const 96) (i32.const 128))))
