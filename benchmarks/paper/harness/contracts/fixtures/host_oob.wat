(module
  (import "env" "keccak256" (func $hash (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "call") (call $hash (i32.const 65530) (i32.const 32) (i32.const 0))))
