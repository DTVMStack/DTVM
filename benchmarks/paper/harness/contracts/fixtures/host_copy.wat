(module
  (import "env" "callDataCopy" (func $copy (param i32 i32 i32)))
  (import "env" "finish" (func $finish (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\aa\aa\aa\aa\aa\aa\aa\aa")
  (func (export "call")
    (call $copy (i32.const 0) (i32.const 1) (i32.const 8))
    (call $finish (i32.const 0) (i32.const 8))))
