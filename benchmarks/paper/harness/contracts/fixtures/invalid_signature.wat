;; A runner must reject this before calling through an undersized result buffer.
(module
  (memory (export "memory") 1)
  (func (export "call") (result i32) (i32.const 7)))
