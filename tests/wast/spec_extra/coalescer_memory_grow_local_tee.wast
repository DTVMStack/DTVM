(module
  (type (;0;) (func (param i32) (result i64)))
  (type (;1;) (func (result i64)))
  (func (;0;) (type 1) (result i64)
    (local i32)
    i32.const -1812402867
    memory.grow
    local.get 0
    local.set 0
    local.tee 0
    drop
    local.get 0
    i64.load32_u offset=55218920 align=1)
  (memory (;0;) 1)
  (export "to_test" (func 0)))
(assert_trap (invoke "to_test") "out of bounds memory access")
