(module
  (type (;0;) (func (result f64)))
  (type (;1;) (func (result i64)))
  (func (;0;) (type 0) (result f64)
    (local f64)
    i32.const 1
    if  ;; label = @1
    end
    call 1
    local.get 0
    local.set 0
    drop
    f64.const 0x0p+0 (;=0;)
    local.tee 0
    local.get 0
    i32.trunc_f64_u
    drop)
  (func (;1;) (type 1) (result i64)
    i64.const 1)
  (export "to_test" (func 0)))
(assert_return (invoke "to_test") (f64.const 0))
