(assert_invalid
  (module
    (type (;0;) (func))
    (type (;1;) (func (result f32)))
    (func (;0;) (type 1) (result f32)
      unreachable
      select
      block  ;; label = @1
      end)
    (export "to_test" (func 0)))
  "load error: type mismatch expect any but got f32"
)
