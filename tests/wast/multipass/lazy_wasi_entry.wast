(module
  (func $helper (result i32) i32.const 7)
  (func (export "_start") (call $helper) drop))
(assert_return (invoke "_start"))

(module
  (func)
  (func (export "_start") (loop nop)))
(assert_return (invoke "_start"))

(module
  (func $init)
  (start $init)
  (func (export "_start")))
(assert_return (invoke "_start"))

(module
  (func)
  (func (export "_start") (result i32) i32.const 7))
(assert_return (invoke "_start") (i32.const 7))
