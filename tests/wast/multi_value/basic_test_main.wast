;; Basic test module with main function
;; This tests basic functionality

(module
  ;; Simple function to test basic functionality
  (func $simple_add (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )

  ;; Main function
  (func (export "_start")
    i32.const 1
    i32.const 2
    call $simple_add
    drop
  )
)