;; Basic test module without multi-value
;; This tests basic functionality

(module
  ;; Simple function to test basic functionality
  (func $simple_add (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )

  ;; Export function for testing
  (export "simple_add" (func $simple_add))
)