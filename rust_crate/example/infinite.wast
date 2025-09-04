;; infinite.wast - A WebAssembly module with an infinite loop function
;; This file is used for testing timeout control mechanisms

(module
  ;; Export the infinite function so it can be called from the host
  (export "infinite" (func $infinite))
  
  ;; Define the infinite loop function
  ;; This function takes no parameters and never returns
  (func $infinite
    ;; Create an infinite loop using a block and branch
    (loop $infinite_loop
      ;; Branch back to the beginning of the loop
      ;; This creates an infinite loop that will run forever
      ;; unless interrupted by the runtime
      br $infinite_loop
    )
  )
  
  ;; Optional: Export a test function that returns a value before looping
  (export "test_then_infinite" (func $test_then_infinite))
  
  ;; A function that does some work then enters infinite loop
  (func $test_then_infinite (result i32)
    ;; Return 42 first
    i32.const 42
    
    ;; Then enter infinite loop (this will never be reached due to return above)
    ;; But if we remove the return, it would loop infinitely after returning 42
    return
    
    ;; Unreachable infinite loop (commented out to avoid unreachable code)
    ;; (loop $infinite_loop
    ;;   br $infinite_loop
    ;; )
  )
  
  ;; Optional: A function with infinite loop that does some computation
  (export "infinite_with_work" (func $infinite_with_work))
  
  ;; This function does some work in each iteration of the infinite loop
  (func $infinite_with_work
    (local $counter i32)
    
    ;; Initialize counter
    i32.const 0
    local.set $counter
    
    ;; Infinite loop with some work
    (loop $work_loop
      ;; Increment counter
      local.get $counter
      i32.const 1
      i32.add
      local.set $counter
      
      ;; Do some meaningless computation to consume cycles
      local.get $counter
      local.get $counter
      i32.mul
      drop
      
      ;; Branch back to continue the loop
      br $work_loop
    )
  )
)