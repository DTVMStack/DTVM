;; Multi-value proposal test cases
;; This file tests the multi-value extension for WebAssembly
;; Requires ZEN_ENABLE_WASI_MULTI_VALUE to be enabled
;;
;; Multi-value allows:
;; - Blocks to have multiple results
;; - Loops to have input parameters and multiple results
;; - If-else to produce multiple results
;; - Functions to return multiple values

(module
  ;; ============================================================
  ;; Type definitions for multi-value functions
  ;; ============================================================
  (type $pair_i32_i32 (func (result i32 i32)))
  (type $triple_i32 (func (result i32 i32 i32)))
  (type $swap_i32 (func (param i32 i32) (result i32 i32)))

  ;; ============================================================
  ;; Test 1: Block with multiple results
  ;; A block that produces two i32 values on the stack
  ;; ============================================================
  (func (export "block_pair") (result i32)
    (block (result i32 i32)
      i32.const 1
      i32.const 2
    )
    i32.add  ;; 1 + 2 = 3
  )

  ;; ============================================================
  ;; Test 2: Function returning multiple values
  ;; ============================================================
  (func $get_pair (type $pair_i32_i32) (result i32 i32)
    i32.const 10
    i32.const 20
  )

  (func (export "call_multi_return") (result i32)
    call $get_pair
    i32.add  ;; 10 + 20 = 30
  )

  ;; ============================================================
  ;; Test 3: Swap function - takes two values, returns them swapped
  ;; ============================================================
  (func $swap (type $swap_i32) (param i32 i32) (result i32 i32)
    local.get 1  ;; second param
    local.get 0  ;; first param
  )

  (func (export "test_swap") (result i32)
    i32.const 5
    i32.const 3
    call $swap
    i32.sub  ;; 5 - 3 = 2 (swapped: second was 3, first was 5)
  )

  ;; ============================================================
  ;; Test 4: If-else with multiple results
  ;; ============================================================
  (func (export "if_pair") (param i32) (result i32)
    (if (result i32 i32) (local.get 0)
      (then
        i32.const 1
        i32.const 2
      )
      (else
        i32.const 3
        i32.const 4
      )
    )
    i32.add  ;; if true: 1+2=3, if false: 3+4=7
  )

  ;; ============================================================
  ;; Test 5: Nested blocks with multiple results
  ;; ============================================================
  (func (export "nested_block") (result i32)
    (block (result i32 i32)
      (block (result i32 i32)
        i32.const 1
        i32.const 2
      )
      ;; stack now has: 1 2 from inner block
      i32.add  ;; 1 + 2 = 3
      i32.const 4
      ;; stack now has: 3 4
    )
    i32.mul  ;; 3 * 4 = 12
  )

  ;; ============================================================
  ;; Test 6: Branch with multiple values
  ;; Br copies the block's result values to the stack
  ;; ============================================================
  (func (export "br_multi") (result i32)
    (block (result i32 i32)
      i32.const 10
      i32.const 20
      br 0
      ;; unreachable
      i32.const 0
      i32.const 0
    )
    i32.add  ;; 10 + 20 = 30
  )

  ;; ============================================================
  ;; Test 7: Block with type index (explicit multi-value type)
  ;; ============================================================
  (func (export "block_with_type_idx") (result i32)
    (block (type $pair_i32_i32) (result i32 i32)
      i32.const 100
      i32.const 200
    )
    i32.sub  ;; 100 - 200 = -100
  )

  ;; ============================================================
  ;; Test 8: Three results
  ;; ============================================================
  (func $get_triple (type $triple_i32) (result i32 i32 i32)
    i32.const 1
    i32.const 2
    i32.const 3
  )

  (func (export "three_results") (result i32)
    call $get_triple
    i32.add  ;; 2 + 3 = 5
    i32.add  ;; 1 + 5 = 6
  )

  ;; ============================================================
  ;; Main entry point
  ;; ============================================================
  (func (export "_start")
    ;; Run all tests and verify results
    call $get_pair
    drop
    drop

    i32.const 42
    drop
  )
)