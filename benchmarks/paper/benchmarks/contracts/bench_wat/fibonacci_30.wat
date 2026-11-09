(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32 i32)))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func))
  (type (;5;) (func (param i32) (result i32)))
  (type (;6;) (func (param i32 i64 i64 i64 i64 i64 i64 i64 i64)))
  (type (;7;) (func (param i32 i64 i64 i64 i64)))
  (import "env" "getCallDataSize" (func $getCallDataSize (type 0)))
  (import "env" "callDataCopy" (func $callDataCopy (type 1)))
  (import "env" "getCallValue" (func $getCallValue (type 2)))
  (import "env" "revert" (func $revert (type 3)))
  (import "env" "finish" (func $finish (type 3)))
  (import "env" "getCodeSize" (func $getCodeSize (type 0)))
  (import "env" "codeCopy" (func $codeCopy (type 1)))
  (func $__wasm_call_ctors (type 4))
  (func $u256_from_big_endian_bytes (type 3) (param i32 i32)
    local.get 1
    local.get 0
    i32.load8_u offset=31
    i32.store8
    local.get 1
    local.get 0
    i32.load8_u offset=30
    i32.store8 offset=1
    local.get 1
    local.get 0
    i32.load8_u offset=29
    i32.store8 offset=2
    local.get 1
    local.get 0
    i32.load8_u offset=28
    i32.store8 offset=3
    local.get 1
    local.get 0
    i32.load8_u offset=27
    i32.store8 offset=4
    local.get 1
    local.get 0
    i32.load8_u offset=26
    i32.store8 offset=5
    local.get 1
    local.get 0
    i32.load8_u offset=25
    i32.store8 offset=6
    local.get 1
    local.get 0
    i32.load8_u offset=24
    i32.store8 offset=7
    local.get 1
    local.get 0
    i32.load8_u offset=23
    i32.store8 offset=8
    local.get 1
    local.get 0
    i32.load8_u offset=22
    i32.store8 offset=9
    local.get 1
    local.get 0
    i32.load8_u offset=21
    i32.store8 offset=10
    local.get 1
    local.get 0
    i32.load8_u offset=20
    i32.store8 offset=11
    local.get 1
    local.get 0
    i32.load8_u offset=19
    i32.store8 offset=12
    local.get 1
    local.get 0
    i32.load8_u offset=18
    i32.store8 offset=13
    local.get 1
    local.get 0
    i32.load8_u offset=17
    i32.store8 offset=14
    local.get 1
    local.get 0
    i32.load8_u offset=16
    i32.store8 offset=15
    local.get 1
    local.get 0
    i32.load8_u offset=15
    i32.store8 offset=16
    local.get 1
    local.get 0
    i32.load8_u offset=14
    i32.store8 offset=17
    local.get 1
    local.get 0
    i32.load8_u offset=13
    i32.store8 offset=18
    local.get 1
    local.get 0
    i32.load8_u offset=12
    i32.store8 offset=19
    local.get 1
    local.get 0
    i32.load8_u offset=11
    i32.store8 offset=20
    local.get 1
    local.get 0
    i32.load8_u offset=10
    i32.store8 offset=21
    local.get 1
    local.get 0
    i32.load8_u offset=9
    i32.store8 offset=22
    local.get 1
    local.get 0
    i32.load8_u offset=8
    i32.store8 offset=23
    local.get 1
    local.get 0
    i32.load8_u offset=7
    i32.store8 offset=24
    local.get 1
    local.get 0
    i32.load8_u offset=6
    i32.store8 offset=25
    local.get 1
    local.get 0
    i32.load8_u offset=5
    i32.store8 offset=26
    local.get 1
    local.get 0
    i32.load8_u offset=4
    i32.store8 offset=27
    local.get 1
    local.get 0
    i32.load8_u offset=3
    i32.store8 offset=28
    local.get 1
    local.get 0
    i32.load8_u offset=2
    i32.store8 offset=29
    local.get 1
    local.get 0
    i32.load8_u offset=1
    i32.store8 offset=30
    local.get 1
    local.get 0
    i32.load8_u
    i32.store8 offset=31)
  (func $i32_from_big_endian_bytes32 (type 5) (param i32) (result i32)
    local.get 0
    i32.load offset=28 align=1
    local.tee 0
    i32.const 24
    i32.shl
    local.get 0
    i32.const 65280
    i32.and
    i32.const 8
    i32.shl
    i32.or
    local.get 0
    i32.const 8
    i32.shr_u
    i32.const 65280
    i32.and
    local.get 0
    i32.const 24
    i32.shr_u
    i32.or
    i32.or)
  (func $wrapper_calldataload_bytes32 (type 3) (param i32 i32)
    (local i32 i32 i32 i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=65536
      local.tee 2
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 2
      i32.store offset=65536
    end
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.const 32
            i32.add
            local.get 2
            i32.le_u
            br_if 0 (;@4;)
            local.get 2
            local.set 3
            block  ;; label = @5
              local.get 2
              i32.const -1
              i32.gt_s
              br_if 0 (;@5;)
              i32.const 0
              call $getCallDataSize
              local.tee 3
              i32.store offset=65536
            end
            local.get 2
            local.get 0
            i32.sub
            local.set 4
            block  ;; label = @5
              local.get 3
              i32.const 101
              i32.lt_s
              br_if 0 (;@5;)
              local.get 1
              local.get 0
              local.get 4
              call $callDataCopy
              br 2 (;@3;)
            end
            block  ;; label = @5
              i32.const 0
              i32.load8_u offset=65668
              br_if 0 (;@5;)
              i32.const 65568
              i32.const 0
              local.get 3
              call $callDataCopy
              i32.const 0
              i32.const 1
              i32.store8 offset=65668
            end
            local.get 4
            i32.eqz
            br_if 2 (;@2;)
            local.get 0
            i32.const 65568
            i32.add
            local.set 3
            block  ;; label = @5
              block  ;; label = @6
                local.get 4
                i32.const 7
                i32.and
                local.tee 5
                br_if 0 (;@6;)
                local.get 4
                local.set 5
                local.get 1
                local.set 6
                br 1 (;@5;)
              end
              local.get 1
              local.set 6
              loop  ;; label = @6
                local.get 6
                local.get 3
                i32.load8_u
                i32.store8
                local.get 6
                i32.const 1
                i32.add
                local.set 6
                local.get 3
                i32.const 1
                i32.add
                local.set 3
                local.get 5
                i32.const -1
                i32.add
                local.tee 5
                br_if 0 (;@6;)
              end
              local.get 4
              i32.const -8
              i32.and
              local.set 5
            end
            local.get 4
            i32.const 8
            i32.lt_u
            br_if 2 (;@2;)
            local.get 5
            i32.const -8
            i32.add
            local.set 5
            loop  ;; label = @5
              local.get 6
              local.get 3
              i32.load8_u
              i32.store8
              local.get 6
              local.get 3
              i32.load8_u offset=1
              i32.store8 offset=1
              local.get 6
              local.get 3
              i32.load8_u offset=2
              i32.store8 offset=2
              local.get 6
              local.get 3
              i32.load8_u offset=3
              i32.store8 offset=3
              local.get 6
              local.get 3
              i32.load8_u offset=4
              i32.store8 offset=4
              local.get 6
              local.get 3
              i32.load8_u offset=5
              i32.store8 offset=5
              local.get 6
              local.get 3
              i32.load8_u offset=6
              i32.store8 offset=6
              local.get 6
              local.get 3
              i32.load8_u offset=7
              i32.store8 offset=7
              local.get 5
              i32.eqz
              br_if 2 (;@3;)
              local.get 5
              i32.const -8
              i32.add
              local.set 5
              local.get 3
              i32.const 8
              i32.add
              local.set 3
              local.get 6
              i32.const 8
              i32.add
              local.set 6
              br 0 (;@5;)
            end
          end
          block  ;; label = @4
            local.get 2
            i32.const -1
            i32.gt_s
            br_if 0 (;@4;)
            i32.const 0
            call $getCallDataSize
            local.tee 2
            i32.store offset=65536
          end
          block  ;; label = @4
            local.get 2
            i32.const 101
            i32.lt_s
            br_if 0 (;@4;)
            local.get 1
            local.get 0
            i32.const 32
            call $callDataCopy
            return
          end
          block  ;; label = @4
            i32.const 0
            i32.load8_u offset=65668
            br_if 0 (;@4;)
            i32.const 65568
            i32.const 0
            local.get 2
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=65668
          end
          local.get 1
          local.get 0
          i32.const 65568
          i32.add
          i32.load8_u
          i32.store8
          local.get 1
          local.get 0
          i32.const 65569
          i32.add
          i32.load8_u
          i32.store8 offset=1
          local.get 1
          local.get 0
          i32.const 65570
          i32.add
          i32.load8_u
          i32.store8 offset=2
          local.get 1
          local.get 0
          i32.const 65571
          i32.add
          i32.load8_u
          i32.store8 offset=3
          local.get 1
          local.get 0
          i32.const 65572
          i32.add
          i32.load8_u
          i32.store8 offset=4
          local.get 1
          local.get 0
          i32.const 65573
          i32.add
          i32.load8_u
          i32.store8 offset=5
          local.get 1
          local.get 0
          i32.const 65574
          i32.add
          i32.load8_u
          i32.store8 offset=6
          local.get 1
          local.get 0
          i32.const 65575
          i32.add
          i32.load8_u
          i32.store8 offset=7
          local.get 1
          local.get 0
          i32.const 65576
          i32.add
          i32.load8_u
          i32.store8 offset=8
          local.get 1
          local.get 0
          i32.const 65577
          i32.add
          i32.load8_u
          i32.store8 offset=9
          local.get 1
          local.get 0
          i32.const 65578
          i32.add
          i32.load8_u
          i32.store8 offset=10
          local.get 1
          local.get 0
          i32.const 65579
          i32.add
          i32.load8_u
          i32.store8 offset=11
          local.get 1
          local.get 0
          i32.const 65580
          i32.add
          i32.load8_u
          i32.store8 offset=12
          local.get 1
          local.get 0
          i32.const 65581
          i32.add
          i32.load8_u
          i32.store8 offset=13
          local.get 1
          local.get 0
          i32.const 65582
          i32.add
          i32.load8_u
          i32.store8 offset=14
          local.get 1
          local.get 0
          i32.const 65583
          i32.add
          i32.load8_u
          i32.store8 offset=15
          local.get 1
          local.get 0
          i32.const 65584
          i32.add
          i32.load8_u
          i32.store8 offset=16
          local.get 1
          local.get 0
          i32.const 65585
          i32.add
          i32.load8_u
          i32.store8 offset=17
          local.get 1
          local.get 0
          i32.const 65586
          i32.add
          i32.load8_u
          i32.store8 offset=18
          local.get 1
          local.get 0
          i32.const 65587
          i32.add
          i32.load8_u
          i32.store8 offset=19
          local.get 1
          local.get 0
          i32.const 65588
          i32.add
          i32.load8_u
          i32.store8 offset=20
          local.get 1
          local.get 0
          i32.const 65589
          i32.add
          i32.load8_u
          i32.store8 offset=21
          local.get 1
          local.get 0
          i32.const 65590
          i32.add
          i32.load8_u
          i32.store8 offset=22
          local.get 1
          local.get 0
          i32.const 65591
          i32.add
          i32.load8_u
          i32.store8 offset=23
          local.get 1
          local.get 0
          i32.const 65592
          i32.add
          i32.load8_u
          i32.store8 offset=24
          local.get 1
          local.get 0
          i32.const 65593
          i32.add
          i32.load8_u
          i32.store8 offset=25
          local.get 1
          local.get 0
          i32.const 65594
          i32.add
          i32.load8_u
          i32.store8 offset=26
          local.get 1
          local.get 0
          i32.const 65595
          i32.add
          i32.load8_u
          i32.store8 offset=27
          local.get 1
          local.get 0
          i32.const 65596
          i32.add
          i32.load8_u
          i32.store8 offset=28
          local.get 1
          local.get 0
          i32.const 65597
          i32.add
          i32.load8_u
          i32.store8 offset=29
          local.get 1
          local.get 0
          i32.const 65598
          i32.add
          i32.load8_u
          i32.store8 offset=30
          local.get 1
          local.get 0
          i32.const 65599
          i32.add
          i32.load8_u
          i32.store8 offset=31
          br 2 (;@1;)
        end
        local.get 4
        i32.const 31
        i32.gt_s
        br_if 1 (;@1;)
      end
      local.get 0
      local.get 2
      i32.sub
      local.tee 3
      i32.const 31
      i32.add
      local.set 6
      block  ;; label = @2
        local.get 3
        i32.const 7
        i32.and
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        loop  ;; label = @3
          local.get 1
          local.get 4
          i32.add
          i32.const 0
          i32.store8
          local.get 4
          i32.const 1
          i32.add
          local.set 4
          local.get 3
          i32.const -1
          i32.add
          local.tee 3
          br_if 0 (;@3;)
        end
      end
      local.get 6
      i32.const 7
      i32.lt_u
      br_if 0 (;@1;)
      i32.const 24
      local.get 4
      i32.sub
      local.tee 6
      i32.const 3
      i32.shr_u
      local.set 0
      block  ;; label = @2
        local.get 6
        i32.const 216
        i32.lt_u
        br_if 0 (;@2;)
        local.get 1
        local.get 4
        i32.add
        local.tee 3
        local.get 6
        i32.const -8
        i32.and
        local.tee 6
        i32.add
        local.get 3
        i32.lt_u
        br_if 0 (;@2;)
        local.get 3
        i32.const 1
        i32.add
        local.tee 5
        local.get 6
        i32.add
        local.get 5
        i32.lt_u
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.add
        local.tee 5
        local.get 6
        i32.add
        local.get 5
        i32.lt_u
        br_if 0 (;@2;)
        local.get 3
        i32.const 3
        i32.add
        local.tee 5
        local.get 6
        i32.add
        local.get 5
        i32.lt_u
        br_if 0 (;@2;)
        local.get 3
        i32.const 4
        i32.add
        local.tee 5
        local.get 6
        i32.add
        local.get 5
        i32.lt_u
        br_if 0 (;@2;)
        local.get 3
        i32.const 5
        i32.add
        local.tee 5
        local.get 6
        i32.add
        local.get 5
        i32.lt_u
        br_if 0 (;@2;)
        local.get 3
        i32.const 6
        i32.add
        local.tee 5
        local.get 6
        i32.add
        local.get 5
        i32.lt_u
        br_if 0 (;@2;)
        local.get 3
        i32.const 7
        i32.add
        local.tee 5
        local.get 6
        i32.add
        local.get 5
        i32.lt_u
        br_if 0 (;@2;)
        local.get 0
        i32.const 1
        i32.add
        local.tee 5
        i32.const 1073741820
        i32.and
        local.tee 0
        i32.const -4
        i32.add
        local.set 6
        local.get 3
        i32.const 15
        i32.add
        local.set 3
        block  ;; label = @3
          loop  ;; label = @4
            local.get 3
            i32.const -15
            i32.add
            i32.const 0
            i32.store16 align=1
            local.get 3
            i32.const -13
            i32.add
            i32.const 0
            i32.store8
            local.get 3
            i32.const 10
            i32.add
            i32.const 0
            i32.store align=1
            local.get 3
            i32.const 14
            i32.add
            i32.const 0
            i32.store16 align=1
            local.get 3
            i32.const -12
            i32.add
            i32.const 0
            i32.store align=1
            local.get 3
            i32.const -8
            i32.add
            i32.const 0
            i32.store16 align=1
            local.get 3
            i32.const -6
            i32.add
            i64.const 0
            i64.store align=1
            local.get 3
            i32.const 2
            i32.add
            i64.const 0
            i64.store align=1
            local.get 3
            i32.const 16
            i32.add
            i32.const 0
            i32.store8
            local.get 6
            i32.eqz
            br_if 1 (;@3;)
            local.get 6
            i32.const -4
            i32.add
            local.set 6
            local.get 3
            i32.const 32
            i32.add
            local.set 3
            br 0 (;@4;)
          end
        end
        local.get 5
        local.get 0
        i32.eq
        br_if 1 (;@1;)
        i32.const 24
        local.get 0
        i32.const 3
        i32.shl
        local.get 4
        i32.add
        local.tee 4
        i32.sub
        i32.const 3
        i32.shr_u
        local.set 0
      end
      local.get 1
      local.get 4
      i32.add
      local.set 3
      local.get 0
      i32.const 3
      i32.shl
      i32.const 8
      i32.add
      local.set 6
      loop  ;; label = @2
        local.get 3
        i32.const 0
        i32.store8
        local.get 3
        i32.const 1
        i32.add
        local.set 3
        local.get 6
        i32.const -1
        i32.add
        local.tee 6
        br_if 0 (;@2;)
      end
    end)
  (func $wrapper_calldata_load_selector (type 0) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    i32.const 0
    local.set 1
    block  ;; label = @1
      i32.const 0
      i32.load offset=65536
      local.tee 2
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 2
      i32.store offset=65536
    end
    block  ;; label = @1
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 2
        i32.const 3
        i32.gt_u
        br_if 0 (;@2;)
        i32.const 0
        local.set 3
        local.get 0
        i32.const 0
        i32.store offset=12
        block  ;; label = @3
          i32.const 0
          i32.load8_u offset=65668
          br_if 0 (;@3;)
          i32.const 65568
          i32.const 0
          local.get 2
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=65668
        end
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.const 4
              i32.ge_u
              br_if 0 (;@5;)
              i32.const 65568
              local.set 1
              local.get 0
              i32.const 12
              i32.add
              local.set 4
              br 1 (;@4;)
            end
            local.get 2
            i32.const -4
            i32.and
            local.tee 3
            i32.const 65568
            i32.add
            local.set 1
            local.get 0
            i32.const 12
            i32.add
            local.get 3
            i32.add
            local.set 4
            i32.const 0
            local.set 5
            loop  ;; label = @5
              local.get 0
              i32.const 12
              i32.add
              local.get 5
              i32.add
              local.get 5
              i32.const 65568
              i32.add
              i32.load
              i32.store
              local.get 3
              local.get 5
              i32.const 4
              i32.add
              local.tee 5
              i32.ne
              br_if 0 (;@5;)
            end
            local.get 2
            local.get 3
            i32.eq
            br_if 1 (;@3;)
          end
          local.get 2
          local.get 3
          i32.sub
          local.set 5
          loop  ;; label = @4
            local.get 4
            local.get 1
            i32.load8_u
            i32.store8
            local.get 4
            i32.const 1
            i32.add
            local.set 4
            local.get 1
            i32.const 1
            i32.add
            local.set 1
            local.get 5
            i32.const -1
            i32.add
            local.tee 5
            br_if 0 (;@4;)
          end
        end
        block  ;; label = @3
          local.get 2
          i32.const 8
          i32.lt_u
          br_if 0 (;@3;)
          local.get 2
          i32.const -8
          i32.and
          local.set 6
          block  ;; label = @4
            local.get 2
            i32.const -8
            i32.add
            local.tee 5
            i32.const 32
            i32.lt_u
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 4
              local.get 1
              local.get 2
              i32.const -8
              i32.and
              local.tee 3
              i32.add
              i32.ge_u
              br_if 0 (;@5;)
              local.get 1
              local.get 4
              local.get 3
              i32.add
              i32.lt_u
              br_if 1 (;@4;)
            end
            local.get 1
            local.get 5
            i32.const 3
            i32.shr_u
            i32.const 1
            i32.add
            local.tee 5
            local.get 5
            i32.const 3
            i32.and
            local.tee 5
            i32.const 4
            local.get 5
            select
            i32.sub
            local.tee 7
            i32.const 3
            i32.shl
            local.tee 5
            i32.add
            local.set 8
            local.get 4
            local.get 5
            i32.add
            local.set 9
            local.get 6
            local.get 5
            i32.sub
            local.set 6
            i32.const 0
            local.set 2
            loop  ;; label = @5
              local.get 4
              local.get 2
              i32.add
              local.tee 5
              local.get 1
              local.get 2
              i32.add
              local.tee 3
              i32.load16_u align=1
              i32.store16 align=1
              local.get 5
              i32.const 24
              i32.add
              local.get 3
              i32.const 24
              i32.add
              i32.load16_u align=1
              i32.store16 align=1
              local.get 5
              i32.const 16
              i32.add
              local.get 3
              i32.const 16
              i32.add
              i32.load16_u align=1
              i32.store16 align=1
              local.get 5
              i32.const 8
              i32.add
              local.get 3
              i32.const 8
              i32.add
              i32.load16_u align=1
              i32.store16 align=1
              local.get 5
              i32.const 26
              i32.add
              local.get 3
              i32.const 26
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 18
              i32.add
              local.get 3
              i32.const 18
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 10
              i32.add
              local.get 3
              i32.const 10
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 2
              i32.add
              local.get 3
              i32.const 2
              i32.add
              i32.load8_u
              i32.store8
              local.get 3
              i32.const 3
              i32.add
              i32.load8_u
              local.set 10
              local.get 3
              i32.const 11
              i32.add
              i32.load8_u
              local.set 11
              local.get 3
              i32.const 19
              i32.add
              i32.load8_u
              local.set 12
              local.get 5
              i32.const 27
              i32.add
              local.get 3
              i32.const 27
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 19
              i32.add
              local.get 12
              i32.store8
              local.get 5
              i32.const 11
              i32.add
              local.get 11
              i32.store8
              local.get 5
              i32.const 3
              i32.add
              local.get 10
              i32.store8
              local.get 5
              i32.const 28
              i32.add
              local.get 3
              i32.const 28
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 20
              i32.add
              local.get 3
              i32.const 20
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 12
              i32.add
              local.get 3
              i32.const 12
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 4
              i32.add
              local.get 3
              i32.const 4
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 5
              i32.add
              local.get 3
              i32.const 5
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 13
              i32.add
              local.get 3
              i32.const 13
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 21
              i32.add
              local.get 3
              i32.const 21
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 29
              i32.add
              local.get 3
              i32.const 29
              i32.add
              i32.load8_u
              i32.store8
              local.get 5
              i32.const 30
              i32.add
              local.get 3
              i32.const 30
              i32.add
              i32.load16_u align=1
              i32.store16 align=1
              local.get 5
              i32.const 22
              i32.add
              local.get 3
              i32.const 22
              i32.add
              i32.load16_u align=1
              i32.store16 align=1
              local.get 5
              i32.const 14
              i32.add
              local.get 3
              i32.const 14
              i32.add
              i32.load16_u align=1
              i32.store16 align=1
              local.get 5
              i32.const 6
              i32.add
              local.get 3
              i32.const 6
              i32.add
              i32.load16_u align=1
              i32.store16 align=1
              local.get 2
              i32.const 32
              i32.add
              local.set 2
              local.get 7
              i32.const -4
              i32.add
              local.tee 7
              br_if 0 (;@5;)
            end
            local.get 9
            local.set 4
            local.get 8
            local.set 1
          end
          local.get 6
          i32.const -8
          i32.add
          local.set 5
          loop  ;; label = @4
            local.get 4
            local.get 1
            i64.load align=1
            i64.store align=1
            local.get 5
            i32.eqz
            br_if 1 (;@3;)
            local.get 5
            i32.const -8
            i32.add
            local.set 5
            local.get 1
            i32.const 8
            i32.add
            local.set 1
            local.get 4
            i32.const 8
            i32.add
            local.set 4
            br 0 (;@4;)
          end
        end
        local.get 0
        i32.load offset=12
        local.tee 1
        i32.const 24
        i32.shl
        local.get 1
        i32.const 65280
        i32.and
        i32.const 8
        i32.shl
        i32.or
        local.get 1
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 1
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        local.set 1
        br 1 (;@1;)
      end
      local.get 0
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 2
        i32.const -1
        i32.gt_s
        br_if 0 (;@2;)
        i32.const 0
        call $getCallDataSize
        local.tee 2
        i32.store offset=65536
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.const 101
          i32.lt_s
          br_if 0 (;@3;)
          local.get 0
          i32.const 8
          i32.add
          i32.const 0
          i32.const 4
          call $callDataCopy
          br 1 (;@2;)
        end
        block  ;; label = @3
          i32.const 0
          i32.load8_u offset=65668
          br_if 0 (;@3;)
          i32.const 65568
          i32.const 0
          local.get 2
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=65668
        end
        local.get 0
        i32.const 0
        i32.load offset=65568
        i32.store offset=8
      end
      local.get 0
      i32.load offset=8
      local.tee 1
      i32.const 24
      i32.shl
      local.get 1
      i32.const 65280
      i32.and
      i32.const 8
      i32.shl
      i32.or
      local.get 1
      i32.const 8
      i32.shr_u
      i32.const 65280
      i32.and
      local.get 1
      i32.const 24
      i32.shr_u
      i32.or
      i32.or
      local.set 1
    end
    local.get 0
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $wrapper_calldata_size (type 0) (result i32)
    (local i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=65536
      local.tee 0
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 0
      i32.store offset=65536
    end
    local.get 0)
  (func $wrapper_callvalue_not_zero (type 0) (result i32)
    (local i32 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    call $getCallValue
    local.get 0
    i64.load offset=8
    local.set 1
    local.get 0
    i64.load
    local.set 2
    local.get 0
    i64.load offset=16
    local.set 3
    local.get 0
    i64.load offset=24
    local.set 4
    local.get 0
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 4
    local.get 3
    local.get 2
    local.get 1
    i64.or
    i64.or
    i64.or
    i64.const 0
    i64.ne)
  (func $wrapper_revert (type 3) (param i32 i32)
    i32.const 0
    i32.load offset=65676
    local.get 0
    i32.add
    local.get 1
    call $revert)
  (func $evm_get_memory_addr (type 5) (param i32) (result i32)
    i32.const 0
    i32.load offset=65676
    local.get 0
    i32.add)
  (func $wrapper_codecopy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=65688
        local.tee 3
        local.get 2
        local.get 0
        i32.add
        local.tee 4
        i32.ge_u
        br_if 0 (;@2;)
        local.get 4
        i32.const 65535
        i32.add
        local.tee 5
        i32.const 16
        i32.shr_u
        local.get 3
        i32.const 16
        i32.shr_u
        i32.sub
        local.tee 3
        memory.grow
        drop
        i32.const 0
        local.get 4
        i32.store offset=65684
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=65688
        i32.const 0
        i32.const 0
        i32.load offset=65680
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=65680
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=65684
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=65684
    end
    i32.const 0
    i32.load offset=65676
    local.tee 4
    local.get 0
    i32.add
    local.set 0
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.const -1
        i32.gt_s
        br_if 0 (;@2;)
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        local.get 1
        i32.add
        local.set 1
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i32.const 7
            i32.and
            local.tee 4
            br_if 0 (;@4;)
            local.get 2
            local.set 4
            br 1 (;@3;)
          end
          loop  ;; label = @4
            local.get 0
            local.get 1
            i32.load8_u
            i32.store8
            local.get 0
            i32.const 1
            i32.add
            local.set 0
            local.get 1
            i32.const 1
            i32.add
            local.set 1
            local.get 4
            i32.const -1
            i32.add
            local.tee 4
            br_if 0 (;@4;)
          end
          local.get 2
          i32.const -8
          i32.and
          local.set 4
        end
        local.get 2
        i32.const 8
        i32.lt_u
        br_if 1 (;@1;)
        local.get 4
        i32.const -8
        i32.add
        local.set 4
        loop  ;; label = @3
          local.get 0
          local.get 1
          i32.load8_u
          i32.store8
          local.get 0
          local.get 1
          i32.load8_u offset=1
          i32.store8 offset=1
          local.get 0
          local.get 1
          i32.load8_u offset=2
          i32.store8 offset=2
          local.get 0
          local.get 1
          i32.load8_u offset=3
          i32.store8 offset=3
          local.get 0
          local.get 1
          i32.load8_u offset=4
          i32.store8 offset=4
          local.get 0
          local.get 1
          i32.load8_u offset=5
          i32.store8 offset=5
          local.get 0
          local.get 1
          i32.load8_u offset=6
          i32.store8 offset=6
          local.get 0
          local.get 1
          i32.load8_u offset=7
          i32.store8 offset=7
          local.get 4
          i32.eqz
          br_if 2 (;@1;)
          local.get 4
          i32.const -8
          i32.add
          local.set 4
          local.get 1
          i32.const 8
          i32.add
          local.set 1
          local.get 0
          i32.const 8
          i32.add
          local.set 0
          br 0 (;@3;)
        end
      end
      block  ;; label = @2
        local.get 2
        local.get 1
        i32.add
        call $getCodeSize
        local.tee 4
        i32.ge_u
        br_if 0 (;@2;)
        local.get 0
        local.get 1
        local.get 2
        call $codeCopy
        return
      end
      block  ;; label = @2
        local.get 4
        i32.const 0
        i32.gt_s
        local.get 1
        local.get 4
        i32.sub
        local.tee 4
        local.get 1
        i32.lt_s
        i32.ne
        br_if 0 (;@2;)
        block  ;; label = @3
          i32.const 0
          i32.load offset=65536
          local.tee 1
          i32.const -1
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 0
          call $getCallDataSize
          local.tee 1
          i32.store offset=65536
          local.get 1
          i32.const -1
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 0
          call $getCallDataSize
          local.tee 1
          i32.store offset=65536
        end
        block  ;; label = @3
          local.get 1
          i32.const 101
          i32.lt_s
          br_if 0 (;@3;)
          local.get 0
          local.get 4
          local.get 2
          call $callDataCopy
          br 2 (;@1;)
        end
        block  ;; label = @3
          i32.const 0
          i32.load8_u offset=65668
          br_if 0 (;@3;)
          i32.const 65568
          i32.const 0
          local.get 1
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=65668
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.const 65568
        i32.add
        local.set 1
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i32.const 7
            i32.and
            local.tee 4
            br_if 0 (;@4;)
            local.get 2
            local.set 4
            br 1 (;@3;)
          end
          loop  ;; label = @4
            local.get 0
            local.get 1
            i32.load8_u
            i32.store8
            local.get 0
            i32.const 1
            i32.add
            local.set 0
            local.get 1
            i32.const 1
            i32.add
            local.set 1
            local.get 4
            i32.const -1
            i32.add
            local.tee 4
            br_if 0 (;@4;)
          end
          local.get 2
          i32.const -8
          i32.and
          local.set 4
        end
        local.get 2
        i32.const 8
        i32.lt_u
        br_if 1 (;@1;)
        local.get 4
        i32.const -8
        i32.add
        local.set 4
        loop  ;; label = @3
          local.get 0
          local.get 1
          i32.load8_u
          i32.store8
          local.get 0
          local.get 1
          i32.load8_u offset=1
          i32.store8 offset=1
          local.get 0
          local.get 1
          i32.load8_u offset=2
          i32.store8 offset=2
          local.get 0
          local.get 1
          i32.load8_u offset=3
          i32.store8 offset=3
          local.get 0
          local.get 1
          i32.load8_u offset=4
          i32.store8 offset=4
          local.get 0
          local.get 1
          i32.load8_u offset=5
          i32.store8 offset=5
          local.get 0
          local.get 1
          i32.load8_u offset=6
          i32.store8 offset=6
          local.get 0
          local.get 1
          i32.load8_u offset=7
          i32.store8 offset=7
          local.get 4
          i32.eqz
          br_if 2 (;@1;)
          local.get 4
          i32.const -8
          i32.add
          local.set 4
          local.get 1
          i32.const 8
          i32.add
          local.set 1
          local.get 0
          i32.const 8
          i32.add
          local.set 0
          br 0 (;@3;)
        end
      end
      unreachable
      unreachable
    end)
  (func $wrapper_memory_guard (type 5) (param i32) (result i32)
    (local i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=65688
      local.tee 1
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      local.get 0
      i32.const 65535
      i32.add
      local.tee 2
      i32.const 16
      i32.shr_u
      local.get 1
      i32.const 16
      i32.shr_u
      i32.sub
      local.tee 1
      memory.grow
      drop
      i32.const 0
      local.get 0
      i32.store offset=65684
      i32.const 0
      local.get 2
      i32.const -65536
      i32.and
      i32.store offset=65688
      i32.const 0
      i32.const 0
      i32.load offset=65680
      local.get 1
      i32.const 16
      i32.shl
      i32.add
      i32.store offset=65680
      i32.const 96
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=65684
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 0
      i32.store offset=65684
    end
    i32.const 96)
  (func $wrapper_mstore_u256 (type 3) (param i32 i32)
    (local i32 i64 i64 i64 i64 i32)
    block  ;; label = @1
      local.get 0
      i32.const 32
      i32.add
      local.tee 2
      local.get 0
      i32.lt_s
      br_if 0 (;@1;)
      local.get 1
      i32.const 24
      i32.add
      i64.load
      local.set 3
      local.get 1
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 1
      i32.const 8
      i32.add
      i64.load
      local.set 5
      local.get 1
      i64.load
      local.set 6
      block  ;; label = @2
        block  ;; label = @3
          i32.const 0
          i32.load offset=65688
          local.tee 1
          local.get 2
          i32.ge_u
          br_if 0 (;@3;)
          local.get 2
          i32.const 65535
          i32.add
          local.tee 7
          i32.const 16
          i32.shr_u
          local.get 1
          i32.const 16
          i32.shr_u
          i32.sub
          local.tee 1
          memory.grow
          drop
          i32.const 0
          local.get 2
          i32.store offset=65684
          i32.const 0
          local.get 7
          i32.const -65536
          i32.and
          i32.store offset=65688
          i32.const 0
          i32.const 0
          i32.load offset=65680
          local.get 1
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65680
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65684
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65684
      end
      i32.const 0
      i32.load offset=65676
      local.get 0
      i32.add
      local.tee 1
      local.get 5
      i64.const 40
      i64.shr_u
      i64.store8 offset=18
      local.get 1
      local.get 5
      i64.const 56
      i64.shr_u
      i64.store8 offset=16
      local.get 1
      local.get 4
      i64.store8 offset=15
      local.get 1
      local.get 4
      i64.const 40
      i64.shr_u
      i64.store8 offset=10
      local.get 1
      local.get 4
      i64.const 56
      i64.shr_u
      i64.store8 offset=8
      local.get 1
      local.get 3
      i64.store8 offset=7
      local.get 1
      local.get 5
      i32.wrap_i64
      local.tee 0
      i32.const 8
      i32.shr_u
      i32.store8 offset=22
      local.get 1
      local.get 0
      i32.const 24
      i32.shr_u
      i32.store8 offset=20
      local.get 1
      local.get 4
      i64.const 32
      i64.shr_u
      i64.store8 offset=11
      local.get 1
      local.get 4
      i64.const 48
      i64.shr_u
      i64.store8 offset=9
      local.get 1
      local.get 3
      i64.const 40
      i64.shr_u
      i64.store8 offset=2
      local.get 1
      local.get 3
      i64.const 56
      i64.shr_u
      i64.store8
      local.get 1
      local.get 4
      i32.wrap_i64
      local.tee 2
      i32.const 8
      i32.shr_u
      i32.store8 offset=14
      local.get 1
      local.get 2
      i32.const 24
      i32.shr_u
      i32.store8 offset=12
      local.get 1
      local.get 3
      i64.const 32
      i64.shr_u
      i64.store8 offset=3
      local.get 1
      local.get 3
      i64.const 48
      i64.shr_u
      i64.store8 offset=1
      local.get 1
      local.get 2
      i32.const 16
      i32.shr_u
      i32.store8 offset=13
      local.get 1
      local.get 3
      i32.wrap_i64
      local.tee 2
      i32.const 8
      i32.shr_u
      i32.store8 offset=6
      local.get 1
      local.get 2
      i32.const 24
      i32.shr_u
      i32.store8 offset=4
      local.get 1
      local.get 2
      i32.const 16
      i32.shr_u
      i32.store8 offset=5
      local.get 1
      local.get 6
      i32.wrap_i64
      local.tee 2
      i32.const 8
      i32.shr_u
      i32.store8 offset=30
      local.get 1
      local.get 2
      i32.const 24
      i32.shr_u
      i32.store8 offset=28
      local.get 1
      local.get 6
      i64.const 40
      i64.shr_u
      i64.store8 offset=26
      local.get 1
      local.get 6
      i64.const 56
      i64.shr_u
      i64.store8 offset=24
      local.get 1
      local.get 5
      i64.store8 offset=23
      local.get 1
      local.get 0
      i32.const 16
      i32.shr_u
      i32.store8 offset=21
      local.get 1
      local.get 5
      i64.const 32
      i64.shr_u
      i64.store8 offset=19
      local.get 1
      local.get 5
      i64.const 48
      i64.shr_u
      i64.store8 offset=17
      local.get 1
      local.get 6
      i64.store8 offset=31
      local.get 1
      local.get 2
      i32.const 16
      i32.shr_u
      i32.store8 offset=29
      local.get 1
      local.get 6
      i64.const 32
      i64.shr_u
      i64.store8 offset=27
      local.get 1
      local.get 6
      i64.const 48
      i64.shr_u
      i64.store8 offset=25
      return
    end
    unreachable
    unreachable)
  (func $wrapper_mstore_u32 (type 3) (param i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      local.get 0
      i32.const 32
      i32.add
      local.tee 2
      local.get 0
      i32.lt_s
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          i32.const 0
          i32.load offset=65688
          local.tee 3
          local.get 2
          i32.ge_u
          br_if 0 (;@3;)
          local.get 2
          i32.const 65535
          i32.add
          local.tee 4
          i32.const 16
          i32.shr_u
          local.get 3
          i32.const 16
          i32.shr_u
          i32.sub
          local.tee 3
          memory.grow
          drop
          i32.const 0
          local.get 2
          i32.store offset=65684
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=65688
          i32.const 0
          i32.const 0
          i32.load offset=65680
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65680
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65684
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65684
      end
      i32.const 0
      i32.load offset=65676
      local.get 0
      i32.add
      local.tee 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 0
      i64.store
      block  ;; label = @2
        local.get 1
        br_if 0 (;@2;)
        local.get 0
        i64.const 0
        i64.store offset=24
        return
      end
      local.get 0
      local.get 1
      i32.store8 offset=31
      local.get 0
      i32.const 0
      i32.store offset=24
      local.get 0
      local.get 1
      i32.const 8
      i32.shr_u
      i32.store8 offset=30
      local.get 0
      local.get 1
      i32.const 16
      i32.shr_u
      i32.store8 offset=29
      local.get 0
      local.get 1
      i32.const 24
      i32.shr_u
      i32.store8 offset=28
      return
    end
    unreachable
    unreachable)
  (func $wrapper_mload_bytes32 (type 3) (param i32 i32)
    local.get 1
    i32.const 0
    i32.load offset=65676
    local.get 0
    i32.add
    local.tee 0
    i32.load8_u
    i32.store8
    local.get 1
    local.get 0
    i32.load8_u offset=1
    i32.store8 offset=1
    local.get 1
    local.get 0
    i32.load8_u offset=2
    i32.store8 offset=2
    local.get 1
    local.get 0
    i32.load8_u offset=3
    i32.store8 offset=3
    local.get 1
    local.get 0
    i32.load8_u offset=4
    i32.store8 offset=4
    local.get 1
    local.get 0
    i32.load8_u offset=5
    i32.store8 offset=5
    local.get 1
    local.get 0
    i32.load8_u offset=6
    i32.store8 offset=6
    local.get 1
    local.get 0
    i32.load8_u offset=7
    i32.store8 offset=7
    local.get 1
    local.get 0
    i32.load8_u offset=8
    i32.store8 offset=8
    local.get 1
    local.get 0
    i32.const 9
    i32.add
    i32.load8_u
    i32.store8 offset=9
    local.get 1
    local.get 0
    i32.const 10
    i32.add
    i32.load8_u
    i32.store8 offset=10
    local.get 1
    local.get 0
    i32.const 11
    i32.add
    i32.load8_u
    i32.store8 offset=11
    local.get 1
    local.get 0
    i32.const 12
    i32.add
    i32.load8_u
    i32.store8 offset=12
    local.get 1
    local.get 0
    i32.const 13
    i32.add
    i32.load8_u
    i32.store8 offset=13
    local.get 1
    local.get 0
    i32.const 14
    i32.add
    i32.load8_u
    i32.store8 offset=14
    local.get 1
    local.get 0
    i32.const 15
    i32.add
    i32.load8_u
    i32.store8 offset=15
    local.get 1
    local.get 0
    i32.const 16
    i32.add
    i32.load8_u
    i32.store8 offset=16
    local.get 1
    local.get 0
    i32.const 17
    i32.add
    i32.load8_u
    i32.store8 offset=17
    local.get 1
    local.get 0
    i32.const 18
    i32.add
    i32.load8_u
    i32.store8 offset=18
    local.get 1
    local.get 0
    i32.const 19
    i32.add
    i32.load8_u
    i32.store8 offset=19
    local.get 1
    local.get 0
    i32.const 20
    i32.add
    i32.load8_u
    i32.store8 offset=20
    local.get 1
    local.get 0
    i32.const 21
    i32.add
    i32.load8_u
    i32.store8 offset=21
    local.get 1
    local.get 0
    i32.const 22
    i32.add
    i32.load8_u
    i32.store8 offset=22
    local.get 1
    local.get 0
    i32.const 23
    i32.add
    i32.load8_u
    i32.store8 offset=23
    local.get 1
    local.get 0
    i32.const 24
    i32.add
    i32.load8_u
    i32.store8 offset=24
    local.get 1
    local.get 0
    i32.const 25
    i32.add
    i32.load8_u
    i32.store8 offset=25
    local.get 1
    local.get 0
    i32.const 26
    i32.add
    i32.load8_u
    i32.store8 offset=26
    local.get 1
    local.get 0
    i32.const 27
    i32.add
    i32.load8_u
    i32.store8 offset=27
    local.get 1
    local.get 0
    i32.const 28
    i32.add
    i32.load8_u
    i32.store8 offset=28
    local.get 1
    local.get 0
    i32.const 29
    i32.add
    i32.load8_u
    i32.store8 offset=29
    local.get 1
    local.get 0
    i32.const 30
    i32.add
    i32.load8_u
    i32.store8 offset=30
    local.get 1
    local.get 0
    i32.const 31
    i32.add
    i32.load8_u
    i32.store8 offset=31)
  (func $wrapper_return (type 3) (param i32 i32)
    i32.const 0
    i32.load offset=65676
    local.get 0
    i32.add
    local.get 1
    call $finish)
  (func $set_is_deploying_tx (type 4)
    i32.const 0
    i32.const 1
    i32.store8 offset=65552)
  (func $wrapper_calldata_size_minus_4 (type 0) (result i32)
    (local i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=65536
      local.tee 0
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 0
      i32.store offset=65536
    end
    local.get 0
    i32.const -4
    i32.add)
  (func $__init_evm_heap (type 4)
    (local i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load8_u offset=65672
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          memory.size
          local.tee 0
          i32.const 2
          i32.lt_u
          br_if 0 (;@3;)
          i32.const 0
          local.get 0
          i32.const 16
          i32.shl
          i32.store offset=65676
          i32.const 1
          memory.grow
          drop
          memory.size
          i32.const 16
          i32.shl
          local.tee 0
          i32.const 0
          i32.load offset=65676
          i32.sub
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 65696
        i32.store offset=65676
        i32.const 82080
        local.set 0
        i32.const 16384
        local.set 1
      end
      i32.const 0
      local.get 0
      i32.store offset=65680
      i32.const 0
      local.get 1
      i32.store offset=65688
      i32.const 0
      i32.const 1
      i32.store8 offset=65672
      i32.const 0
      i32.const 0
      i32.store offset=65684
    end)
  (func $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.checked_add_uint256 (type 6) (param i32 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i64 i32)
    global.get $__stack_pointer
    local.tee 9
    local.set 10
    block  ;; label = @1
      local.get 5
      local.get 1
      i64.add
      local.tee 11
      local.get 1
      i64.ge_u
      local.get 6
      local.get 2
      i64.add
      local.get 11
      local.get 5
      i64.lt_u
      local.tee 12
      i64.extend_i32_u
      i64.add
      local.tee 1
      local.get 2
      i64.ge_u
      local.get 1
      local.get 2
      i64.eq
      select
      local.get 7
      local.get 3
      i64.add
      local.tee 5
      local.get 12
      local.get 1
      local.get 6
      i64.lt_u
      local.get 1
      local.get 6
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 2
      local.get 3
      i64.ge_u
      local.get 8
      local.get 4
      i64.add
      local.get 5
      local.get 7
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 2
      local.get 5
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 6
      local.get 4
      i64.ge_u
      local.get 6
      local.get 4
      i64.eq
      select
      local.get 2
      local.get 3
      i64.xor
      local.get 6
      local.get 4
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      local.get 9
      i32.const -32
      i32.add
      local.tee 12
      global.set $__stack_pointer
      local.get 12
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 12
      i64.const 0
      i64.store offset=16
      local.get 12
      i64.const 0
      i64.store offset=8
      local.get 12
      i64.const 0
      i64.store
      i32.const 0
      local.get 12
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 17
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 0
    local.get 11
    i64.store
    local.get 0
    local.get 1
    i64.store offset=8
    local.get 0
    local.get 2
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 6
    i64.store
    local.get 10
    global.set $__stack_pointer)
  (func $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.fun_fibonacci (type 7) (param i32 i64 i64 i64 i64)
    (local i32 i64 i64 i32 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i64.const 1
        i64.gt_u
        local.get 2
        i64.const 0
        i64.ne
        local.get 2
        i64.eqz
        select
        local.get 3
        i64.const 0
        i64.ne
        local.get 4
        i64.const 0
        i64.ne
        local.get 4
        i64.eqz
        select
        local.get 3
        local.get 4
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 1
          i32.wrap_i64
          br_table 2 (;@1;) 0 (;@3;) 2 (;@1;)
        end
        i64.const 0
        local.set 2
        i64.const 1
        local.set 1
        i64.const 0
        local.set 3
        i64.const 0
        local.set 4
        br 1 (;@1;)
      end
      local.get 5
      i32.const 64
      i32.add
      local.get 1
      i64.const -1
      i64.add
      local.tee 6
      local.get 2
      i64.const -1
      i64.add
      local.tee 7
      local.get 6
      local.get 1
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      local.tee 9
      local.get 3
      i64.const -1
      i64.add
      local.tee 6
      local.get 8
      local.get 9
      local.get 2
      i64.lt_u
      local.get 9
      local.get 2
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 9
      local.get 4
      local.get 6
      local.get 3
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.tee 3
      local.get 9
      local.get 6
      i64.lt_u
      i64.extend_i32_u
      i64.add
      call $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.fun_fibonacci
      local.get 5
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 9
      local.get 5
      i32.const 64
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 64
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 11
      local.get 5
      i64.load offset=64
      local.set 12
      local.get 5
      i32.const 32
      i32.add
      local.get 1
      i64.const -2
      i64.add
      local.tee 4
      local.get 7
      local.get 4
      local.get 1
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      local.tee 4
      local.get 6
      local.get 8
      local.get 4
      local.get 2
      i64.lt_u
      local.get 4
      local.get 2
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 2
      local.get 3
      local.get 2
      local.get 6
      i64.lt_u
      i64.extend_i32_u
      i64.add
      call $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.fun_fibonacci
      local.get 5
      local.get 12
      local.get 11
      local.get 10
      local.get 9
      local.get 5
      i64.load offset=32
      local.get 5
      i32.const 32
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 5
      i32.const 32
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.get 5
      i32.const 32
      i32.add
      i32.const 24
      i32.add
      i64.load
      call $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.checked_add_uint256
      local.get 5
      i32.const 24
      i32.add
      i64.load
      local.set 4
      local.get 5
      i32.const 16
      i32.add
      i64.load
      local.set 3
      local.get 5
      i32.const 8
      i32.add
      i64.load
      local.set 2
      local.get 5
      i64.load
      local.set 1
    end
    local.get 0
    local.get 1
    i64.store
    local.get 0
    local.get 2
    i64.store offset=8
    local.get 0
    local.get 3
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 5
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.init (type 4)
    (local i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 0
    local.set 1
    local.get 0
    global.set $__stack_pointer
    i32.const 128
    call $wrapper_memory_guard
    drop
    i32.const 64
    i32.const 96
    call $wrapper_mstore_u32
    block  ;; label = @1
      call $wrapper_calldata_size
      i32.const 4
      i32.lt_u
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          call $wrapper_calldata_load_selector
          local.tee 2
          i32.const -1400004437
          i32.eq
          br_if 0 (;@3;)
          local.get 2
          i32.const 1627684852
          i32.ne
          br_if 2 (;@1;)
          block  ;; label = @4
            call $wrapper_callvalue_not_zero
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            i32.const 0
            call $wrapper_revert
          end
          block  ;; label = @4
            call $wrapper_calldata_size_minus_4
            i32.const 31
            i32.gt_u
            br_if 0 (;@4;)
            i32.const 0
            i32.const 0
            call $wrapper_revert
          end
          local.get 0
          i32.const -32
          i32.add
          local.tee 2
          local.tee 0
          global.set $__stack_pointer
          i32.const 4
          local.get 2
          call $wrapper_calldataload_bytes32
          local.get 0
          i32.const -32
          i32.add
          local.tee 0
          local.tee 3
          global.set $__stack_pointer
          local.get 2
          local.get 0
          call $u256_from_big_endian_bytes
          local.get 1
          local.get 0
          i64.load
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.get 0
          i32.const 24
          i32.add
          i64.load
          call $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.fun_fibonacci
          local.get 1
          i32.const 8
          i32.add
          i64.load
          local.set 4
          local.get 1
          i32.const 16
          i32.add
          i64.load
          local.set 5
          local.get 1
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 1
          i64.load
          local.set 7
          local.get 3
          i32.const -32
          i32.add
          local.tee 0
          local.tee 3
          global.set $__stack_pointer
          i32.const 64
          local.get 0
          call $wrapper_mload_bytes32
          local.get 0
          call $i32_from_big_endian_bytes32
          local.set 2
          local.get 3
          i32.const -32
          i32.add
          local.tee 0
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 6
          i64.store
          local.get 0
          local.get 5
          i64.store offset=16
          local.get 0
          local.get 4
          i64.store offset=8
          local.get 0
          local.get 7
          i64.store
          local.get 2
          local.get 0
          call $wrapper_mstore_u256
          br 1 (;@2;)
        end
        block  ;; label = @3
          call $wrapper_callvalue_not_zero
          i32.eqz
          br_if 0 (;@3;)
          i32.const 0
          i32.const 0
          call $wrapper_revert
        end
        block  ;; label = @3
          call $wrapper_calldata_size_minus_4
          i32.const 31
          i32.gt_u
          br_if 0 (;@3;)
          i32.const 0
          i32.const 0
          call $wrapper_revert
        end
        local.get 0
        i32.const -32
        i32.add
        local.tee 2
        local.tee 0
        global.set $__stack_pointer
        i32.const 4
        local.get 2
        call $wrapper_calldataload_bytes32
        local.get 0
        i32.const -32
        i32.add
        local.tee 0
        local.tee 3
        global.set $__stack_pointer
        local.get 2
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 5
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 6
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 4
        local.get 0
        i64.load
        local.set 7
        i64.const 0
        local.set 8
        i64.const 0
        local.set 9
        i64.const 0
        local.set 10
        i64.const 0
        local.set 11
        i64.const 1
        local.set 12
        i64.const 0
        local.set 13
        i64.const 0
        local.set 14
        i64.const 0
        local.set 15
        block  ;; label = @3
          block  ;; label = @4
            loop  ;; label = @5
              block  ;; label = @6
                local.get 7
                i64.const 1
                i64.gt_u
                local.get 4
                i64.const 0
                i64.ne
                local.get 4
                i64.eqz
                select
                local.get 6
                i64.const 0
                i64.ne
                local.get 5
                i64.const 0
                i64.ne
                local.get 5
                i64.eqz
                select
                local.get 6
                local.get 5
                i64.or
                i64.eqz
                select
                br_if 0 (;@6;)
                local.get 7
                i32.wrap_i64
                br_table 3 (;@3;) 2 (;@4;) 3 (;@3;)
              end
              local.get 1
              i32.const 32
              i32.add
              local.get 8
              local.get 9
              local.get 10
              local.get 11
              local.get 12
              local.get 13
              local.get 14
              local.get 15
              call $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.checked_add_uint256
              local.get 5
              local.get 6
              i64.const -1
              i64.add
              local.tee 8
              local.get 6
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.get 8
              local.get 7
              i64.const -1
              i64.add
              local.tee 9
              local.get 7
              i64.lt_u
              local.tee 0
              local.get 4
              local.get 0
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.tee 6
              local.get 4
              i64.lt_u
              local.get 6
              local.get 4
              i64.eq
              select
              i64.extend_i32_u
              i64.add
              local.tee 10
              local.get 8
              i64.lt_u
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.set 5
              local.get 9
              local.set 7
              local.get 6
              local.set 4
              local.get 10
              local.set 6
              local.get 12
              local.set 8
              local.get 13
              local.set 9
              local.get 14
              local.set 10
              local.get 15
              local.set 11
              local.get 1
              i64.load offset=32
              local.set 12
              local.get 1
              i32.const 32
              i32.add
              i32.const 8
              i32.add
              i64.load
              local.set 13
              local.get 1
              i32.const 32
              i32.add
              i32.const 16
              i32.add
              i64.load
              local.set 14
              local.get 1
              i32.const 32
              i32.add
              i32.const 24
              i32.add
              i64.load
              local.set 15
              br 0 (;@5;)
            end
          end
          local.get 12
          local.set 8
          local.get 13
          local.set 9
          local.get 14
          local.set 10
          local.get 15
          local.set 11
        end
        local.get 3
        i32.const -32
        i32.add
        local.tee 0
        local.tee 3
        global.set $__stack_pointer
        i32.const 64
        local.get 0
        call $wrapper_mload_bytes32
        local.get 0
        call $i32_from_big_endian_bytes32
        local.set 2
        local.get 3
        i32.const -32
        i32.add
        local.tee 0
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 11
        i64.store
        local.get 0
        local.get 10
        i64.store offset=16
        local.get 0
        local.get 9
        i64.store offset=8
        local.get 0
        local.get 8
        i64.store
        local.get 2
        local.get 0
        call $wrapper_mstore_u256
      end
      local.get 2
      i32.const 32
      call $wrapper_return
    end
    i32.const 0
    i32.const 0
    call $wrapper_revert
    local.get 1
    i32.const 64
    i32.add
    global.set $__stack_pointer)
  (func $call (type 4)
    call $FibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.init)
  (func $_start (type 4)
    call $__init_evm_heap)
  (func $deploy (type 4)
    call $set_is_deploying_tx
    i32.const 128
    call $wrapper_memory_guard
    drop
    i32.const 64
    i32.const 96
    call $wrapper_mstore_u32
    block  ;; label = @1
      call $wrapper_callvalue_not_zero
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      call $wrapper_revert
    end
    i32.const 96
    i32.const 82080
    i32.const 0
    call $evm_get_memory_addr
    i32.sub
    i32.const 4
    call $wrapper_codecopy
    i32.const 96
    i32.const 4
    call $wrapper_return)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 3)
  (global $__stack_pointer (mut i32) (i32.const 65536))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "call" (func $call))
  (export "deploy" (func $deploy))
  (data $.data (i32.const 65536) "\ff\ff\ff\ff")
  (data (;1;) (i32.const 65672) "\01")
  (data (;2;) (i32.const 65678) "\02\00\00\00\03")
  (data (;3;) (i32.const 65690) "\01")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "producers" "\02\08language\01\03C99\00\0cprocessed-by\02\05clangV11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\0eHomebrew clang\0616.0.6")
  (@custom "name" "\01\80\06\1f\00\0fgetCallDataSize\01\0ccallDataCopy\02\0cgetCallValue\03\06revert\04\06finish\05\0bgetCodeSize\06\08codeCopy\07\11__wasm_call_ctors\08\1au256_from_big_endian_bytes\09\1bi32_from_big_endian_bytes32\0a\1cwrapper_calldataload_bytes32\0b\1ewrapper_calldata_load_selector\0c\15wrapper_calldata_size\0d\1awrapper_callvalue_not_zero\0e\0ewrapper_revert\0f\13evm_get_memory_addr\10\10wrapper_codecopy\11\14wrapper_memory_guard\12\13wrapper_mstore_u256\13\12wrapper_mstore_u32\14\15wrapper_mload_bytes32\15\0ewrapper_return\16\13set_is_deploying_tx\17\1dwrapper_calldata_size_minus_4\18\0f__init_evm_heap\19WFibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.checked_add_uint256\1aQFibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.fun_fibonacci\1bHFibonacciRecurTest_48845_deployed.FibonacciRecurTest_48845_deployed.init\1c\04call\1d\06_start\1e\06deploy\07\12\01\00\0f__stack_pointer\09\08\01\00\05.data")
  (@custom ".debug_str" "y\00x\00low\00wasisdk://v12.0/build/compiler-rt\00du_int\00ti_int\00di_int\00long long int\00long long unsigned int\00uint64_t\00twords\00r\00all\00lower_mask\00high\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins/multi3.c\00b\00a\00__int128\00__multi3\00__mulddi3\00bits_in_dword_2\00clang version 11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\00")
  (@custom ".debug_line" "M\01\00\00\04\00\c2\00\00\00\01\01\01\fb\0e\0d\00\01\01\01\01\00\00\00\01\00\00\01wasisdk://v12.0/build/install/opt/wasi-sdk/share/wasi-sysroot/include/bits\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins\00\00alltypes.h\00\01\00\00int_types.h\00\02\00\00multi3.c\00\02\00\00\00\04\03\00\05\02\ff\ff\ff\ff\03'\01\05\03\0aD\05,-\05\18\06X\05\0c\06\03rX\05\0b\1eo\05&`\05\0c\06<\05#\06\03u \05\10\06\ac\05\1e\90\03i<\05\16\06\03\18J\05\1f\22\05\05\06X\03f \05\10\06\03\1cJ\05\22\03\13 \05\0f\03n \05\1f\92\05\05\06X\03a \05\11\06\03!J\05\0c\03\0e \05\03!\05\1f\03pX\05\0b\03yX\97\05\03\03\10 \02\04\00\01\01")
  (@custom ".debug_abbrev" "\01\11\01%\0e\13\05\03\0e\10\17\1b\0e\11\01\12\06\00\00\02$\00\03\0e>\0b\0b\0b\00\00\03\16\00I\13\03\0e:\0b;\0b\00\00\04.\01\03\0e:\0b;\0b'\19I\13 \0b\00\00\05\05\00\03\0e:\0b;\0bI\13\00\00\064\00\03\0e:\0b;\0bI\13\00\00\07\17\01\0b\0b:\0b;\0b\00\00\08\0d\00\03\0eI\13:\0b;\0b8\0b\00\00\09\13\01\0b\0b:\0b;\0b\00\00\0a&\00I\13\00\00\0b.\01\11\01\12\06@\18\97B\19\03\0e:\0b;\0b'\19I\13?\19\00\00\0c\05\00\02\17\03\0e:\0b;\0bI\13\00\00\0d4\00\02\17\03\0e:\0b;\0bI\13\00\00\0e\1d\011\13U\17X\0bY\0bW\0b\00\00\0f\05\001\13\00\00\104\00\02\171\13\00\00\114\00\1c\0d1\13\00\00\124\00\1c\0f1\13\00\00\00")
  (@custom ".debug_ranges" "\0f\00\00\00G\00\00\00H\00\00\00\5c\00\00\00b\00\00\00q\00\00\00\00\00\00\00\00\00\00\00")
  (@custom ".debug_loc" "\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\007\00\00\009\00\00\00\06\00\ed\02\02\9f\93\089\00\00\00G\00\00\00\06\00\ed\00\05\9f\93\08G\00\00\00H\00\00\00\0c\00\ed\00\05\9f\93\08\ed\02\02\9f\93\08H\00\00\00p\00\00\00\06\00\ed\00\05\9f\93\08p\00\00\00q\00\00\00\06\00\ed\02\02\9f\93\08q\00\00\00t\00\00\00\06\00\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00]\00\00\00`\00\00\00\08\00\93\08\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00<\00\00\00B\00\00\00\04\00\ed\02\02\9fQ\00\00\00Y\00\00\00\04\00\ed\02\02\9fY\00\00\00u\00\00\00\04\00\ed\00\03\9f\00\00\00\00\00\00\00\00")
  (@custom ".debug_info" "\b4\01\00\00\04\00\00\00\00\00\04\01\fd\00\00\00\0c\00\8a\00\00\00\00\00\00\00\08\00\00\00\ff\ff\ff\ffu\00\00\00\02`\00\00\00\05\04\038\00\00\00*\00\00\00\02&\03C\00\00\00d\00\00\00\01\aa\02M\00\00\00\07\08\04\e3\00\00\00\03\13\99\00\00\00\01\05\cf\00\00\00\03\13-\00\00\00\05\cd\00\00\00\03\13-\00\00\00\06t\00\00\00\03\14\ab\00\00\00\06\ed\00\00\00\03\15\0d\01\00\00\06z\00\00\00\03\16\12\01\00\00\06k\00\00\00\03\18-\00\00\00\00\03\a4\00\00\001\00\00\00\02O\02\d1\00\00\00\05\10\03\b6\00\00\00m\00\00\00\02]\07\10\02R\08v\00\00\00\99\00\00\00\02S\00\08r\00\00\00\d2\00\00\00\02\5c\00\09\10\02T\08\04\00\00\00-\00\00\00\02V\00\08\85\00\00\00\f0\00\00\00\02W\08\00\00\03\fb\00\00\008\00\00\00\02%\03\06\01\00\00e\00\00\00\01\91\02?\00\00\00\05\08\0a&\00\00\00\0a-\00\00\00\0b\ff\ff\ff\ffu\00\00\00\07\ed\03\00\00\00\00\9f\da\00\00\00\03(\99\00\00\00\0c\00\00\00\00\cf\00\00\00\03(\99\00\00\00\0c\14\00\00\00\cd\00\00\00\03(\99\00\00\00\0d(\00\00\00\00\00\00\00\03+\ab\00\00\00\0d\aa\00\00\00\02\00\00\00\03)\ab\00\00\00\0d\be\00\00\00t\00\00\00\03-\ab\00\00\00\0eJ\00\00\00\00\00\00\00\03.\0b\0fV\00\00\00\0fa\00\00\00\10<\00\00\00l\00\00\00\11 w\00\00\00\12\ff\ff\ff\ff\0f\82\00\00\00\10\d8\00\00\00\8d\00\00\00\00\00\00"))
