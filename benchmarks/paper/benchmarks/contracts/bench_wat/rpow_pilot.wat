(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32 i32)))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func))
  (type (;5;) (func (param i32 i64 i64 i64 i64)))
  (type (;6;) (func (param i32) (result i32)))
  (import "env" "getCallDataSize" (func $getCallDataSize (type 0)))
  (import "env" "callDataCopy" (func $callDataCopy (type 1)))
  (import "env" "getCallValue" (func $getCallValue (type 2)))
  (import "env" "revert" (func $revert (type 3)))
  (import "env" "finish" (func $finish (type 3)))
  (import "env" "getCodeSize" (func $getCodeSize (type 0)))
  (import "env" "codeCopy" (func $codeCopy (type 1)))
  (func $__wasm_call_ctors (type 4))
  (func $__multi3 (type 5) (param i32 i64 i64 i64 i64)
    (local i64)
    local.get 0
    local.get 4
    local.get 1
    i64.mul
    local.get 2
    local.get 3
    i64.mul
    i64.add
    local.get 3
    i64.const 32
    i64.shr_u
    local.tee 4
    local.get 1
    i64.const 32
    i64.shr_u
    local.tee 2
    i64.mul
    i64.add
    local.get 3
    i64.const 4294967295
    i64.and
    local.tee 3
    local.get 1
    i64.const 4294967295
    i64.and
    local.tee 1
    i64.mul
    local.tee 5
    i64.const 32
    i64.shr_u
    local.get 3
    local.get 2
    i64.mul
    i64.add
    local.tee 3
    i64.const 32
    i64.shr_u
    i64.add
    local.get 3
    i64.const 4294967295
    i64.and
    local.get 4
    local.get 1
    i64.mul
    i64.add
    local.tee 3
    i64.const 32
    i64.shr_u
    i64.add
    i64.store offset=8
    local.get 0
    local.get 3
    i64.const 32
    i64.shl
    local.get 5
    i64.const 4294967295
    i64.and
    i64.or
    i64.store)
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
              i32.load8_u offset=65796
              br_if 0 (;@5;)
              i32.const 65696
              i32.const 0
              local.get 3
              call $callDataCopy
              i32.const 0
              i32.const 1
              i32.store8 offset=65796
            end
            local.get 4
            i32.eqz
            br_if 2 (;@2;)
            local.get 0
            i32.const 65696
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
            i32.load8_u offset=65796
            br_if 0 (;@4;)
            i32.const 65696
            i32.const 0
            local.get 2
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=65796
          end
          local.get 1
          local.get 0
          i32.const 65696
          i32.add
          i32.load8_u
          i32.store8
          local.get 1
          local.get 0
          i32.const 65697
          i32.add
          i32.load8_u
          i32.store8 offset=1
          local.get 1
          local.get 0
          i32.const 65698
          i32.add
          i32.load8_u
          i32.store8 offset=2
          local.get 1
          local.get 0
          i32.const 65699
          i32.add
          i32.load8_u
          i32.store8 offset=3
          local.get 1
          local.get 0
          i32.const 65700
          i32.add
          i32.load8_u
          i32.store8 offset=4
          local.get 1
          local.get 0
          i32.const 65701
          i32.add
          i32.load8_u
          i32.store8 offset=5
          local.get 1
          local.get 0
          i32.const 65702
          i32.add
          i32.load8_u
          i32.store8 offset=6
          local.get 1
          local.get 0
          i32.const 65703
          i32.add
          i32.load8_u
          i32.store8 offset=7
          local.get 1
          local.get 0
          i32.const 65704
          i32.add
          i32.load8_u
          i32.store8 offset=8
          local.get 1
          local.get 0
          i32.const 65705
          i32.add
          i32.load8_u
          i32.store8 offset=9
          local.get 1
          local.get 0
          i32.const 65706
          i32.add
          i32.load8_u
          i32.store8 offset=10
          local.get 1
          local.get 0
          i32.const 65707
          i32.add
          i32.load8_u
          i32.store8 offset=11
          local.get 1
          local.get 0
          i32.const 65708
          i32.add
          i32.load8_u
          i32.store8 offset=12
          local.get 1
          local.get 0
          i32.const 65709
          i32.add
          i32.load8_u
          i32.store8 offset=13
          local.get 1
          local.get 0
          i32.const 65710
          i32.add
          i32.load8_u
          i32.store8 offset=14
          local.get 1
          local.get 0
          i32.const 65711
          i32.add
          i32.load8_u
          i32.store8 offset=15
          local.get 1
          local.get 0
          i32.const 65712
          i32.add
          i32.load8_u
          i32.store8 offset=16
          local.get 1
          local.get 0
          i32.const 65713
          i32.add
          i32.load8_u
          i32.store8 offset=17
          local.get 1
          local.get 0
          i32.const 65714
          i32.add
          i32.load8_u
          i32.store8 offset=18
          local.get 1
          local.get 0
          i32.const 65715
          i32.add
          i32.load8_u
          i32.store8 offset=19
          local.get 1
          local.get 0
          i32.const 65716
          i32.add
          i32.load8_u
          i32.store8 offset=20
          local.get 1
          local.get 0
          i32.const 65717
          i32.add
          i32.load8_u
          i32.store8 offset=21
          local.get 1
          local.get 0
          i32.const 65718
          i32.add
          i32.load8_u
          i32.store8 offset=22
          local.get 1
          local.get 0
          i32.const 65719
          i32.add
          i32.load8_u
          i32.store8 offset=23
          local.get 1
          local.get 0
          i32.const 65720
          i32.add
          i32.load8_u
          i32.store8 offset=24
          local.get 1
          local.get 0
          i32.const 65721
          i32.add
          i32.load8_u
          i32.store8 offset=25
          local.get 1
          local.get 0
          i32.const 65722
          i32.add
          i32.load8_u
          i32.store8 offset=26
          local.get 1
          local.get 0
          i32.const 65723
          i32.add
          i32.load8_u
          i32.store8 offset=27
          local.get 1
          local.get 0
          i32.const 65724
          i32.add
          i32.load8_u
          i32.store8 offset=28
          local.get 1
          local.get 0
          i32.const 65725
          i32.add
          i32.load8_u
          i32.store8 offset=29
          local.get 1
          local.get 0
          i32.const 65726
          i32.add
          i32.load8_u
          i32.store8 offset=30
          local.get 1
          local.get 0
          i32.const 65727
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
    i32.load offset=65804
    local.get 0
    i32.add
    local.get 1
    call $revert)
  (func $evm_get_memory_addr (type 6) (param i32) (result i32)
    i32.const 0
    i32.load offset=65804
    local.get 0
    i32.add)
  (func $wrapper_codecopy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=65816
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
        i32.store offset=65812
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=65816
        i32.const 0
        i32.const 0
        i32.load offset=65808
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=65808
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=65812
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=65812
    end
    i32.const 0
    i32.load offset=65804
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
          i32.load8_u offset=65796
          br_if 0 (;@3;)
          i32.const 65696
          i32.const 0
          local.get 1
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=65796
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.const 65696
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
  (func $wrapper_memory_guard (type 6) (param i32) (result i32)
    (local i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=65816
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
      i32.store offset=65812
      i32.const 0
      local.get 2
      i32.const -65536
      i32.and
      i32.store offset=65816
      i32.const 0
      i32.const 0
      i32.load offset=65808
      local.get 1
      i32.const 16
      i32.shl
      i32.add
      i32.store offset=65808
      i32.const 96
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=65812
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 0
      i32.store offset=65812
    end
    i32.const 96)
  (func $wrapper_mstore_bytes32 (type 3) (param i32 i32)
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
          i32.load offset=65816
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
          i32.store offset=65812
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=65816
          i32.const 0
          i32.const 0
          i32.load offset=65808
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65808
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65812
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65812
      end
      i32.const 0
      i32.load offset=65804
      local.get 0
      i32.add
      local.tee 0
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
      local.get 0
      local.get 1
      i32.load8_u offset=8
      i32.store8 offset=8
      local.get 0
      i32.const 9
      i32.add
      local.get 1
      i32.load8_u offset=9
      i32.store8
      local.get 0
      i32.const 10
      i32.add
      local.get 1
      i32.load8_u offset=10
      i32.store8
      local.get 0
      i32.const 11
      i32.add
      local.get 1
      i32.load8_u offset=11
      i32.store8
      local.get 0
      i32.const 12
      i32.add
      local.get 1
      i32.load8_u offset=12
      i32.store8
      local.get 0
      i32.const 13
      i32.add
      local.get 1
      i32.load8_u offset=13
      i32.store8
      local.get 0
      i32.const 14
      i32.add
      local.get 1
      i32.load8_u offset=14
      i32.store8
      local.get 0
      i32.const 15
      i32.add
      local.get 1
      i32.load8_u offset=15
      i32.store8
      local.get 0
      i32.const 16
      i32.add
      local.get 1
      i32.load8_u offset=16
      i32.store8
      local.get 0
      i32.const 17
      i32.add
      local.get 1
      i32.load8_u offset=17
      i32.store8
      local.get 0
      i32.const 18
      i32.add
      local.get 1
      i32.load8_u offset=18
      i32.store8
      local.get 0
      i32.const 19
      i32.add
      local.get 1
      i32.load8_u offset=19
      i32.store8
      local.get 0
      i32.const 20
      i32.add
      local.get 1
      i32.load8_u offset=20
      i32.store8
      local.get 0
      i32.const 21
      i32.add
      local.get 1
      i32.load8_u offset=21
      i32.store8
      local.get 0
      i32.const 22
      i32.add
      local.get 1
      i32.load8_u offset=22
      i32.store8
      local.get 0
      i32.const 23
      i32.add
      local.get 1
      i32.load8_u offset=23
      i32.store8
      local.get 0
      i32.const 24
      i32.add
      local.get 1
      i32.load8_u offset=24
      i32.store8
      local.get 0
      i32.const 25
      i32.add
      local.get 1
      i32.load8_u offset=25
      i32.store8
      local.get 0
      i32.const 26
      i32.add
      local.get 1
      i32.load8_u offset=26
      i32.store8
      local.get 0
      i32.const 27
      i32.add
      local.get 1
      i32.load8_u offset=27
      i32.store8
      local.get 0
      i32.const 28
      i32.add
      local.get 1
      i32.load8_u offset=28
      i32.store8
      local.get 0
      i32.const 29
      i32.add
      local.get 1
      i32.load8_u offset=29
      i32.store8
      local.get 0
      i32.const 30
      i32.add
      local.get 1
      i32.load8_u offset=30
      i32.store8
      local.get 0
      i32.const 31
      i32.add
      local.get 1
      i32.load8_u offset=31
      i32.store8
      return
    end
    unreachable
    unreachable)
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
          i32.load offset=65816
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
          i32.store offset=65812
          i32.const 0
          local.get 7
          i32.const -65536
          i32.and
          i32.store offset=65816
          i32.const 0
          i32.const 0
          i32.load offset=65808
          local.get 1
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65808
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65812
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65812
      end
      i32.const 0
      i32.load offset=65804
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
          i32.load offset=65816
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
          i32.store offset=65812
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=65816
          i32.const 0
          i32.const 0
          i32.load offset=65808
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65808
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65812
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65812
      end
      i32.const 0
      i32.load offset=65804
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
  (func $wrapper_mload_u256 (type 3) (param i32 i32)
    local.get 1
    i32.const 0
    i32.load offset=65804
    local.get 0
    i32.add
    local.tee 0
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
  (func $wrapper_return (type 3) (param i32 i32)
    i32.const 0
    i32.load offset=65804
    local.get 0
    i32.add
    local.get 1
    call $finish)
  (func $set_is_deploying_tx (type 4)
    i32.const 0
    i32.const 1
    i32.store8 offset=65680)
  (func $__init_evm_heap (type 2) (param i32)
    (local i32)
    block  ;; label = @1
      i32.const 0
      i32.load8_u offset=65800
      br_if 0 (;@1;)
      memory.size
      local.set 1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.lt_u
            br_if 1 (;@3;)
          end
          i32.const 0
          local.get 1
          i32.const 16
          i32.shl
          i32.store offset=65804
          i32.const 1
          memory.grow
          drop
          memory.size
          i32.const 16
          i32.shl
          local.tee 0
          i32.const 0
          i32.load offset=65804
          i32.sub
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 65824
        i32.store offset=65804
        i32.const 82208
        local.set 0
        i32.const 16384
        local.set 1
      end
      i32.const 0
      local.get 0
      i32.store offset=65808
      i32.const 0
      local.get 1
      i32.store offset=65816
      i32.const 0
      i32.const 1
      i32.store8 offset=65800
      i32.const 0
      i32.const 0
      i32.store offset=65812
    end)
  (func $wrapper_u256_shr (type 1) (param i32 i32 i32)
    (local i32 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.const 0
        i32.gt_s
        br_if 0 (;@2;)
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 4
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 5
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 6
        local.get 0
        i64.load
        local.set 7
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.const 255
        i32.le_u
        br_if 0 (;@2;)
        i64.const 0
        local.set 7
        i64.const 0
        local.set 6
        i64.const 0
        local.set 5
        i64.const 0
        local.set 4
        br 1 (;@1;)
      end
      local.get 3
      i32.const 56
      i32.add
      i64.const 0
      i64.store align=1
      local.get 3
      i32.const 48
      i32.add
      i64.const 0
      i64.store align=1
      local.get 3
      i32.const 40
      i32.add
      i64.const 0
      i64.store align=1
      local.get 3
      i32.const 24
      i32.add
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.store align=1
      local.get 3
      i64.const 0
      i64.store offset=32 align=1
      local.get 3
      local.get 0
      i64.load
      i64.store align=1
      local.get 3
      local.get 0
      i32.const 16
      i32.add
      i64.load
      i64.store offset=16 align=1
      local.get 3
      local.get 0
      i32.const 8
      i32.add
      i64.load
      i64.store offset=8 align=1
      local.get 3
      local.get 1
      i32.const 3
      i32.shr_u
      i32.const 31
      i32.and
      i32.add
      local.tee 3
      i32.const 16
      i32.add
      i64.load align=1
      local.tee 6
      local.get 1
      i32.const 7
      i32.and
      local.tee 0
      i64.extend_i32_u
      local.tee 4
      i64.shr_u
      local.get 3
      i32.const 24
      i32.add
      i64.load align=1
      local.tee 8
      i64.const 1
      i64.shl
      local.get 0
      i32.const 63
      i32.xor
      i64.extend_i32_u
      local.tee 7
      i64.shl
      i64.or
      local.set 5
      local.get 3
      i32.const 8
      i32.add
      i64.load align=1
      local.tee 9
      local.get 4
      i64.shr_u
      local.get 6
      i64.const 1
      i64.shl
      local.get 0
      i32.const -1
      i32.xor
      i32.const 63
      i32.and
      i64.extend_i32_u
      i64.shl
      i64.or
      local.set 6
      local.get 3
      i64.load align=1
      local.get 4
      i64.shr_u
      local.get 9
      i64.const 1
      i64.shl
      local.get 7
      i64.shl
      i64.or
      local.set 7
      local.get 8
      local.get 4
      i64.shr_u
      local.set 4
    end
    local.get 2
    local.get 7
    i64.store
    local.get 2
    local.get 6
    i64.store offset=8
    local.get 2
    local.get 5
    i64.store offset=16
    local.get 2
    i32.const 24
    i32.add
    local.get 4
    i64.store)
  (func $RpowPilot_88_deployed.RpowPilot_88_deployed.fun_generate_87 (type 5) (param i32 i64 i64 i64 i64)
    (local i32 i64 i64 i64 i64 i64 i64 i64 i32 i32 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i32 i64 i64 i32 i64 i64 i64 i64 i64 i32 i32 i32 i32 i64 i64 i32 i64 i64 i32 i64 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32)
    global.get $__stack_pointer
    i32.const 768
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    i32.const 640
    i32.add
    local.get 1
    i64.const 0
    i64.const 86400
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 672
    i32.add
    local.get 2
    i64.const 0
    i64.const 86400
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 688
    i32.add
    local.get 1
    local.get 2
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 592
    i32.add
    local.get 3
    i64.const 0
    i64.const 86400
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 576
    i32.add
    local.get 4
    i64.const 0
    i64.const 86400
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 624
    i32.add
    local.get 1
    i64.const 0
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 656
    i32.add
    local.get 2
    i64.const 0
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 608
    i32.add
    local.get 1
    i64.const 0
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 5
    i64.load offset=640
    local.set 6
    block  ;; label = @1
      local.get 5
      i64.load offset=584
      i64.const 0
      i64.ne
      local.get 5
      i32.const 592
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 1
      local.get 5
      i64.load offset=576
      i64.add
      local.tee 3
      local.get 1
      i64.lt_u
      i32.or
      local.get 5
      i64.load offset=656
      local.tee 4
      local.get 5
      i32.const 672
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 5
      i64.load offset=672
      local.tee 1
      local.get 5
      i32.const 640
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.add
      local.tee 2
      local.get 1
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 7
      local.get 5
      i32.const 624
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 5
      i64.load offset=624
      local.tee 1
      local.get 2
      i64.add
      local.tee 8
      local.get 1
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.add
      local.tee 9
      i64.add
      local.tee 1
      local.get 5
      i64.load offset=688
      i64.add
      local.tee 2
      local.get 5
      i64.load offset=592
      local.tee 10
      local.get 5
      i64.load offset=608
      i64.add
      local.tee 11
      i64.add
      local.tee 12
      local.get 2
      i64.lt_u
      local.tee 13
      local.get 5
      i32.const 656
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 9
      local.get 7
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 1
      local.get 4
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 5
      i32.const 688
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.add
      local.get 2
      local.get 1
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 1
      local.get 3
      local.get 5
      i32.const 608
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.add
      local.get 11
      local.get 10
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.add
      local.get 13
      i64.extend_i32_u
      i64.add
      local.tee 2
      local.get 1
      i64.lt_u
      local.get 2
      local.get 1
      i64.eq
      select
      i32.or
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      i32.const 0
      i32.const 65552
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 17
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    i32.const 65584
    local.get 5
    i32.const 736
    i32.add
    call $u256_from_big_endian_bytes
    local.get 5
    i32.const 736
    i32.add
    i32.const 24
    i32.add
    local.tee 14
    i64.load
    local.set 15
    local.get 5
    i32.const 736
    i32.add
    i32.const 16
    i32.add
    local.tee 16
    i64.load
    local.set 17
    local.get 5
    i32.const 736
    i32.add
    i32.const 8
    i32.add
    local.tee 13
    i64.load
    local.set 18
    local.get 5
    i64.load offset=736
    local.set 19
    i32.const 65616
    local.get 5
    i32.const 736
    i32.add
    call $u256_from_big_endian_bytes
    local.get 14
    i64.load
    local.set 20
    local.get 16
    i64.load
    local.set 21
    local.get 13
    i64.load
    local.set 22
    local.get 5
    i64.load offset=736
    local.set 23
    i32.const 65616
    local.get 5
    i32.const 736
    i32.add
    call $u256_from_big_endian_bytes
    local.get 13
    i64.load
    local.set 1
    local.get 16
    i64.load
    local.set 3
    local.get 14
    i64.load
    local.set 4
    local.get 5
    i64.load offset=736
    local.set 7
    local.get 14
    local.get 2
    i64.store
    local.get 5
    local.get 12
    i64.store offset=752
    local.get 5
    local.get 8
    i64.store offset=744
    local.get 5
    local.get 6
    i64.store offset=736
    local.get 5
    i32.const 736
    i32.add
    i32.const 1
    local.get 5
    i32.const 704
    i32.add
    call $wrapper_u256_shr
    block  ;; label = @1
      local.get 5
      i64.load offset=704
      local.tee 24
      local.get 5
      i32.const 704
      i32.add
      i32.const 16
      i32.add
      local.tee 25
      i64.load
      local.tee 26
      i64.or
      local.get 5
      i32.const 704
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 27
      local.get 5
      i32.const 704
      i32.add
      i32.const 24
      i32.add
      local.tee 28
      i64.load
      local.tee 29
      i64.or
      i64.or
      i64.eqz
      br_if 0 (;@1;)
      local.get 3
      i64.const 1
      i64.shr_u
      local.get 4
      i64.const 63
      i64.shl
      i64.or
      local.set 30
      local.get 1
      i64.const 1
      i64.shr_u
      local.get 3
      i64.const 63
      i64.shl
      i64.or
      local.set 31
      local.get 7
      i64.const 1
      i64.shr_u
      local.get 1
      i64.const 63
      i64.shl
      i64.or
      local.set 32
      local.get 4
      i64.const 1
      i64.shr_u
      local.set 33
      local.get 5
      i32.const 64
      i32.add
      i32.const 40
      i32.add
      local.set 34
      local.get 5
      i32.const 64
      i32.add
      i32.const 32
      i32.add
      local.set 35
      local.get 5
      i32.const 64
      i32.add
      i32.const 48
      i32.add
      local.set 36
      local.get 5
      i32.const 64
      i32.add
      i32.const 56
      i32.add
      local.set 37
      loop  ;; label = @2
        local.get 5
        i32.const 528
        i32.add
        local.get 18
        i64.const 0
        local.get 19
        i64.const 0
        call $__multi3
        local.get 5
        i32.const 512
        i32.add
        local.get 19
        i64.const 0
        local.get 18
        i64.const 0
        call $__multi3
        local.get 5
        i32.const 480
        i32.add
        local.get 19
        local.get 18
        i64.const 0
        i64.const 0
        call $__multi3
        local.get 5
        i32.const 496
        i32.add
        local.get 17
        i64.const 0
        local.get 19
        i64.const 0
        call $__multi3
        local.get 5
        i32.const 448
        i32.add
        local.get 18
        i64.const 0
        local.get 17
        i64.const 0
        call $__multi3
        local.get 5
        i32.const 464
        i32.add
        local.get 15
        i64.const 0
        local.get 19
        i64.const 0
        call $__multi3
        local.get 5
        i32.const 544
        i32.add
        local.get 19
        i64.const 0
        local.get 19
        i64.const 0
        call $__multi3
        local.get 5
        i32.const 560
        i32.add
        local.get 18
        i64.const 0
        local.get 18
        i64.const 0
        call $__multi3
        local.get 5
        i64.load offset=544
        local.set 2
        block  ;; label = @3
          local.get 17
          local.get 15
          i64.or
          i64.const 0
          i64.ne
          local.get 15
          i64.const 0
          i64.ne
          local.get 18
          i64.const 0
          i64.ne
          i32.and
          local.get 5
          i64.load offset=472
          i64.const 0
          i64.ne
          i32.or
          local.get 5
          i64.load offset=456
          i64.const 0
          i64.ne
          i32.or
          local.get 5
          i32.const 496
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.tee 1
          local.get 5
          i64.load offset=464
          local.get 5
          i64.load offset=448
          i64.add
          i64.add
          local.tee 3
          local.get 1
          i64.lt_u
          i32.or
          i32.or
          local.get 5
          i64.load offset=560
          local.tee 10
          local.get 5
          i32.const 528
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.get 5
          i64.load offset=528
          local.tee 1
          local.get 5
          i32.const 544
          i32.add
          i32.const 8
          i32.add
          i64.load
          i64.add
          local.tee 4
          local.get 1
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.tee 11
          local.get 5
          i32.const 512
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.get 5
          i64.load offset=512
          local.tee 6
          local.get 4
          i64.add
          local.tee 1
          local.get 6
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.add
          local.tee 12
          i64.add
          local.tee 4
          local.get 5
          i64.load offset=480
          local.tee 7
          local.get 7
          i64.add
          local.tee 38
          i64.add
          local.tee 8
          local.get 5
          i64.load offset=496
          local.tee 9
          local.get 9
          i64.add
          local.tee 39
          i64.add
          local.tee 6
          local.get 8
          i64.lt_u
          local.tee 13
          local.get 5
          i32.const 560
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.get 12
          local.get 11
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 4
          local.get 10
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 5
          i32.const 480
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.tee 10
          local.get 10
          i64.add
          local.get 38
          local.get 7
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.add
          local.get 8
          local.get 4
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.tee 4
          local.get 3
          local.get 3
          i64.add
          local.get 39
          local.get 9
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.add
          local.get 13
          i64.extend_i32_u
          i64.add
          local.tee 3
          local.get 4
          i64.lt_u
          local.get 3
          local.get 4
          i64.eq
          select
          i32.or
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65552
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 17
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        block  ;; label = @3
          local.get 2
          local.get 32
          i64.add
          local.tee 12
          local.get 2
          i64.ge_u
          local.get 1
          local.get 31
          i64.add
          local.get 12
          local.get 2
          i64.lt_u
          local.tee 13
          i64.extend_i32_u
          i64.add
          local.tee 2
          local.get 1
          i64.ge_u
          local.get 2
          local.get 1
          i64.eq
          local.tee 40
          select
          local.get 6
          local.get 30
          i64.add
          local.tee 7
          local.get 13
          local.get 2
          local.get 1
          i64.lt_u
          local.get 40
          select
          i64.extend_i32_u
          i64.add
          local.tee 4
          local.get 6
          i64.ge_u
          local.get 3
          local.get 33
          i64.add
          local.get 7
          local.get 6
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 4
          local.get 7
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.tee 1
          local.get 3
          i64.ge_u
          local.get 1
          local.get 3
          i64.eq
          select
          local.get 4
          local.get 6
          i64.xor
          local.get 1
          local.get 3
          i64.xor
          i64.or
          i64.eqz
          select
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65552
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 17
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        i32.const 65616
        local.get 5
        i32.const 736
        i32.add
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 5
          i64.load offset=736
          local.tee 41
          local.get 16
          i64.load
          local.tee 42
          i64.or
          local.get 5
          i32.const 736
          i32.add
          i32.const 8
          i32.add
          local.tee 43
          i64.load
          local.tee 44
          local.get 14
          i64.load
          local.tee 45
          i64.or
          i64.or
          local.tee 3
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65648
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 18
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        i64.const 0
        local.get 1
        local.get 3
        i64.eqz
        local.get 12
        local.get 4
        i64.or
        local.get 2
        local.get 1
        i64.or
        i64.or
        i64.eqz
        i32.or
        i64.const 0
        local.get 45
        i64.clz
        local.get 42
        i64.clz
        i64.const 64
        i64.add
        local.get 45
        i64.const 0
        i64.ne
        select
        local.get 44
        i64.clz
        local.get 41
        i64.clz
        i64.const 64
        i64.add
        local.get 44
        i64.const 0
        i64.ne
        select
        local.tee 3
        i64.const 128
        i64.add
        local.tee 6
        local.get 42
        local.get 45
        i64.or
        i64.const 0
        i64.ne
        local.tee 13
        select
        local.tee 7
        local.get 1
        i64.clz
        local.get 4
        i64.clz
        i64.const 64
        i64.add
        local.get 1
        i64.const 0
        i64.ne
        select
        local.get 2
        i64.clz
        local.get 12
        i64.clz
        i64.const 64
        i64.add
        local.get 2
        i64.const 0
        i64.ne
        select
        local.tee 8
        i64.const 128
        i64.add
        local.tee 9
        local.get 4
        local.get 1
        i64.or
        i64.const 0
        i64.ne
        local.tee 40
        select
        local.tee 10
        i64.lt_u
        local.tee 46
        i64.const 0
        local.get 6
        local.get 3
        i64.lt_u
        i64.extend_i32_u
        local.get 13
        select
        local.tee 3
        i64.const 0
        local.get 9
        local.get 8
        i64.lt_u
        i64.extend_i32_u
        local.get 40
        select
        local.tee 6
        i64.lt_u
        local.get 3
        local.get 6
        i64.eq
        select
        local.tee 13
        i64.extend_i32_u
        i64.sub
        local.tee 47
        i64.const 0
        i64.ne
        i64.const 0
        local.get 13
        i32.const 0
        i32.ne
        i64.extend_i32_u
        i64.sub
        local.tee 39
        i64.const 0
        i64.ne
        local.get 39
        i64.eqz
        select
        local.get 7
        local.get 10
        i64.sub
        local.tee 38
        i64.const 255
        i64.gt_u
        local.get 3
        local.get 6
        i64.sub
        local.get 46
        i64.extend_i32_u
        i64.sub
        local.tee 11
        i64.const 0
        i64.ne
        local.get 11
        i64.eqz
        select
        local.get 13
        select
        i32.or
        local.tee 13
        select
        local.set 15
        i64.const 0
        local.get 4
        local.get 13
        select
        local.set 17
        i64.const 0
        local.get 2
        local.get 13
        select
        local.set 18
        i64.const 0
        local.get 12
        local.get 13
        select
        local.set 19
        block  ;; label = @3
          local.get 13
          br_if 0 (;@3;)
          local.get 38
          i64.const 255
          i64.xor
          local.get 47
          i64.or
          local.get 11
          local.get 39
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.const 384
          i32.add
          i32.const 40
          i32.add
          local.get 2
          i64.store align=1
          local.get 5
          i32.const 384
          i32.add
          i32.const 32
          i32.add
          local.tee 13
          local.get 12
          i64.store align=1
          i64.const 0
          local.set 48
          local.get 5
          i32.const 384
          i32.add
          i32.const 24
          i32.add
          i64.const 0
          i64.store align=1
          local.get 5
          i32.const 384
          i32.add
          i32.const 48
          i32.add
          local.get 4
          i64.store align=1
          local.get 5
          i32.const 384
          i32.add
          i32.const 56
          i32.add
          local.get 1
          i64.store align=1
          local.get 5
          i64.const 0
          i64.store offset=400 align=1
          local.get 5
          i64.const 0
          i64.store offset=392 align=1
          local.get 5
          i64.const 0
          i64.store offset=384 align=1
          local.get 13
          i32.const 255
          local.get 38
          i32.wrap_i64
          i32.sub
          local.tee 40
          i32.const 3
          i32.shr_u
          i32.const 31
          i32.and
          i32.sub
          local.tee 13
          i32.const 8
          i32.add
          i64.load align=1
          local.tee 6
          local.get 40
          i32.const 7
          i32.and
          local.tee 40
          i64.extend_i32_u
          local.tee 3
          i64.shl
          local.get 13
          i64.load align=1
          local.tee 9
          i64.const 1
          i64.shr_u
          local.get 40
          i32.const 63
          i32.xor
          i64.extend_i32_u
          local.tee 8
          i64.shr_u
          i64.or
          local.set 7
          local.get 13
          i32.const 24
          i32.add
          i64.load align=1
          local.get 3
          i64.shl
          local.get 13
          i32.const 16
          i32.add
          i64.load align=1
          local.tee 18
          i64.const 1
          i64.shr_u
          local.get 8
          i64.shr_u
          i64.or
          local.set 10
          local.get 18
          local.get 3
          i64.shl
          local.get 6
          i64.const 1
          i64.shr_u
          local.get 40
          i32.const -1
          i32.xor
          i32.const 63
          i32.and
          i64.extend_i32_u
          i64.shr_u
          i64.or
          local.set 8
          local.get 9
          local.get 3
          i64.shl
          local.set 9
          block  ;; label = @4
            block  ;; label = @5
              local.get 38
              i64.const 1
              i64.add
              local.tee 6
              local.get 47
              local.get 6
              local.get 38
              i64.lt_u
              local.tee 13
              local.get 11
              local.get 13
              i64.extend_i32_u
              i64.add
              local.tee 3
              local.get 11
              i64.lt_u
              local.get 6
              local.get 38
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 11
              i64.or
              local.get 3
              local.get 39
              local.get 11
              local.get 47
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.tee 19
              i64.or
              i64.or
              i64.eqz
              br_if 0 (;@5;)
              i64.const 0
              local.set 15
              local.get 5
              i32.const 320
              i32.add
              i32.const 56
              i32.add
              i64.const 0
              i64.store align=1
              local.get 5
              i32.const 320
              i32.add
              i32.const 48
              i32.add
              i64.const 0
              i64.store align=1
              local.get 5
              i32.const 320
              i32.add
              i32.const 40
              i32.add
              i64.const 0
              i64.store align=1
              local.get 5
              i32.const 320
              i32.add
              i32.const 24
              i32.add
              local.get 1
              i64.store align=1
              local.get 5
              i64.const 0
              i64.store offset=352 align=1
              local.get 5
              local.get 12
              i64.store offset=320 align=1
              local.get 5
              local.get 2
              i64.store offset=328 align=1
              local.get 5
              local.get 4
              i64.store offset=336 align=1
              local.get 5
              i32.const 320
              i32.add
              local.get 6
              i32.wrap_i64
              local.tee 40
              i32.const 3
              i32.shr_u
              i32.const 31
              i32.and
              i32.add
              local.tee 13
              i32.const 16
              i32.add
              i64.load align=1
              local.tee 2
              local.get 6
              i64.const 7
              i64.and
              local.tee 1
              i64.shr_u
              local.get 13
              i32.const 24
              i32.add
              i64.load align=1
              local.tee 4
              i64.const 1
              i64.shl
              local.get 40
              i32.const 7
              i32.and
              local.tee 40
              i32.const 63
              i32.xor
              i64.extend_i32_u
              local.tee 39
              i64.shl
              i64.or
              local.set 12
              local.get 13
              i32.const 8
              i32.add
              i64.load align=1
              local.tee 47
              local.get 1
              i64.shr_u
              local.get 2
              i64.const 1
              i64.shl
              local.get 40
              i32.const -1
              i32.xor
              i32.const 63
              i32.and
              i64.extend_i32_u
              i64.shl
              i64.or
              local.set 38
              local.get 13
              i64.load align=1
              local.get 1
              i64.shr_u
              local.get 47
              i64.const 1
              i64.shl
              local.get 39
              i64.shl
              i64.or
              local.set 39
              local.get 45
              local.get 42
              i64.const -1
              i64.add
              local.tee 2
              local.get 42
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.get 2
              local.get 41
              i64.const -1
              i64.add
              local.tee 49
              local.get 41
              i64.lt_u
              local.tee 13
              local.get 44
              local.get 13
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.tee 18
              local.get 44
              i64.lt_u
              local.get 18
              local.get 44
              i64.eq
              select
              i64.extend_i32_u
              i64.add
              local.tee 50
              local.get 2
              i64.lt_u
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.set 51
              local.get 4
              local.get 1
              i64.shr_u
              local.set 52
              i64.const 0
              local.set 53
              loop  ;; label = @6
                local.get 12
                i64.const 1
                i64.shl
                local.get 38
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 4
                local.get 51
                local.get 52
                i64.const 1
                i64.shl
                local.get 12
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 52
                i64.sub
                local.get 50
                local.get 4
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.get 50
                local.get 4
                i64.sub
                local.get 49
                local.get 39
                i64.const 1
                i64.shl
                local.get 10
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 47
                i64.lt_u
                local.get 18
                local.get 38
                i64.const 1
                i64.shl
                local.get 39
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 1
                i64.lt_u
                local.get 18
                local.get 1
                i64.eq
                select
                i64.extend_i32_u
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                i64.const 63
                i64.shr_s
                local.tee 2
                local.get 42
                i64.and
                local.tee 39
                i64.sub
                local.tee 54
                local.get 47
                local.get 2
                local.get 41
                i64.and
                local.tee 55
                i64.lt_u
                local.tee 13
                local.get 1
                local.get 2
                local.get 44
                i64.and
                local.tee 38
                i64.lt_u
                local.get 1
                local.get 38
                i64.eq
                select
                i64.extend_i32_u
                local.tee 48
                i64.sub
                local.set 12
                local.get 52
                local.get 2
                local.get 45
                i64.and
                i64.sub
                local.get 4
                local.get 39
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.get 54
                local.get 48
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.set 52
                local.get 1
                local.get 38
                i64.sub
                local.get 13
                i64.extend_i32_u
                i64.sub
                local.set 38
                local.get 47
                local.get 55
                i64.sub
                local.set 39
                local.get 3
                local.get 6
                i64.const -1
                i64.add
                local.tee 4
                local.get 6
                i64.lt_u
                local.tee 13
                i64.extend_i32_u
                i64.add
                i64.const -1
                i64.add
                local.tee 1
                local.get 3
                i64.eq
                local.set 40
                local.get 1
                local.get 3
                i64.lt_u
                local.set 46
                local.get 11
                i64.const -1
                i64.add
                local.tee 47
                local.get 11
                i64.lt_u
                local.set 56
                local.get 9
                i64.const 63
                i64.shr_u
                local.set 54
                local.get 7
                i64.const 63
                i64.shr_u
                local.set 55
                i64.const 0
                local.get 10
                i64.const 1
                i64.shl
                local.get 8
                i64.const 63
                i64.shr_u
                i64.or
                i64.or
                local.set 10
                local.get 53
                local.get 9
                i64.const 1
                i64.shl
                i64.or
                local.set 9
                local.get 2
                i64.const 1
                i64.and
                local.tee 48
                local.set 53
                local.get 4
                local.set 6
                local.get 1
                local.set 3
                local.get 47
                local.get 13
                local.get 46
                local.get 40
                select
                i64.extend_i32_u
                i64.add
                local.tee 2
                local.set 11
                i64.const 0
                local.get 54
                local.get 7
                i64.const 1
                i64.shl
                i64.or
                i64.or
                local.tee 54
                local.set 7
                i64.const 0
                local.get 55
                local.get 8
                i64.const 1
                i64.shl
                i64.or
                i64.or
                local.tee 55
                local.set 8
                local.get 4
                local.get 2
                i64.or
                local.get 1
                local.get 19
                local.get 56
                i64.extend_i32_u
                i64.add
                local.get 2
                local.get 47
                i64.lt_u
                i64.extend_i32_u
                i64.add
                i64.const -1
                i64.add
                local.tee 19
                i64.or
                i64.or
                i64.eqz
                i32.eqz
                br_if 0 (;@6;)
              end
              i64.const 0
              local.set 1
              i64.const 0
              local.set 2
              local.get 54
              local.set 7
              local.get 55
              local.set 8
              br 1 (;@4;)
            end
            i64.const 0
            local.set 15
            i64.const 0
            local.set 1
            i64.const 0
            local.set 2
          end
          local.get 15
          local.get 7
          i64.const 1
          i64.shl
          local.get 9
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 18
          local.get 1
          local.get 8
          i64.const 1
          i64.shl
          local.get 7
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 17
          local.get 2
          local.get 10
          i64.const 1
          i64.shl
          local.get 8
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 15
          local.get 48
          local.get 9
          i64.const 1
          i64.shl
          i64.or
          local.set 19
        end
        block  ;; label = @3
          local.get 24
          i64.const 1
          i64.and
          i64.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.const 272
          i32.add
          local.get 23
          i64.const 0
          local.get 19
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 256
          i32.add
          local.get 22
          i64.const 0
          local.get 19
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 288
          i32.add
          local.get 23
          i64.const 0
          local.get 18
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 304
          i32.add
          local.get 22
          i64.const 0
          local.get 18
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 192
          i32.add
          local.get 19
          local.get 18
          i64.const 0
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 208
          i32.add
          local.get 23
          local.get 22
          i64.const 0
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 144
          i32.add
          local.get 22
          i64.const 0
          local.get 17
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 176
          i32.add
          local.get 15
          i64.const 0
          local.get 23
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 240
          i32.add
          local.get 17
          i64.const 0
          local.get 23
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 128
          i32.add
          local.get 18
          i64.const 0
          local.get 21
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 160
          i32.add
          local.get 20
          i64.const 0
          local.get 19
          i64.const 0
          call $__multi3
          local.get 5
          i32.const 224
          i32.add
          local.get 21
          i64.const 0
          local.get 19
          i64.const 0
          call $__multi3
          local.get 5
          i64.load offset=272
          local.set 2
          block  ;; label = @4
            local.get 21
            local.get 20
            i64.or
            i64.const 0
            i64.ne
            local.get 17
            local.get 15
            i64.or
            i64.const 0
            i64.ne
            i32.and
            local.get 20
            i64.const 0
            i64.ne
            local.get 18
            i64.const 0
            i64.ne
            i32.and
            local.get 5
            i64.load offset=168
            i64.const 0
            i64.ne
            i32.or
            local.get 5
            i64.load offset=136
            i64.const 0
            i64.ne
            i32.or
            local.get 5
            i32.const 224
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.tee 1
            local.get 5
            i64.load offset=160
            local.get 5
            i64.load offset=128
            i64.add
            i64.add
            local.tee 7
            local.get 1
            i64.lt_u
            i32.or
            i32.or
            local.get 15
            i64.const 0
            i64.ne
            local.get 22
            i64.const 0
            i64.ne
            i32.and
            local.get 5
            i64.load offset=184
            i64.const 0
            i64.ne
            i32.or
            local.get 5
            i64.load offset=152
            i64.const 0
            i64.ne
            i32.or
            local.get 5
            i32.const 240
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.tee 1
            local.get 5
            i64.load offset=176
            local.get 5
            i64.load offset=144
            i64.add
            i64.add
            local.tee 8
            local.get 1
            i64.lt_u
            i32.or
            i32.or
            local.get 5
            i64.load offset=304
            local.tee 9
            local.get 5
            i32.const 256
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.get 5
            i64.load offset=256
            local.tee 1
            local.get 5
            i32.const 272
            i32.add
            i32.const 8
            i32.add
            i64.load
            i64.add
            local.tee 3
            local.get 1
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.tee 10
            local.get 5
            i32.const 288
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.get 5
            i64.load offset=288
            local.tee 4
            local.get 3
            i64.add
            local.tee 1
            local.get 4
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.add
            local.tee 11
            i64.add
            local.tee 3
            local.get 5
            i64.load offset=208
            local.tee 12
            local.get 5
            i64.load offset=192
            i64.add
            local.tee 38
            i64.add
            local.tee 4
            local.get 5
            i64.load offset=224
            local.tee 39
            local.get 5
            i64.load offset=240
            i64.add
            local.tee 47
            i64.add
            local.tee 6
            local.get 4
            i64.lt_u
            local.tee 13
            local.get 5
            i32.const 304
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.get 11
            local.get 10
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.get 3
            local.get 9
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.get 5
            i32.const 208
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.get 5
            i32.const 192
            i32.add
            i32.const 8
            i32.add
            i64.load
            i64.add
            local.get 38
            local.get 12
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.add
            local.get 4
            local.get 3
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.tee 4
            local.get 7
            local.get 8
            i64.add
            local.get 47
            local.get 39
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.add
            local.get 13
            i64.extend_i32_u
            i64.add
            local.tee 3
            local.get 4
            i64.lt_u
            local.get 3
            local.get 4
            i64.eq
            select
            i32.or
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            i32.const 65552
            call $wrapper_mstore_bytes32
            i32.const 4
            i32.const 17
            call $wrapper_mstore_u32
            i32.const 0
            i32.const 36
            call $wrapper_revert
          end
          block  ;; label = @4
            local.get 2
            local.get 32
            i64.add
            local.tee 12
            local.get 2
            i64.ge_u
            local.get 1
            local.get 31
            i64.add
            local.get 12
            local.get 2
            i64.lt_u
            local.tee 13
            i64.extend_i32_u
            i64.add
            local.tee 2
            local.get 1
            i64.ge_u
            local.get 2
            local.get 1
            i64.eq
            local.tee 40
            select
            local.get 6
            local.get 30
            i64.add
            local.tee 7
            local.get 13
            local.get 2
            local.get 1
            i64.lt_u
            local.get 40
            select
            i64.extend_i32_u
            i64.add
            local.tee 4
            local.get 6
            i64.ge_u
            local.get 3
            local.get 33
            i64.add
            local.get 7
            local.get 6
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.get 4
            local.get 7
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.tee 1
            local.get 3
            i64.ge_u
            local.get 1
            local.get 3
            i64.eq
            select
            local.get 4
            local.get 6
            i64.xor
            local.get 1
            local.get 3
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
            i32.const 0
            i32.const 65552
            call $wrapper_mstore_bytes32
            i32.const 4
            i32.const 17
            call $wrapper_mstore_u32
            i32.const 0
            i32.const 36
            call $wrapper_revert
          end
          i32.const 65616
          local.get 5
          i32.const 736
          i32.add
          call $u256_from_big_endian_bytes
          block  ;; label = @4
            local.get 5
            i64.load offset=736
            local.tee 51
            local.get 16
            i64.load
            local.tee 49
            i64.or
            local.get 43
            i64.load
            local.tee 41
            local.get 14
            i64.load
            local.tee 42
            i64.or
            i64.or
            local.tee 3
            i64.const 0
            i64.ne
            br_if 0 (;@4;)
            i32.const 0
            i32.const 65648
            call $wrapper_mstore_bytes32
            i32.const 4
            i32.const 18
            call $wrapper_mstore_u32
            i32.const 0
            i32.const 36
            call $wrapper_revert
          end
          i64.const 0
          local.get 1
          local.get 3
          i64.eqz
          local.get 12
          local.get 4
          i64.or
          local.get 2
          local.get 1
          i64.or
          i64.or
          i64.eqz
          i32.or
          i64.const 0
          local.get 42
          i64.clz
          local.get 49
          i64.clz
          i64.const 64
          i64.add
          local.get 42
          i64.const 0
          i64.ne
          select
          local.get 41
          i64.clz
          local.get 51
          i64.clz
          i64.const 64
          i64.add
          local.get 41
          i64.const 0
          i64.ne
          select
          local.tee 3
          i64.const 128
          i64.add
          local.tee 6
          local.get 49
          local.get 42
          i64.or
          i64.const 0
          i64.ne
          local.tee 13
          select
          local.tee 7
          local.get 1
          i64.clz
          local.get 4
          i64.clz
          i64.const 64
          i64.add
          local.get 1
          i64.const 0
          i64.ne
          select
          local.get 2
          i64.clz
          local.get 12
          i64.clz
          i64.const 64
          i64.add
          local.get 2
          i64.const 0
          i64.ne
          select
          local.tee 8
          i64.const 128
          i64.add
          local.tee 9
          local.get 4
          local.get 1
          i64.or
          i64.const 0
          i64.ne
          local.tee 40
          select
          local.tee 10
          i64.lt_u
          local.tee 46
          i64.const 0
          local.get 6
          local.get 3
          i64.lt_u
          i64.extend_i32_u
          local.get 13
          select
          local.tee 3
          i64.const 0
          local.get 9
          local.get 8
          i64.lt_u
          i64.extend_i32_u
          local.get 40
          select
          local.tee 6
          i64.lt_u
          local.get 3
          local.get 6
          i64.eq
          select
          local.tee 13
          i64.extend_i32_u
          i64.sub
          local.tee 47
          i64.const 0
          i64.ne
          i64.const 0
          local.get 13
          i32.const 0
          i32.ne
          i64.extend_i32_u
          i64.sub
          local.tee 39
          i64.const 0
          i64.ne
          local.get 39
          i64.eqz
          select
          local.get 7
          local.get 10
          i64.sub
          local.tee 38
          i64.const 255
          i64.gt_u
          local.get 3
          local.get 6
          i64.sub
          local.get 46
          i64.extend_i32_u
          i64.sub
          local.tee 11
          i64.const 0
          i64.ne
          local.get 11
          i64.eqz
          select
          local.get 13
          select
          i32.or
          local.tee 13
          select
          local.set 20
          i64.const 0
          local.get 4
          local.get 13
          select
          local.set 21
          i64.const 0
          local.get 2
          local.get 13
          select
          local.set 22
          i64.const 0
          local.get 12
          local.get 13
          select
          local.set 23
          local.get 13
          br_if 0 (;@3;)
          local.get 38
          i64.const 255
          i64.xor
          local.get 47
          i64.or
          local.get 11
          local.get 39
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          local.get 34
          local.get 2
          i64.store align=1
          local.get 35
          local.get 12
          i64.store align=1
          i64.const 0
          local.set 44
          local.get 5
          i32.const 64
          i32.add
          i32.const 24
          i32.add
          i64.const 0
          i64.store align=1
          local.get 36
          local.get 4
          i64.store align=1
          local.get 37
          local.get 1
          i64.store align=1
          local.get 5
          i64.const 0
          i64.store offset=80 align=1
          local.get 5
          i64.const 0
          i64.store offset=72 align=1
          local.get 5
          i64.const 0
          i64.store offset=64 align=1
          local.get 35
          i32.const 255
          local.get 38
          i32.wrap_i64
          i32.sub
          local.tee 40
          i32.const 3
          i32.shr_u
          i32.const 31
          i32.and
          i32.sub
          local.tee 13
          i32.const 8
          i32.add
          i64.load align=1
          local.tee 6
          local.get 40
          i32.const 7
          i32.and
          local.tee 40
          i64.extend_i32_u
          local.tee 3
          i64.shl
          local.get 13
          i64.load align=1
          local.tee 9
          i64.const 1
          i64.shr_u
          local.get 40
          i32.const 63
          i32.xor
          i64.extend_i32_u
          local.tee 8
          i64.shr_u
          i64.or
          local.set 7
          local.get 13
          i32.const 24
          i32.add
          i64.load align=1
          local.get 3
          i64.shl
          local.get 13
          i32.const 16
          i32.add
          i64.load align=1
          local.tee 50
          i64.const 1
          i64.shr_u
          local.get 8
          i64.shr_u
          i64.or
          local.set 10
          local.get 50
          local.get 3
          i64.shl
          local.get 6
          i64.const 1
          i64.shr_u
          local.get 40
          i32.const -1
          i32.xor
          i32.const 63
          i32.and
          i64.extend_i32_u
          i64.shr_u
          i64.or
          local.set 8
          local.get 9
          local.get 3
          i64.shl
          local.set 9
          block  ;; label = @4
            block  ;; label = @5
              local.get 38
              i64.const 1
              i64.add
              local.tee 6
              local.get 47
              local.get 6
              local.get 38
              i64.lt_u
              local.tee 13
              local.get 11
              local.get 13
              i64.extend_i32_u
              i64.add
              local.tee 3
              local.get 11
              i64.lt_u
              local.get 6
              local.get 38
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 11
              i64.or
              local.get 3
              local.get 39
              local.get 11
              local.get 47
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.tee 52
              i64.or
              i64.or
              i64.eqz
              br_if 0 (;@5;)
              i64.const 0
              local.set 20
              local.get 5
              i32.const 56
              i32.add
              i64.const 0
              i64.store align=1
              local.get 5
              i32.const 48
              i32.add
              i64.const 0
              i64.store align=1
              local.get 5
              i32.const 40
              i32.add
              i64.const 0
              i64.store align=1
              local.get 5
              i32.const 24
              i32.add
              local.get 1
              i64.store align=1
              local.get 5
              i64.const 0
              i64.store offset=32 align=1
              local.get 5
              local.get 12
              i64.store align=1
              local.get 5
              local.get 2
              i64.store offset=8 align=1
              local.get 5
              local.get 4
              i64.store offset=16 align=1
              local.get 5
              local.get 6
              i32.wrap_i64
              local.tee 40
              i32.const 3
              i32.shr_u
              i32.const 31
              i32.and
              i32.add
              local.tee 13
              i32.const 16
              i32.add
              i64.load align=1
              local.tee 2
              local.get 6
              i64.const 7
              i64.and
              local.tee 1
              i64.shr_u
              local.get 13
              i32.const 24
              i32.add
              i64.load align=1
              local.tee 4
              i64.const 1
              i64.shl
              local.get 40
              i32.const 7
              i32.and
              local.tee 40
              i32.const 63
              i32.xor
              i64.extend_i32_u
              local.tee 39
              i64.shl
              i64.or
              local.set 12
              local.get 13
              i32.const 8
              i32.add
              i64.load align=1
              local.tee 47
              local.get 1
              i64.shr_u
              local.get 2
              i64.const 1
              i64.shl
              local.get 40
              i32.const -1
              i32.xor
              i32.const 63
              i32.and
              i64.extend_i32_u
              i64.shl
              i64.or
              local.set 38
              local.get 13
              i64.load align=1
              local.get 1
              i64.shr_u
              local.get 47
              i64.const 1
              i64.shl
              local.get 39
              i64.shl
              i64.or
              local.set 39
              local.get 42
              local.get 49
              i64.const -1
              i64.add
              local.tee 2
              local.get 49
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.get 2
              local.get 51
              i64.const -1
              i64.add
              local.tee 22
              local.get 51
              i64.lt_u
              local.tee 13
              local.get 41
              local.get 13
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.tee 50
              local.get 41
              i64.lt_u
              local.get 50
              local.get 41
              i64.eq
              select
              i64.extend_i32_u
              i64.add
              local.tee 53
              local.get 2
              i64.lt_u
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.set 23
              local.get 4
              local.get 1
              i64.shr_u
              local.set 54
              i64.const 0
              local.set 55
              loop  ;; label = @6
                local.get 12
                i64.const 1
                i64.shl
                local.get 38
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 4
                local.get 23
                local.get 54
                i64.const 1
                i64.shl
                local.get 12
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 54
                i64.sub
                local.get 53
                local.get 4
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.get 53
                local.get 4
                i64.sub
                local.get 22
                local.get 39
                i64.const 1
                i64.shl
                local.get 10
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 47
                i64.lt_u
                local.get 50
                local.get 38
                i64.const 1
                i64.shl
                local.get 39
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 1
                i64.lt_u
                local.get 50
                local.get 1
                i64.eq
                select
                i64.extend_i32_u
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                i64.const 63
                i64.shr_s
                local.tee 2
                local.get 49
                i64.and
                local.tee 39
                i64.sub
                local.tee 48
                local.get 47
                local.get 2
                local.get 51
                i64.and
                local.tee 45
                i64.lt_u
                local.tee 13
                local.get 1
                local.get 2
                local.get 41
                i64.and
                local.tee 38
                i64.lt_u
                local.get 1
                local.get 38
                i64.eq
                select
                i64.extend_i32_u
                local.tee 44
                i64.sub
                local.set 12
                local.get 54
                local.get 2
                local.get 42
                i64.and
                i64.sub
                local.get 4
                local.get 39
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.get 48
                local.get 44
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.set 54
                local.get 1
                local.get 38
                i64.sub
                local.get 13
                i64.extend_i32_u
                i64.sub
                local.set 38
                local.get 47
                local.get 45
                i64.sub
                local.set 39
                local.get 3
                local.get 6
                i64.const -1
                i64.add
                local.tee 4
                local.get 6
                i64.lt_u
                local.tee 13
                i64.extend_i32_u
                i64.add
                i64.const -1
                i64.add
                local.tee 1
                local.get 3
                i64.eq
                local.set 40
                local.get 1
                local.get 3
                i64.lt_u
                local.set 46
                local.get 11
                i64.const -1
                i64.add
                local.tee 47
                local.get 11
                i64.lt_u
                local.set 56
                local.get 9
                i64.const 63
                i64.shr_u
                local.set 48
                local.get 7
                i64.const 63
                i64.shr_u
                local.set 45
                i64.const 0
                local.get 10
                i64.const 1
                i64.shl
                local.get 8
                i64.const 63
                i64.shr_u
                i64.or
                i64.or
                local.set 10
                local.get 55
                local.get 9
                i64.const 1
                i64.shl
                i64.or
                local.set 9
                local.get 2
                i64.const 1
                i64.and
                local.tee 44
                local.set 55
                local.get 4
                local.set 6
                local.get 1
                local.set 3
                local.get 47
                local.get 13
                local.get 46
                local.get 40
                select
                i64.extend_i32_u
                i64.add
                local.tee 2
                local.set 11
                i64.const 0
                local.get 48
                local.get 7
                i64.const 1
                i64.shl
                i64.or
                i64.or
                local.tee 48
                local.set 7
                i64.const 0
                local.get 45
                local.get 8
                i64.const 1
                i64.shl
                i64.or
                i64.or
                local.tee 45
                local.set 8
                local.get 4
                local.get 2
                i64.or
                local.get 1
                local.get 52
                local.get 56
                i64.extend_i32_u
                i64.add
                local.get 2
                local.get 47
                i64.lt_u
                i64.extend_i32_u
                i64.add
                i64.const -1
                i64.add
                local.tee 52
                i64.or
                i64.or
                i64.eqz
                i32.eqz
                br_if 0 (;@6;)
              end
              i64.const 0
              local.set 1
              i64.const 0
              local.set 2
              local.get 48
              local.set 7
              local.get 45
              local.set 8
              br 1 (;@4;)
            end
            i64.const 0
            local.set 20
            i64.const 0
            local.set 1
            i64.const 0
            local.set 2
          end
          local.get 20
          local.get 7
          i64.const 1
          i64.shl
          local.get 9
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 22
          local.get 1
          local.get 8
          i64.const 1
          i64.shl
          local.get 7
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 21
          local.get 2
          local.get 10
          i64.const 1
          i64.shl
          local.get 8
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 20
          local.get 44
          local.get 9
          i64.const 1
          i64.shl
          i64.or
          local.set 23
        end
        local.get 14
        local.get 29
        i64.store
        local.get 5
        local.get 24
        i64.store offset=736
        local.get 5
        local.get 27
        i64.store offset=744
        local.get 5
        local.get 26
        i64.store offset=752
        local.get 5
        i32.const 736
        i32.add
        i32.const 1
        local.get 5
        i32.const 704
        i32.add
        call $wrapper_u256_shr
        local.get 5
        i64.load offset=704
        local.tee 24
        local.get 25
        i64.load
        local.tee 26
        i64.or
        local.get 5
        i32.const 704
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 27
        local.get 28
        i64.load
        local.tee 29
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
      end
    end
    local.get 0
    local.get 23
    i64.store
    local.get 0
    local.get 22
    i64.store offset=8
    local.get 0
    local.get 21
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 20
    i64.store
    local.get 5
    i32.const 768
    i32.add
    global.set $__stack_pointer)
  (func $RpowPilot_88_deployed.RpowPilot_88_deployed.init (type 4)
    (local i32 i64 i64 i64 i64 i32)
    global.get $__stack_pointer
    i32.const 128
    i32.sub
    local.tee 0
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
      i32.const 0
      local.get 0
      i32.const 32
      i32.add
      call $wrapper_calldataload_bytes32
      local.get 0
      i32.const 32
      i32.add
      local.get 0
      i32.const 96
      i32.add
      call $u256_from_big_endian_bytes
      local.get 0
      i32.const 96
      i32.add
      i32.const 224
      local.get 0
      i32.const 64
      i32.add
      call $wrapper_u256_shr
      local.get 0
      i64.load offset=64
      i64.const 1249760547
      i64.xor
      local.get 0
      i32.const 80
      i32.add
      i64.load
      i64.or
      local.get 0
      i32.const 72
      i32.add
      i64.load
      local.get 0
      i32.const 88
      i32.add
      i64.load
      i64.or
      i64.or
      i64.eqz
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        call $wrapper_callvalue_not_zero
        i32.eqz
        br_if 0 (;@2;)
        i32.const 0
        i32.const 0
        call $wrapper_revert
      end
      block  ;; label = @2
        call $wrapper_calldata_size
        i32.const 35
        i32.gt_u
        br_if 0 (;@2;)
        i32.const 0
        i32.const 0
        call $wrapper_revert
      end
      i32.const 4
      local.get 0
      i32.const 96
      i32.add
      call $wrapper_calldataload_bytes32
      local.get 0
      i32.const 96
      i32.add
      local.get 0
      i32.const 64
      i32.add
      call $u256_from_big_endian_bytes
      local.get 0
      local.get 0
      i64.load offset=64
      local.get 0
      i32.const 64
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 0
      i32.const 64
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.get 0
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      i64.load
      call $RpowPilot_88_deployed.RpowPilot_88_deployed.fun_generate_87
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 1
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 2
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 3
      local.get 0
      i64.load
      local.set 4
      i32.const 64
      local.get 0
      i32.const 96
      i32.add
      call $wrapper_mload_u256
      local.get 0
      i32.load offset=96
      local.set 5
      local.get 0
      i32.const 96
      i32.add
      i32.const 24
      i32.add
      local.get 3
      i64.store
      local.get 0
      local.get 2
      i64.store offset=112
      local.get 0
      local.get 1
      i64.store offset=104
      local.get 0
      local.get 4
      i64.store offset=96
      local.get 5
      local.get 0
      i32.const 96
      i32.add
      call $wrapper_mstore_u256
      local.get 5
      i32.const 32
      call $wrapper_return
    end
    i32.const 0
    i32.const 0
    call $wrapper_revert
    local.get 0
    i32.const 128
    i32.add
    global.set $__stack_pointer)
  (func $call (type 4)
    call $RpowPilot_88_deployed.RpowPilot_88_deployed.init)
  (func $_start (type 4)
    i32.const 1
    call $__init_evm_heap)
  (func $deploy (type 4)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 0
    global.set $__stack_pointer
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
    i32.const 64
    local.get 0
    call $wrapper_mload_u256
    local.get 0
    i32.load
    local.tee 1
    i32.const 82208
    i32.const 0
    call $evm_get_memory_addr
    i32.sub
    i32.const 4
    call $wrapper_codecopy
    local.get 1
    i32.const 4
    call $wrapper_return
    local.get 0
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 3)
  (global $__stack_pointer (mut i32) (i32.const 65536))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "call" (func $call))
  (export "deploy" (func $deploy))
  (data $.data (i32.const 65536) "\ff\ff\ff\ff")
  (data (;1;) (i32.const 65552) "NH{q")
  (data (;2;) (i32.const 65604) "\03;.<\a8\87a\c9\9b\af\152")
  (data (;3;) (i32.const 65636) "\03;.<\9f\d0\80<\e8\00\00\00NH{q")
  (data (;4;) (i32.const 65800) "\01")
  (data (;5;) (i32.const 65806) "\02\00\00\00\03")
  (data (;6;) (i32.const 65818) "\01")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "producers" "\02\08language\01\03C99\00\0cprocessed-by\02\05clangV11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\0cUbuntu clang@16.0.6 (++20231112100510+7cbf1a259152-1~exp1~20231112100554.106)")
  (@custom "name" "\01\ce\04\1e\00\0fgetCallDataSize\01\0ccallDataCopy\02\0cgetCallValue\03\06revert\04\06finish\05\0bgetCodeSize\06\08codeCopy\07\11__wasm_call_ctors\08\08__multi3\09\1au256_from_big_endian_bytes\0a\1cwrapper_calldataload_bytes32\0b\15wrapper_calldata_size\0c\1awrapper_callvalue_not_zero\0d\0ewrapper_revert\0e\13evm_get_memory_addr\0f\10wrapper_codecopy\10\14wrapper_memory_guard\11\16wrapper_mstore_bytes32\12\13wrapper_mstore_u256\13\12wrapper_mstore_u32\14\12wrapper_mload_u256\15\0ewrapper_return\16\13set_is_deploying_tx\17\0f__init_evm_heap\18\10wrapper_u256_shr\19;RpowPilot_88_deployed.RpowPilot_88_deployed.fun_generate_87\1a0RpowPilot_88_deployed.RpowPilot_88_deployed.init\1b\04call\1c\06_start\1d\06deploy\07\12\01\00\0f__stack_pointer\09\08\01\00\05.data")
  (@custom ".debug_str" "y\00x\00low\00wasisdk://v12.0/build/compiler-rt\00du_int\00ti_int\00di_int\00long long int\00long long unsigned int\00uint64_t\00twords\00r\00all\00lower_mask\00high\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins/multi3.c\00b\00a\00__int128\00__multi3\00__mulddi3\00bits_in_dword_2\00clang version 11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\00")
  (@custom ".debug_line" "M\01\00\00\04\00\c2\00\00\00\01\01\01\fb\0e\0d\00\01\01\01\01\00\00\00\01\00\00\01wasisdk://v12.0/build/install/opt/wasi-sdk/share/wasi-sysroot/include/bits\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins\00\00alltypes.h\00\01\00\00int_types.h\00\02\00\00multi3.c\00\02\00\00\00\04\03\00\05\02\05\00\00\00\03'\01\05\03\0aD\05,-\05\18\06X\05\0c\06\03rX\05\0b\1eo\05&`\05\0c\06<\05#\06\03u \05\10\06\ac\05\1e\90\03i<\05\16\06\03\18J\05\1f\22\05\05\06X\03f \05\10\06\03\1cJ\05\22\03\13 \05\0f\03n \05\1f\92\05\05\06X\03a \05\11\06\03!J\05\0c\03\0e \05\03!\05\1f\03pX\05\0b\03yX\97\05\03\03\10 \02\04\00\01\01")
  (@custom ".debug_abbrev" "\01\11\01%\0e\13\05\03\0e\10\17\1b\0e\11\01\12\06\00\00\02$\00\03\0e>\0b\0b\0b\00\00\03\16\00I\13\03\0e:\0b;\0b\00\00\04.\01\03\0e:\0b;\0b'\19I\13 \0b\00\00\05\05\00\03\0e:\0b;\0bI\13\00\00\064\00\03\0e:\0b;\0bI\13\00\00\07\17\01\0b\0b:\0b;\0b\00\00\08\0d\00\03\0eI\13:\0b;\0b8\0b\00\00\09\13\01\0b\0b:\0b;\0b\00\00\0a&\00I\13\00\00\0b.\01\11\01\12\06@\18\97B\19\03\0e:\0b;\0b'\19I\13?\19\00\00\0c\05\00\02\17\03\0e:\0b;\0bI\13\00\00\0d4\00\02\17\03\0e:\0b;\0bI\13\00\00\0e\1d\011\13U\17X\0bY\0bW\0b\00\00\0f\05\001\13\00\00\104\00\02\171\13\00\00\114\00\1c\0d1\13\00\00\124\00\1c\0f1\13\00\00\00")
  (@custom ".debug_ranges" "\0f\00\00\00G\00\00\00H\00\00\00\5c\00\00\00b\00\00\00q\00\00\00\00\00\00\00\00\00\00\00")
  (@custom ".debug_loc" "\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\007\00\00\009\00\00\00\06\00\ed\02\02\9f\93\089\00\00\00G\00\00\00\06\00\ed\00\05\9f\93\08G\00\00\00H\00\00\00\0c\00\ed\00\05\9f\93\08\ed\02\02\9f\93\08H\00\00\00p\00\00\00\06\00\ed\00\05\9f\93\08p\00\00\00q\00\00\00\06\00\ed\02\02\9f\93\08q\00\00\00t\00\00\00\06\00\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00]\00\00\00`\00\00\00\08\00\93\08\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00<\00\00\00B\00\00\00\04\00\ed\02\02\9fQ\00\00\00Y\00\00\00\04\00\ed\02\02\9fY\00\00\00u\00\00\00\04\00\ed\00\03\9f\00\00\00\00\00\00\00\00")
  (@custom ".debug_info" "\b4\01\00\00\04\00\00\00\00\00\04\01\fd\00\00\00\0c\00\8a\00\00\00\00\00\00\00\08\00\00\00\05\00\00\00u\00\00\00\02`\00\00\00\05\04\038\00\00\00*\00\00\00\02&\03C\00\00\00d\00\00\00\01\aa\02M\00\00\00\07\08\04\e3\00\00\00\03\13\99\00\00\00\01\05\cf\00\00\00\03\13-\00\00\00\05\cd\00\00\00\03\13-\00\00\00\06t\00\00\00\03\14\ab\00\00\00\06\ed\00\00\00\03\15\0d\01\00\00\06z\00\00\00\03\16\12\01\00\00\06k\00\00\00\03\18-\00\00\00\00\03\a4\00\00\001\00\00\00\02O\02\d1\00\00\00\05\10\03\b6\00\00\00m\00\00\00\02]\07\10\02R\08v\00\00\00\99\00\00\00\02S\00\08r\00\00\00\d2\00\00\00\02\5c\00\09\10\02T\08\04\00\00\00-\00\00\00\02V\00\08\85\00\00\00\f0\00\00\00\02W\08\00\00\03\fb\00\00\008\00\00\00\02%\03\06\01\00\00e\00\00\00\01\91\02?\00\00\00\05\08\0a&\00\00\00\0a-\00\00\00\0b\05\00\00\00u\00\00\00\07\ed\03\00\00\00\00\9f\da\00\00\00\03(\99\00\00\00\0c\00\00\00\00\cf\00\00\00\03(\99\00\00\00\0c\14\00\00\00\cd\00\00\00\03(\99\00\00\00\0d(\00\00\00\00\00\00\00\03+\ab\00\00\00\0d\aa\00\00\00\02\00\00\00\03)\ab\00\00\00\0d\be\00\00\00t\00\00\00\03-\ab\00\00\00\0eJ\00\00\00\00\00\00\00\03.\0b\0fV\00\00\00\0fa\00\00\00\10<\00\00\00l\00\00\00\11 w\00\00\00\12\ff\ff\ff\ff\0f\82\00\00\00\10\d8\00\00\00\8d\00\00\00\00\00\00"))
