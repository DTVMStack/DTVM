(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32 i32)))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func))
  (type (;5;) (func (param i32 i64 i64 i64 i64)))
  (type (;6;) (func (param i32) (result i32)))
  (type (;7;) (func (param i32 i32) (result i32)))
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
  (func $u256_to_big_endian_bytes (type 3) (param i32 i32)
    (local i64 i64 i64 i64 i32)
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 3
    local.get 0
    i64.load
    local.set 4
    local.get 1
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.tee 5
    i64.const 40
    i64.shr_u
    i64.store8 offset=2
    local.get 1
    local.get 5
    i64.const 56
    i64.shr_u
    i64.store8
    local.get 1
    local.get 3
    i64.const 40
    i64.shr_u
    i64.store8 offset=10
    local.get 1
    local.get 3
    i64.const 56
    i64.shr_u
    i64.store8 offset=8
    local.get 1
    local.get 5
    i32.wrap_i64
    local.tee 0
    i32.store8 offset=7
    local.get 1
    local.get 5
    i64.const 32
    i64.shr_u
    i64.store8 offset=3
    local.get 1
    local.get 5
    i64.const 48
    i64.shr_u
    i64.store8 offset=1
    local.get 1
    local.get 2
    i64.const 40
    i64.shr_u
    i64.store8 offset=18
    local.get 1
    local.get 2
    i64.const 56
    i64.shr_u
    i64.store8 offset=16
    local.get 1
    local.get 3
    i32.wrap_i64
    local.tee 6
    i32.store8 offset=15
    local.get 1
    local.get 3
    i64.const 32
    i64.shr_u
    i64.store8 offset=11
    local.get 1
    local.get 3
    i64.const 48
    i64.shr_u
    i64.store8 offset=9
    local.get 1
    local.get 0
    i32.const 8
    i32.shr_u
    i32.store8 offset=6
    local.get 1
    local.get 0
    i32.const 24
    i32.shr_u
    i32.store8 offset=4
    local.get 1
    local.get 6
    i32.const 8
    i32.shr_u
    i32.store8 offset=14
    local.get 1
    local.get 6
    i32.const 24
    i32.shr_u
    i32.store8 offset=12
    local.get 1
    local.get 0
    i32.const 16
    i32.shr_u
    i32.store8 offset=5
    local.get 1
    local.get 2
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
    local.get 6
    i32.const 16
    i32.shr_u
    i32.store8 offset=13
    local.get 1
    local.get 4
    i32.wrap_i64
    local.tee 6
    i32.const 8
    i32.shr_u
    i32.store8 offset=30
    local.get 1
    local.get 6
    i32.const 24
    i32.shr_u
    i32.store8 offset=28
    local.get 1
    local.get 4
    i64.const 40
    i64.shr_u
    i64.store8 offset=26
    local.get 1
    local.get 4
    i64.const 56
    i64.shr_u
    i64.store8 offset=24
    local.get 1
    local.get 0
    i32.store8 offset=23
    local.get 1
    local.get 0
    i32.const 16
    i32.shr_u
    i32.store8 offset=21
    local.get 1
    local.get 2
    i64.const 32
    i64.shr_u
    i64.store8 offset=19
    local.get 1
    local.get 2
    i64.const 48
    i64.shr_u
    i64.store8 offset=17
    local.get 1
    local.get 6
    i32.store8 offset=31
    local.get 1
    local.get 6
    i32.const 16
    i32.shr_u
    i32.store8 offset=29
    local.get 1
    local.get 4
    i64.const 32
    i64.shr_u
    i64.store8 offset=27
    local.get 1
    local.get 4
    i64.const 48
    i64.shr_u
    i64.store8 offset=25)
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
              i32.load8_u offset=66660
              br_if 0 (;@5;)
              i32.const 66560
              i32.const 0
              local.get 3
              call $callDataCopy
              i32.const 0
              i32.const 1
              i32.store8 offset=66660
            end
            local.get 4
            i32.eqz
            br_if 2 (;@2;)
            local.get 0
            i32.const 66560
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
            i32.load8_u offset=66660
            br_if 0 (;@4;)
            i32.const 66560
            i32.const 0
            local.get 2
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=66660
          end
          local.get 1
          local.get 0
          i32.const 66560
          i32.add
          i32.load8_u
          i32.store8
          local.get 1
          local.get 0
          i32.const 66561
          i32.add
          i32.load8_u
          i32.store8 offset=1
          local.get 1
          local.get 0
          i32.const 66562
          i32.add
          i32.load8_u
          i32.store8 offset=2
          local.get 1
          local.get 0
          i32.const 66563
          i32.add
          i32.load8_u
          i32.store8 offset=3
          local.get 1
          local.get 0
          i32.const 66564
          i32.add
          i32.load8_u
          i32.store8 offset=4
          local.get 1
          local.get 0
          i32.const 66565
          i32.add
          i32.load8_u
          i32.store8 offset=5
          local.get 1
          local.get 0
          i32.const 66566
          i32.add
          i32.load8_u
          i32.store8 offset=6
          local.get 1
          local.get 0
          i32.const 66567
          i32.add
          i32.load8_u
          i32.store8 offset=7
          local.get 1
          local.get 0
          i32.const 66568
          i32.add
          i32.load8_u
          i32.store8 offset=8
          local.get 1
          local.get 0
          i32.const 66569
          i32.add
          i32.load8_u
          i32.store8 offset=9
          local.get 1
          local.get 0
          i32.const 66570
          i32.add
          i32.load8_u
          i32.store8 offset=10
          local.get 1
          local.get 0
          i32.const 66571
          i32.add
          i32.load8_u
          i32.store8 offset=11
          local.get 1
          local.get 0
          i32.const 66572
          i32.add
          i32.load8_u
          i32.store8 offset=12
          local.get 1
          local.get 0
          i32.const 66573
          i32.add
          i32.load8_u
          i32.store8 offset=13
          local.get 1
          local.get 0
          i32.const 66574
          i32.add
          i32.load8_u
          i32.store8 offset=14
          local.get 1
          local.get 0
          i32.const 66575
          i32.add
          i32.load8_u
          i32.store8 offset=15
          local.get 1
          local.get 0
          i32.const 66576
          i32.add
          i32.load8_u
          i32.store8 offset=16
          local.get 1
          local.get 0
          i32.const 66577
          i32.add
          i32.load8_u
          i32.store8 offset=17
          local.get 1
          local.get 0
          i32.const 66578
          i32.add
          i32.load8_u
          i32.store8 offset=18
          local.get 1
          local.get 0
          i32.const 66579
          i32.add
          i32.load8_u
          i32.store8 offset=19
          local.get 1
          local.get 0
          i32.const 66580
          i32.add
          i32.load8_u
          i32.store8 offset=20
          local.get 1
          local.get 0
          i32.const 66581
          i32.add
          i32.load8_u
          i32.store8 offset=21
          local.get 1
          local.get 0
          i32.const 66582
          i32.add
          i32.load8_u
          i32.store8 offset=22
          local.get 1
          local.get 0
          i32.const 66583
          i32.add
          i32.load8_u
          i32.store8 offset=23
          local.get 1
          local.get 0
          i32.const 66584
          i32.add
          i32.load8_u
          i32.store8 offset=24
          local.get 1
          local.get 0
          i32.const 66585
          i32.add
          i32.load8_u
          i32.store8 offset=25
          local.get 1
          local.get 0
          i32.const 66586
          i32.add
          i32.load8_u
          i32.store8 offset=26
          local.get 1
          local.get 0
          i32.const 66587
          i32.add
          i32.load8_u
          i32.store8 offset=27
          local.get 1
          local.get 0
          i32.const 66588
          i32.add
          i32.load8_u
          i32.store8 offset=28
          local.get 1
          local.get 0
          i32.const 66589
          i32.add
          i32.load8_u
          i32.store8 offset=29
          local.get 1
          local.get 0
          i32.const 66590
          i32.add
          i32.load8_u
          i32.store8 offset=30
          local.get 1
          local.get 0
          i32.const 66591
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
    i32.load offset=66668
    local.get 0
    i32.add
    local.get 1
    call $revert)
  (func $evm_get_memory_addr (type 6) (param i32) (result i32)
    i32.const 0
    i32.load offset=66668
    local.get 0
    i32.add)
  (func $wrapper_codecopy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=66680
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
        i32.store offset=66676
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=66680
        i32.const 0
        i32.const 0
        i32.load offset=66672
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=66672
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=66676
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=66676
    end
    i32.const 0
    i32.load offset=66668
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
          i32.load8_u offset=66660
          br_if 0 (;@3;)
          i32.const 66560
          i32.const 0
          local.get 1
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=66660
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.const 66560
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
      i32.load offset=66680
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
      i32.store offset=66676
      i32.const 0
      local.get 2
      i32.const -65536
      i32.and
      i32.store offset=66680
      i32.const 0
      i32.const 0
      i32.load offset=66672
      local.get 1
      i32.const 16
      i32.shl
      i32.add
      i32.store offset=66672
      i32.const 96
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=66676
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 0
      i32.store offset=66676
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
          i32.load offset=66680
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
          i32.store offset=66676
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=66680
          i32.const 0
          i32.const 0
          i32.load offset=66672
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=66672
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=66676
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=66676
      end
      i32.const 0
      i32.load offset=66668
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
          i32.load offset=66680
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
          i32.store offset=66676
          i32.const 0
          local.get 7
          i32.const -65536
          i32.and
          i32.store offset=66680
          i32.const 0
          i32.const 0
          i32.load offset=66672
          local.get 1
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=66672
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=66676
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=66676
      end
      i32.const 0
      i32.load offset=66668
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
          i32.load offset=66680
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
          i32.store offset=66676
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=66680
          i32.const 0
          i32.const 0
          i32.load offset=66672
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=66672
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=66676
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=66676
      end
      i32.const 0
      i32.load offset=66668
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
    i32.load offset=66668
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
    i32.load offset=66668
    local.get 0
    i32.add
    local.get 1
    call $finish)
  (func $set_is_deploying_tx (type 4)
    i32.const 0
    i32.const 1
    i32.store8 offset=66544)
  (func $wrapper_sign_extend (type 1) (param i32 i32 i32)
    (local i32 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.set 3
    local.get 1
    i32.const 24
    i32.add
    i64.load
    local.set 4
    local.get 1
    i32.const 16
    i32.add
    i64.load
    local.set 5
    local.get 1
    i32.const 8
    i32.add
    i64.load
    local.set 6
    local.get 1
    i64.load
    local.set 7
    block  ;; label = @1
      local.get 0
      i32.const 31
      i32.gt_u
      br_if 0 (;@1;)
      local.get 3
      i32.const 56
      i32.add
      i64.const -1
      i64.store align=1
      local.get 3
      i32.const 48
      i32.add
      i64.const -1
      i64.store align=1
      local.get 3
      i32.const 40
      i32.add
      i64.const -1
      i64.store align=1
      local.get 3
      i32.const 32
      i32.add
      local.tee 1
      i64.const -1
      i64.store align=1
      local.get 3
      i32.const 24
      i32.add
      i64.const 0
      i64.store align=1
      local.get 3
      i64.const 0
      i64.store offset=16 align=1
      local.get 3
      i64.const 0
      i64.store offset=8 align=1
      local.get 3
      i64.const 0
      i64.store align=1
      local.get 7
      local.get 1
      local.get 0
      i32.const 3
      i32.shl
      local.tee 3
      i32.const 8
      i32.add
      i32.const 3
      i32.shr_u
      i32.const 31
      i32.and
      i32.sub
      local.tee 1
      i64.load align=1
      local.tee 8
      i64.const -1
      i64.xor
      i64.and
      local.get 7
      local.get 8
      i64.or
      local.get 7
      local.get 3
      i32.const 7
      i32.or
      i64.extend_i32_u
      i64.shr_u
      i64.const 1
      i64.and
      i64.eqz
      local.tee 3
      select
      local.set 7
      local.get 4
      local.get 1
      i32.const 24
      i32.add
      i64.load align=1
      local.tee 8
      i64.const -1
      i64.xor
      i64.and
      local.get 4
      local.get 8
      i64.or
      local.get 3
      select
      local.set 4
      local.get 5
      local.get 1
      i32.const 16
      i32.add
      i64.load align=1
      local.tee 8
      i64.const -1
      i64.xor
      i64.and
      local.get 5
      local.get 8
      i64.or
      local.get 3
      select
      local.set 5
      local.get 6
      local.get 1
      i32.const 8
      i32.add
      i64.load align=1
      local.tee 8
      i64.const -1
      i64.xor
      i64.and
      local.get 6
      local.get 8
      i64.or
      local.get 3
      select
      local.set 6
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
  (func $__init_evm_heap (type 2) (param i32)
    (local i32)
    block  ;; label = @1
      i32.const 0
      i32.load8_u offset=66664
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
          i32.store offset=66668
          i32.const 1
          memory.grow
          drop
          memory.size
          i32.const 16
          i32.shl
          local.tee 0
          i32.const 0
          i32.load offset=66668
          i32.sub
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 66688
        i32.store offset=66668
        i32.const 83072
        local.set 0
        i32.const 16384
        local.set 1
      end
      i32.const 0
      local.get 0
      i32.store offset=66672
      i32.const 0
      local.get 1
      i32.store offset=66680
      i32.const 0
      i32.const 1
      i32.store8 offset=66664
      i32.const 0
      i32.const 0
      i32.store offset=66676
    end)
  (func $wrapper_bytes32_eq (type 7) (param i32 i32) (result i32)
    (local i32)
    i32.const 0
    local.set 2
    block  ;; label = @1
      local.get 0
      i64.load
      local.get 1
      i64.load
      i64.ne
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=8
      local.get 1
      i64.load offset=8
      i64.ne
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=16
      local.get 1
      i64.load offset=16
      i64.ne
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=24
      local.get 1
      i64.load offset=24
      i64.eq
      local.set 2
    end
    local.get 2)
  (func $wrapper_bytes32_and (type 1) (param i32 i32 i32)
    local.get 2
    local.get 1
    i64.load
    local.get 0
    i64.load
    i64.and
    i64.store
    local.get 2
    local.get 1
    i64.load offset=8
    local.get 0
    i64.load offset=8
    i64.and
    i64.store offset=8
    local.get 2
    local.get 1
    i64.load offset=16
    local.get 0
    i64.load offset=16
    i64.and
    i64.store offset=16
    local.get 2
    local.get 1
    i64.load offset=24
    local.get 0
    i64.load offset=24
    i64.and
    i64.store offset=24)
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
  (func $TickMathPilot_27_deployed.TickMathPilot_27_deployed.external_fun_generate_26 (type 4)
    (local i32 i64 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32)
    global.get $__stack_pointer
    i32.const 288
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    block  ;; label = @1
      call $wrapper_callvalue_not_zero
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      call $wrapper_revert
    end
    block  ;; label = @1
      call $wrapper_calldata_size
      i32.const 35
      i32.gt_u
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      call $wrapper_revert
    end
    i32.const 4
    local.get 0
    i32.const 160
    i32.add
    call $wrapper_calldataload_bytes32
    local.get 0
    i32.const 160
    i32.add
    local.get 0
    i32.const 256
    i32.add
    call $u256_from_big_endian_bytes
    local.get 0
    i32.const 80
    i32.add
    local.get 0
    i64.load offset=256
    local.tee 1
    i64.const 0
    i64.const 200000
    i64.const 0
    call $__multi3
    local.get 0
    i32.const 112
    i32.add
    local.get 0
    i32.const 256
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.tee 2
    i64.const 0
    i64.const 200000
    i64.const 0
    call $__multi3
    local.get 0
    i32.const 128
    i32.add
    local.get 1
    local.get 2
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 0
    i32.const 144
    i32.add
    local.get 0
    i32.const 256
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.const 0
    i64.const 200000
    i64.const 0
    call $__multi3
    local.get 0
    i32.const 32
    i32.add
    local.get 0
    i32.const 256
    i32.add
    i32.const 24
    i32.add
    local.tee 3
    i64.load
    i64.const 0
    i64.const 200000
    i64.const 0
    call $__multi3
    local.get 0
    i32.const 64
    i32.add
    local.get 1
    i64.const 0
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 0
    i32.const 96
    i32.add
    local.get 2
    i64.const 0
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 0
    i32.const 48
    i32.add
    local.get 1
    i64.const 0
    i64.const 0
    i64.const 0
    call $__multi3
    local.get 0
    i64.load offset=80
    local.set 4
    block  ;; label = @1
      local.get 0
      i64.load offset=40
      i64.const 0
      i64.ne
      local.get 0
      i32.const 144
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 1
      local.get 0
      i64.load offset=32
      i64.add
      local.tee 5
      local.get 1
      i64.lt_u
      i32.or
      local.get 0
      i64.load offset=96
      local.tee 6
      local.get 0
      i32.const 112
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 0
      i64.load offset=112
      local.tee 1
      local.get 0
      i32.const 80
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
      local.get 0
      i32.const 64
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 0
      i64.load offset=64
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
      local.get 0
      i64.load offset=128
      i64.add
      local.tee 2
      local.get 0
      i64.load offset=144
      local.tee 10
      local.get 0
      i64.load offset=48
      i64.add
      local.tee 11
      i64.add
      local.tee 12
      local.get 2
      i64.lt_u
      local.tee 13
      local.get 0
      i32.const 96
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
      local.get 6
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 0
      i32.const 128
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
      local.get 5
      local.get 0
      i32.const 48
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
    local.get 3
    local.get 2
    i64.store
    local.get 0
    local.get 4
    i64.store offset=256
    local.get 0
    local.get 8
    i64.store offset=264
    local.get 0
    local.get 12
    i64.store offset=272
    i32.const 2
    local.get 0
    i32.const 256
    i32.add
    local.get 0
    i32.const 224
    i32.add
    call $wrapper_sign_extend
    local.get 0
    local.get 0
    i64.load offset=224
    local.get 0
    i32.const 224
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.get 0
    i32.const 224
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.get 0
    i32.const 224
    i32.add
    i32.const 24
    i32.add
    i64.load
    call $TickMathPilot_27_deployed.TickMathPilot_27_deployed.fun_getSqrtRatioAtTick_425
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
    i64.load
    local.set 4
    local.get 0
    i32.const 192
    i32.add
    i32.const 24
    i32.add
    local.get 0
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 0
    local.get 2
    i64.store offset=208
    local.get 0
    local.get 1
    i64.store offset=200
    local.get 0
    local.get 4
    i64.store offset=192
    local.get 0
    i32.const 192
    i32.add
    local.get 0
    i32.const 224
    i32.add
    call $u256_to_big_endian_bytes
    local.get 0
    i32.const 224
    i32.add
    i32.const 65584
    local.get 0
    i32.const 160
    i32.add
    call $wrapper_bytes32_and
    local.get 0
    i32.const 160
    i32.add
    local.get 0
    i32.const 256
    i32.add
    call $u256_from_big_endian_bytes
    i32.const 64
    local.get 0
    i32.const 224
    i32.add
    call $wrapper_mload_u256
    local.get 0
    i32.load offset=224
    local.tee 3
    local.get 0
    i32.const 256
    i32.add
    call $wrapper_mstore_u256
    local.get 3
    i32.const 32
    call $wrapper_return
    local.get 0
    i32.const 288
    i32.add
    global.set $__stack_pointer)
  (func $TickMathPilot_27_deployed.TickMathPilot_27_deployed.fun_getSqrtRatioAtTick_425 (type 5) (param i32 i64 i64 i64 i64)
    (local i32 i32 i32 i64 i32 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 4800
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    i32.const 4768
    i32.add
    i32.const 24
    i32.add
    local.tee 6
    local.get 4
    i64.store
    local.get 5
    local.get 3
    i64.store offset=4784
    local.get 5
    local.get 2
    i64.store offset=4776
    local.get 5
    local.get 1
    i64.store offset=4768
    i32.const 2
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $wrapper_sign_extend
    local.get 5
    i32.const 4744
    i32.add
    local.tee 7
    i64.load
    local.set 8
    local.get 5
    i32.const 4752
    i32.add
    local.tee 9
    i64.load
    local.set 10
    local.get 5
    i32.const 4736
    i32.add
    i32.const 24
    i32.add
    local.tee 11
    i64.load
    local.set 12
    local.get 5
    i64.load offset=4736
    local.set 13
    local.get 6
    i64.const 0
    i64.store
    local.get 5
    i64.const 0
    i64.store offset=4784
    local.get 5
    i64.const 0
    i64.store offset=4776
    local.get 5
    i64.const 0
    i64.store offset=4768
    i32.const 2
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $wrapper_sign_extend
    block  ;; label = @1
      block  ;; label = @2
        local.get 13
        local.get 5
        i64.load offset=4736
        i64.lt_u
        local.get 8
        local.get 7
        i64.load
        local.tee 13
        i64.lt_u
        local.get 8
        local.get 13
        i64.eq
        select
        local.get 10
        local.get 9
        i64.load
        local.tee 13
        i64.lt_u
        local.get 12
        local.get 11
        i64.load
        local.tee 8
        i64.lt_s
        local.get 12
        local.get 8
        i64.eq
        select
        local.get 10
        local.get 13
        i64.xor
        local.get 12
        local.get 8
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        local.get 6
        local.get 4
        i64.store
        local.get 5
        local.get 1
        i64.store offset=4768
        local.get 5
        local.get 2
        i64.store offset=4776
        local.get 5
        local.get 3
        i64.store offset=4784
        i32.const 2
        local.get 5
        i32.const 4768
        i32.add
        local.get 5
        i32.const 4736
        i32.add
        call $wrapper_sign_extend
        local.get 11
        i64.load
        local.set 8
        local.get 9
        i64.load
        local.set 14
        local.get 7
        i64.load
        local.set 15
        local.get 5
        i64.load offset=4736
        local.set 16
        br 1 (;@1;)
      end
      local.get 6
      local.get 4
      i64.store
      local.get 5
      local.get 1
      i64.store offset=4768
      local.get 5
      local.get 2
      i64.store offset=4776
      local.get 5
      local.get 3
      i64.store offset=4784
      i32.const 2
      local.get 5
      i32.const 4768
      i32.add
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_sign_extend
      local.get 7
      i64.load
      local.set 12
      local.get 9
      i64.load
      local.set 8
      local.get 5
      i64.load offset=4736
      local.set 10
      local.get 6
      local.get 11
      i64.load
      local.tee 13
      i64.store
      local.get 5
      local.get 8
      i64.store offset=4784
      local.get 5
      local.get 12
      i64.store offset=4776
      local.get 5
      local.get 10
      i64.store offset=4768
      local.get 5
      i32.const 4768
      i32.add
      local.get 5
      i32.const 4672
      i32.add
      call $u256_to_big_endian_bytes
      block  ;; label = @2
        local.get 5
        i32.const 4672
        i32.add
        i32.const 65616
        call $wrapper_bytes32_eq
        i32.eqz
        br_if 0 (;@2;)
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
      i64.const 0
      local.get 8
      i64.sub
      local.tee 16
      local.get 10
      i64.const 0
      i64.ne
      local.tee 6
      local.get 12
      i64.const 0
      i64.ne
      local.get 12
      i64.eqz
      select
      i64.extend_i32_u
      local.tee 15
      i64.sub
      local.set 14
      i64.const 0
      local.get 13
      local.get 8
      i64.const 0
      i64.ne
      i64.extend_i32_u
      i64.add
      local.get 16
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.sub
      local.set 8
      i64.const 0
      local.get 10
      i64.sub
      local.set 16
      i64.const 0
      local.get 12
      local.get 6
      i64.extend_i32_u
      i64.add
      i64.sub
      local.set 15
    end
    i32.const 65648
    local.get 5
    i32.const 4736
    i32.add
    call $u256_from_big_endian_bytes
    i32.const 2
    local.get 5
    i32.const 4736
    i32.add
    local.get 5
    i32.const 4768
    i32.add
    call $wrapper_sign_extend
    i32.const 2
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $wrapper_sign_extend
    local.get 5
    i32.const 4704
    i32.add
    i32.const 24
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    i32.const 24
    i32.add
    local.tee 6
    i64.load
    local.tee 17
    i64.store
    local.get 5
    local.get 5
    i32.const 4752
    i32.add
    local.tee 7
    i64.load
    local.tee 10
    i64.store offset=4720
    local.get 5
    local.get 5
    i32.const 4744
    i32.add
    local.tee 9
    i64.load
    local.tee 12
    i64.store offset=4712
    local.get 5
    local.get 5
    i64.load offset=4736
    local.tee 13
    i64.store offset=4704
    local.get 5
    i32.const 4704
    i32.add
    local.get 5
    i32.const 4672
    i32.add
    call $u256_to_big_endian_bytes
    block  ;; label = @1
      local.get 5
      i32.const 4672
      i32.add
      i32.const 65680
      call $wrapper_bytes32_eq
      i32.eqz
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
    local.get 5
    i32.const 4768
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    local.get 17
    local.get 10
    i64.const 0
    i64.ne
    i64.extend_i32_u
    i64.add
    i64.const 0
    local.get 10
    i64.sub
    local.tee 10
    local.get 13
    i64.const 0
    i64.ne
    local.tee 11
    local.get 12
    i64.const 0
    i64.ne
    local.get 12
    i64.eqz
    select
    i64.extend_i32_u
    local.tee 17
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.sub
    i64.store
    local.get 5
    i64.const 0
    local.get 13
    i64.sub
    i64.store offset=4768
    local.get 5
    i64.const 0
    local.get 12
    local.get 11
    i64.extend_i32_u
    i64.add
    i64.sub
    i64.store offset=4776
    local.get 5
    local.get 10
    local.get 17
    i64.sub
    i64.store offset=4784
    i32.const 2
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $wrapper_sign_extend
    block  ;; label = @1
      local.get 16
      local.get 5
      i64.load offset=4736
      i64.le_u
      local.get 15
      local.get 9
      i64.load
      local.tee 12
      i64.le_u
      local.get 15
      local.get 12
      i64.eq
      select
      local.get 14
      local.get 7
      i64.load
      local.tee 10
      i64.le_u
      local.get 8
      local.get 6
      i64.load
      local.tee 12
      i64.le_u
      local.get 8
      local.get 12
      i64.eq
      select
      local.get 14
      local.get 10
      i64.xor
      local.get 8
      local.get 12
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      i32.const 64
      local.get 5
      i32.const 4768
      i32.add
      call $wrapper_mload_u256
      local.get 5
      i32.load offset=4768
      local.tee 6
      i32.const 65712
      call $wrapper_mstore_bytes32
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 5
      i64.const 0
      i64.store offset=4752
      local.get 5
      i64.const 0
      i64.store offset=4744
      local.get 5
      i64.const 32
      i64.store offset=4736
      local.get 6
      i32.const 4
      i32.add
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_mstore_u256
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.tee 7
      i64.const 0
      i64.store
      local.get 5
      i64.const 0
      i64.store offset=4784
      local.get 5
      i64.const 0
      i64.store offset=4776
      local.get 5
      i64.const 1
      i64.store offset=4768
      local.get 6
      i32.const 36
      i32.add
      local.get 5
      i32.const 4768
      i32.add
      call $wrapper_mstore_u256
      local.get 7
      i64.const 6052837899185946624
      i64.store
      local.get 5
      i64.const 0
      i64.store offset=4784
      local.get 5
      i64.const 0
      i64.store offset=4776
      local.get 5
      i64.const 0
      i64.store offset=4768
      local.get 6
      i32.const 68
      i32.add
      local.get 5
      i32.const 4768
      i32.add
      call $wrapper_mstore_u256
      local.get 6
      i32.const 100
      call $wrapper_revert
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 16
        i64.const 1
        i64.and
        i64.eqz
        i32.eqz
        br_if 0 (;@2;)
        i32.const 65808
        local.get 5
        i32.const 4768
        i32.add
        call $u256_from_big_endian_bytes
        local.get 5
        i32.const 4768
        i32.add
        local.get 5
        i32.const 4704
        i32.add
        call $u256_to_big_endian_bytes
        local.get 5
        i32.const 4704
        i32.add
        i32.const 65744
        local.get 5
        i32.const 4672
        i32.add
        call $wrapper_bytes32_and
        local.get 5
        i32.const 4672
        i32.add
        local.get 5
        i32.const 4736
        i32.add
        call $u256_from_big_endian_bytes
        local.get 5
        i32.const 4760
        i32.add
        i64.load
        local.set 8
        local.get 5
        i32.const 4752
        i32.add
        i64.load
        local.set 10
        local.get 5
        i32.const 4744
        i32.add
        i64.load
        local.set 13
        br 1 (;@1;)
      end
      i32.const 65840
      local.get 5
      i32.const 4768
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 4768
      i32.add
      local.get 5
      i32.const 4704
      i32.add
      call $u256_to_big_endian_bytes
      local.get 5
      i32.const 4704
      i32.add
      i32.const 65744
      local.get 5
      i32.const 4672
      i32.add
      call $wrapper_bytes32_and
      local.get 5
      i32.const 4672
      i32.add
      local.get 5
      i32.const 4736
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 4760
      i32.add
      i64.load
      local.set 8
      local.get 5
      i32.const 4752
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4744
      i32.add
      i64.load
      local.set 13
    end
    local.get 5
    i64.load offset=4736
    local.set 12
    local.get 5
    i32.const 4768
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 5
    local.get 10
    i64.store offset=4784
    local.get 5
    local.get 13
    i64.store offset=4776
    local.get 5
    local.get 12
    i64.store offset=4768
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4704
    i32.add
    call $u256_to_big_endian_bytes
    local.get 5
    i32.const 4704
    i32.add
    i32.const 65744
    local.get 5
    i32.const 4672
    i32.add
    call $wrapper_bytes32_and
    local.get 5
    i32.const 4672
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $u256_from_big_endian_bytes
    local.get 5
    i32.const 4736
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 10
    local.get 5
    i32.const 4736
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 13
    local.get 5
    i32.const 4736
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 12
    local.get 5
    i64.load offset=4736
    local.set 8
    block  ;; label = @1
      local.get 16
      i64.const 2
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 65872
      local.get 5
      i32.const 4000
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 3952
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4000
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3936
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3968
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4000
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3984
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3888
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3872
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3824
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4000
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3808
      i32.add
      local.get 5
      i32.const 4000
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3920
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3840
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3856
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3904
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=3952
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3864
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3848
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3904
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=3856
        local.get 5
        i64.load offset=3840
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3816
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3832
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3920
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=3808
        local.get 5
        i64.load offset=3824
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=3984
        local.tee 15
        local.get 5
        i32.const 3936
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3936
        local.tee 12
        local.get 5
        i32.const 3952
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 3968
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3968
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=3888
        local.tee 20
        local.get 5
        i64.load offset=3872
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=3904
        local.tee 22
        local.get 5
        i64.load offset=3920
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 3984
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 3888
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 3872
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4752
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4744
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 4
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 65904
      local.get 5
      i32.const 4032
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 3760
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4032
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3744
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3776
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4032
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3792
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3696
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3680
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3632
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4032
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3616
      i32.add
      local.get 5
      i32.const 4032
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3728
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3648
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3664
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3712
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=3760
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3672
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3656
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3712
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=3664
        local.get 5
        i64.load offset=3648
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3624
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3640
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3728
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=3616
        local.get 5
        i64.load offset=3632
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=3792
        local.tee 15
        local.get 5
        i32.const 3744
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3744
        local.tee 12
        local.get 5
        i32.const 3760
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 3776
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3776
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=3696
        local.tee 20
        local.get 5
        i64.load offset=3680
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=3712
        local.tee 22
        local.get 5
        i64.load offset=3728
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 3792
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 3696
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 3680
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 8
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 65936
      local.get 5
      i32.const 4064
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 3568
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4064
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3552
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3584
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4064
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3600
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3504
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3488
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3440
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4064
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3424
      i32.add
      local.get 5
      i32.const 4064
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3536
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3456
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3472
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3520
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=3568
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3480
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3464
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3520
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=3472
        local.get 5
        i64.load offset=3456
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3432
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3448
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3536
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=3424
        local.get 5
        i64.load offset=3440
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=3600
        local.tee 15
        local.get 5
        i32.const 3552
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3552
        local.tee 12
        local.get 5
        i32.const 3568
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 3584
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3584
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=3504
        local.tee 20
        local.get 5
        i64.load offset=3488
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=3520
        local.tee 22
        local.get 5
        i64.load offset=3536
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 3600
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 3504
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 3488
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 16
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 65968
      local.get 5
      i32.const 4096
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 3376
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4096
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3360
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3392
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4096
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3408
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3312
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3296
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3248
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4096
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3232
      i32.add
      local.get 5
      i32.const 4096
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3344
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3264
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3280
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3328
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=3376
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3288
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3272
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3328
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=3280
        local.get 5
        i64.load offset=3264
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3240
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3256
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3344
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=3232
        local.get 5
        i64.load offset=3248
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=3408
        local.tee 15
        local.get 5
        i32.const 3360
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3360
        local.tee 12
        local.get 5
        i32.const 3376
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 3392
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3392
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=3312
        local.tee 20
        local.get 5
        i64.load offset=3296
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=3328
        local.tee 22
        local.get 5
        i64.load offset=3344
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 3408
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 3312
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 3296
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 32
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66000
      local.get 5
      i32.const 4128
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 3184
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4128
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3168
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3200
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4128
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3216
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3120
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3104
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3056
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4128
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3040
      i32.add
      local.get 5
      i32.const 4128
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3152
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3072
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3088
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3136
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=3184
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3096
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3080
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3136
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=3088
        local.get 5
        i64.load offset=3072
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=3048
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=3064
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 3152
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=3040
        local.get 5
        i64.load offset=3056
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=3216
        local.tee 15
        local.get 5
        i32.const 3168
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3168
        local.tee 12
        local.get 5
        i32.const 3184
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 3200
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3200
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=3120
        local.tee 20
        local.get 5
        i64.load offset=3104
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=3136
        local.tee 22
        local.get 5
        i64.load offset=3152
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 3216
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 3120
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 3104
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 64
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66032
      local.get 5
      i32.const 4160
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 2992
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4160
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2976
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3008
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4160
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 3024
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2928
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2912
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2864
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4160
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2848
      i32.add
      local.get 5
      i32.const 4160
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2960
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2880
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2896
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2944
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=2992
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2904
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2888
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2944
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=2896
        local.get 5
        i64.load offset=2880
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2856
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2872
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2960
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=2848
        local.get 5
        i64.load offset=2864
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=3024
        local.tee 15
        local.get 5
        i32.const 2976
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2976
        local.tee 12
        local.get 5
        i32.const 2992
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 3008
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=3008
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=2928
        local.tee 20
        local.get 5
        i64.load offset=2912
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=2944
        local.tee 22
        local.get 5
        i64.load offset=2960
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 3024
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 2928
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 2912
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 128
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66064
      local.get 5
      i32.const 4192
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 2800
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4192
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2784
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2816
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4192
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2832
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2736
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2720
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2672
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4192
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2656
      i32.add
      local.get 5
      i32.const 4192
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2768
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2688
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2704
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2752
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=2800
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2712
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2696
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2752
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=2704
        local.get 5
        i64.load offset=2688
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2664
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2680
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2768
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=2656
        local.get 5
        i64.load offset=2672
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=2832
        local.tee 15
        local.get 5
        i32.const 2784
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2784
        local.tee 12
        local.get 5
        i32.const 2800
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 2816
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2816
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=2736
        local.tee 20
        local.get 5
        i64.load offset=2720
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=2752
        local.tee 22
        local.get 5
        i64.load offset=2768
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 2832
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 2736
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 2720
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 256
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66096
      local.get 5
      i32.const 4224
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 2608
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4224
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2592
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2624
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4224
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2640
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2544
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2528
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2480
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4224
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2464
      i32.add
      local.get 5
      i32.const 4224
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2576
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2496
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2512
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2560
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=2608
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2520
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2504
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2560
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=2512
        local.get 5
        i64.load offset=2496
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2472
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2488
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2576
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=2464
        local.get 5
        i64.load offset=2480
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=2640
        local.tee 15
        local.get 5
        i32.const 2592
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2592
        local.tee 12
        local.get 5
        i32.const 2608
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 2624
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2624
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=2544
        local.tee 20
        local.get 5
        i64.load offset=2528
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=2560
        local.tee 22
        local.get 5
        i64.load offset=2576
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 2640
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 2544
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 2528
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 512
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66128
      local.get 5
      i32.const 4256
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 2416
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4256
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2400
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2432
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4256
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2448
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2352
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2336
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2288
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4256
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2272
      i32.add
      local.get 5
      i32.const 4256
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2384
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2304
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2320
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2368
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=2416
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2328
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2312
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2368
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=2320
        local.get 5
        i64.load offset=2304
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2280
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2296
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2384
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=2272
        local.get 5
        i64.load offset=2288
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=2448
        local.tee 15
        local.get 5
        i32.const 2400
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2400
        local.tee 12
        local.get 5
        i32.const 2416
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 2432
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2432
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=2352
        local.tee 20
        local.get 5
        i64.load offset=2336
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=2368
        local.tee 22
        local.get 5
        i64.load offset=2384
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 2448
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 2352
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 2336
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 1024
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66160
      local.get 5
      i32.const 4288
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 2224
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4288
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2208
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2240
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4288
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2256
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2160
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2144
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2096
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4288
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2080
      i32.add
      local.get 5
      i32.const 4288
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2192
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2112
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2128
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2176
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=2224
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2136
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2120
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2176
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=2128
        local.get 5
        i64.load offset=2112
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=2088
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=2104
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2192
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=2080
        local.get 5
        i64.load offset=2096
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=2256
        local.tee 15
        local.get 5
        i32.const 2208
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2208
        local.tee 12
        local.get 5
        i32.const 2224
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 2240
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2240
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=2160
        local.tee 20
        local.get 5
        i64.load offset=2144
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=2176
        local.tee 22
        local.get 5
        i64.load offset=2192
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 2256
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 2160
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 2144
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 2048
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66192
      local.get 5
      i32.const 4320
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 2032
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4320
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2016
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2048
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4320
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2064
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1968
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1952
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1904
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4320
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1888
      i32.add
      local.get 5
      i32.const 4320
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 2000
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1920
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1936
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1984
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=2032
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1944
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1928
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1984
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=1936
        local.get 5
        i64.load offset=1920
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1896
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1912
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 2000
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=1888
        local.get 5
        i64.load offset=1904
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=2064
        local.tee 15
        local.get 5
        i32.const 2016
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2016
        local.tee 12
        local.get 5
        i32.const 2032
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 2048
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=2048
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=1968
        local.tee 20
        local.get 5
        i64.load offset=1952
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=1984
        local.tee 22
        local.get 5
        i64.load offset=2000
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 2064
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 1968
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 1952
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 4096
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66224
      local.get 5
      i32.const 4352
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 1840
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4352
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1824
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1856
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4352
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1872
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1776
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1760
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1712
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4352
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1696
      i32.add
      local.get 5
      i32.const 4352
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1808
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1728
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1744
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1792
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=1840
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1752
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1736
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1792
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=1744
        local.get 5
        i64.load offset=1728
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1704
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1720
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1808
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=1696
        local.get 5
        i64.load offset=1712
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=1872
        local.tee 15
        local.get 5
        i32.const 1824
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1824
        local.tee 12
        local.get 5
        i32.const 1840
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 1856
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1856
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=1776
        local.tee 20
        local.get 5
        i64.load offset=1760
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=1792
        local.tee 22
        local.get 5
        i64.load offset=1808
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 1872
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 1776
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 1760
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 8192
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66256
      local.get 5
      i32.const 4384
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 1648
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4384
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1632
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1664
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4384
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1680
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1584
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1568
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1520
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4384
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1504
      i32.add
      local.get 5
      i32.const 4384
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1616
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1536
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1552
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1600
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=1648
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1560
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1544
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1600
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=1552
        local.get 5
        i64.load offset=1536
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1512
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1528
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1616
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=1504
        local.get 5
        i64.load offset=1520
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=1680
        local.tee 15
        local.get 5
        i32.const 1632
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1632
        local.tee 12
        local.get 5
        i32.const 1648
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 1664
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1664
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=1584
        local.tee 20
        local.get 5
        i64.load offset=1568
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=1600
        local.tee 22
        local.get 5
        i64.load offset=1616
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 1680
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 1584
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 1568
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 16384
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66288
      local.get 5
      i32.const 4416
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 1456
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4416
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1440
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1472
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4416
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1488
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1392
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1376
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1328
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4416
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1312
      i32.add
      local.get 5
      i32.const 4416
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1424
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1344
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1360
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1408
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=1456
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1368
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1352
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1408
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=1360
        local.get 5
        i64.load offset=1344
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1320
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1336
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1424
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=1312
        local.get 5
        i64.load offset=1328
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=1488
        local.tee 15
        local.get 5
        i32.const 1440
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1440
        local.tee 12
        local.get 5
        i32.const 1456
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 1472
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1472
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=1392
        local.tee 20
        local.get 5
        i64.load offset=1376
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=1408
        local.tee 22
        local.get 5
        i64.load offset=1424
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 1488
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 1392
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 1376
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 32768
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66320
      local.get 5
      i32.const 4448
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 1264
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4448
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1248
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1280
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4448
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1296
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1200
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1184
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1136
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4448
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1120
      i32.add
      local.get 5
      i32.const 4448
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1232
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1152
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1168
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1216
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=1264
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1176
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1160
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1216
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=1168
        local.get 5
        i64.load offset=1152
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=1128
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=1144
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1232
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=1120
        local.get 5
        i64.load offset=1136
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=1296
        local.tee 15
        local.get 5
        i32.const 1248
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1248
        local.tee 12
        local.get 5
        i32.const 1264
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 1280
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1280
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=1200
        local.tee 20
        local.get 5
        i64.load offset=1184
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=1216
        local.tee 22
        local.get 5
        i64.load offset=1232
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 1296
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 1200
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 1184
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 65536
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66352
      local.get 5
      i32.const 4480
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 1072
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4480
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1056
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1088
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4480
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1104
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1008
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 992
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 944
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4480
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 928
      i32.add
      local.get 5
      i32.const 4480
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1040
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 960
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 976
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 1024
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=1072
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=984
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=968
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1024
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=976
        local.get 5
        i64.load offset=960
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=936
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=952
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 1040
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=928
        local.get 5
        i64.load offset=944
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=1104
        local.tee 15
        local.get 5
        i32.const 1056
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1056
        local.tee 12
        local.get 5
        i32.const 1072
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 1088
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=1088
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=1008
        local.tee 20
        local.get 5
        i64.load offset=992
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=1024
        local.tee 22
        local.get 5
        i64.load offset=1040
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 1104
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 1008
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 992
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 131072
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66384
      local.get 5
      i32.const 4512
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 880
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4512
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 864
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 896
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4512
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 912
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 816
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 800
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 752
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4512
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 736
      i32.add
      local.get 5
      i32.const 4512
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 848
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 768
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 784
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 832
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=880
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=792
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=776
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 832
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=784
        local.get 5
        i64.load offset=768
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=744
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=760
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 848
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=736
        local.get 5
        i64.load offset=752
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=912
        local.tee 15
        local.get 5
        i32.const 864
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=864
        local.tee 12
        local.get 5
        i32.const 880
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 896
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=896
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=816
        local.tee 20
        local.get 5
        i64.load offset=800
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=832
        local.tee 22
        local.get 5
        i64.load offset=848
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 912
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 816
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 800
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 262144
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66416
      local.get 5
      i32.const 4544
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 688
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4544
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 672
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 704
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4544
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 720
      i32.add
      local.get 12
      i64.const 0
      local.get 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 624
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 608
      i32.add
      local.get 14
      local.get 15
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 560
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4544
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 544
      i32.add
      local.get 5
      i32.const 4544
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 18
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 656
      i32.add
      local.get 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 576
      i32.add
      local.get 15
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 592
      i32.add
      local.get 10
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 640
      i32.add
      local.get 13
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=688
      local.set 14
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 17
        local.get 18
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 15
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=600
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=584
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 640
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=592
        local.get 5
        i64.load offset=576
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 18
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=552
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=568
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 656
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=544
        local.get 5
        i64.load offset=560
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=720
        local.tee 15
        local.get 5
        i32.const 672
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=672
        local.tee 12
        local.get 5
        i32.const 688
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 5
        i32.const 704
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=704
        local.tee 12
        local.get 8
        i64.add
        local.tee 18
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 19
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=624
        local.tee 20
        local.get 5
        i64.load offset=608
        i64.add
        local.tee 21
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=640
        local.tee 22
        local.get 5
        i64.load offset=656
        i64.add
        local.tee 23
        i64.add
        local.tee 24
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 720
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 19
        local.get 17
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 624
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 608
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 21
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 23
        local.get 22
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 14
      i64.store offset=4768
      local.get 5
      local.get 18
      i64.store offset=4776
      local.get 5
      local.get 24
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    block  ;; label = @1
      local.get 16
      i64.const 524288
      i64.and
      i64.eqz
      br_if 0 (;@1;)
      i32.const 66448
      local.get 5
      i32.const 4576
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 496
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i64.load offset=4576
      local.tee 16
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 480
      i32.add
      local.get 12
      i64.const 0
      local.get 16
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 512
      i32.add
      local.get 8
      i64.const 0
      local.get 5
      i32.const 4576
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 528
      i32.add
      local.get 12
      i64.const 0
      local.get 14
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 432
      i32.add
      local.get 8
      local.get 12
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 416
      i32.add
      local.get 16
      local.get 14
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 368
      i32.add
      local.get 12
      i64.const 0
      local.get 5
      i32.const 4576
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 15
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 352
      i32.add
      local.get 5
      i32.const 4576
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 17
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 464
      i32.add
      local.get 15
      i64.const 0
      local.get 8
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 384
      i32.add
      local.get 14
      i64.const 0
      local.get 13
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 400
      i32.add
      local.get 10
      i64.const 0
      local.get 16
      i64.const 0
      call $__multi3
      local.get 5
      i32.const 448
      i32.add
      local.get 13
      i64.const 0
      local.get 16
      i64.const 0
      call $__multi3
      local.get 5
      i64.load offset=496
      local.set 16
      block  ;; label = @2
        local.get 13
        local.get 10
        i64.or
        i64.const 0
        i64.ne
        local.get 15
        local.get 17
        i64.or
        i64.const 0
        i64.ne
        i32.and
        local.get 10
        i64.const 0
        i64.ne
        local.get 14
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=408
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=392
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 448
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 8
        local.get 5
        i64.load offset=400
        local.get 5
        i64.load offset=384
        i64.add
        i64.add
        local.tee 10
        local.get 8
        i64.lt_u
        i32.or
        i32.or
        local.get 17
        i64.const 0
        i64.ne
        local.get 12
        i64.const 0
        i64.ne
        i32.and
        local.get 5
        i64.load offset=360
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i64.load offset=376
        i64.const 0
        i64.ne
        i32.or
        local.get 5
        i32.const 464
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 12
        local.get 5
        i64.load offset=352
        local.get 5
        i64.load offset=368
        i64.add
        i64.add
        local.tee 13
        local.get 12
        i64.lt_u
        i32.or
        i32.or
        local.get 5
        i64.load offset=528
        local.tee 14
        local.get 5
        i32.const 480
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=480
        local.tee 12
        local.get 5
        i32.const 496
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 15
        local.get 5
        i32.const 512
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i64.load offset=512
        local.tee 12
        local.get 8
        i64.add
        local.tee 17
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 18
        i64.add
        local.tee 12
        local.get 5
        i64.load offset=432
        local.tee 19
        local.get 5
        i64.load offset=416
        i64.add
        local.tee 20
        i64.add
        local.tee 8
        local.get 5
        i64.load offset=448
        local.tee 21
        local.get 5
        i64.load offset=464
        i64.add
        local.tee 22
        i64.add
        local.tee 23
        local.get 8
        i64.lt_u
        local.tee 6
        local.get 5
        i32.const 528
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 18
        local.get 15
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 12
        local.get 14
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 5
        i32.const 432
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 5
        i32.const 416
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 20
        local.get 19
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 10
        local.get 13
        i64.add
        local.get 22
        local.get 21
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 8
        local.get 12
        i64.lt_u
        local.get 8
        local.get 12
        i64.eq
        select
        i32.or
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
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
      local.get 5
      i32.const 4768
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 5
      local.get 16
      i64.store offset=4768
      local.get 5
      local.get 17
      i64.store offset=4776
      local.get 5
      local.get 23
      i64.store offset=4784
      local.get 5
      i32.const 4768
      i32.add
      i32.const 128
      local.get 5
      i32.const 4736
      i32.add
      call $wrapper_u256_shr
      local.get 5
      i32.const 4736
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 10
      local.get 5
      i32.const 4736
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 13
      local.get 5
      i32.const 4736
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 5
      i64.load offset=4736
      local.set 8
    end
    local.get 5
    i32.const 4768
    i32.add
    i32.const 24
    i32.add
    local.tee 25
    local.get 4
    i64.store
    local.get 5
    local.get 1
    i64.store offset=4768
    local.get 5
    local.get 2
    i64.store offset=4776
    local.get 5
    local.get 3
    i64.store offset=4784
    i32.const 2
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $wrapper_sign_extend
    local.get 5
    i32.const 4736
    i32.add
    i32.const 8
    i32.add
    local.tee 26
    i64.load
    local.set 4
    local.get 5
    i32.const 4736
    i32.add
    i32.const 16
    i32.add
    local.tee 27
    i64.load
    local.set 3
    local.get 5
    i32.const 4736
    i32.add
    i32.const 24
    i32.add
    local.tee 28
    i64.load
    local.set 16
    local.get 5
    i64.load offset=4736
    local.set 2
    local.get 25
    i64.const 0
    i64.store
    local.get 5
    i64.const 0
    i64.store offset=4784
    local.get 5
    i64.const 0
    i64.store offset=4776
    local.get 5
    i64.const 0
    i64.store offset=4768
    i32.const 2
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $wrapper_sign_extend
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        local.get 5
        i64.load offset=4736
        i64.le_u
        local.get 4
        local.get 26
        i64.load
        local.tee 2
        i64.le_u
        local.get 4
        local.get 2
        i64.eq
        select
        local.get 3
        local.get 27
        i64.load
        local.tee 2
        i64.le_u
        local.get 16
        local.get 28
        i64.load
        local.tee 4
        i64.le_s
        local.get 16
        local.get 4
        i64.eq
        select
        local.get 3
        local.get 2
        i64.xor
        local.get 16
        local.get 4
        i64.xor
        i64.or
        i64.eqz
        select
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        local.set 29
        local.get 12
        local.set 30
        local.get 13
        local.set 31
        local.get 10
        local.set 32
        br 1 (;@1;)
      end
      i32.const 66480
      local.get 5
      i32.const 4608
      i32.add
      call $u256_from_big_endian_bytes
      local.get 5
      i32.const 4608
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 16
      local.get 5
      i32.const 4608
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 5
      i32.const 4608
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 2
      local.get 5
      i64.load offset=4608
      local.set 20
      block  ;; label = @2
        local.get 8
        local.get 13
        i64.or
        local.get 12
        local.get 10
        i64.or
        i64.or
        local.tee 3
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65776
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      i64.const 0
      local.get 16
      local.get 3
      i64.eqz
      local.get 20
      local.get 4
      i64.or
      local.get 2
      local.get 16
      i64.or
      i64.or
      i64.eqz
      i32.or
      i64.const 0
      local.get 10
      i64.clz
      local.get 13
      i64.clz
      i64.const 64
      i64.add
      local.get 10
      i64.const 0
      i64.ne
      select
      local.get 12
      i64.clz
      local.get 8
      i64.clz
      i64.const 64
      i64.add
      local.get 12
      i64.const 0
      i64.ne
      select
      local.tee 3
      i64.const 128
      i64.add
      local.tee 1
      local.get 13
      local.get 10
      i64.or
      i64.const 0
      i64.ne
      local.tee 6
      select
      local.tee 14
      local.get 16
      i64.clz
      local.get 4
      i64.clz
      i64.const 64
      i64.add
      local.get 16
      i64.const 0
      i64.ne
      select
      local.get 2
      i64.clz
      local.get 20
      i64.clz
      i64.const 64
      i64.add
      local.get 2
      i64.const 0
      i64.ne
      select
      local.tee 15
      i64.const 128
      i64.add
      local.tee 17
      local.get 4
      local.get 16
      i64.or
      i64.const 0
      i64.ne
      local.tee 7
      select
      local.tee 18
      i64.lt_u
      local.tee 9
      i64.const 0
      local.get 1
      local.get 3
      i64.lt_u
      i64.extend_i32_u
      local.get 6
      select
      local.tee 3
      i64.const 0
      local.get 17
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      local.get 7
      select
      local.tee 1
      i64.lt_u
      local.get 3
      local.get 1
      i64.eq
      select
      local.tee 6
      i64.extend_i32_u
      i64.sub
      local.tee 23
      i64.const 0
      i64.ne
      i64.const 0
      local.get 6
      i32.const 0
      i32.ne
      i64.extend_i32_u
      i64.sub
      local.tee 22
      i64.const 0
      i64.ne
      local.get 22
      i64.eqz
      select
      local.get 14
      local.get 18
      i64.sub
      local.tee 19
      i64.const 255
      i64.gt_u
      local.get 3
      local.get 1
      i64.sub
      local.get 9
      i64.extend_i32_u
      i64.sub
      local.tee 21
      i64.const 0
      i64.ne
      local.get 21
      i64.eqz
      select
      local.get 6
      select
      i32.or
      local.tee 6
      select
      local.set 32
      i64.const 0
      local.get 4
      local.get 6
      select
      local.set 31
      i64.const 0
      local.get 2
      local.get 6
      select
      local.set 30
      i64.const 0
      local.get 20
      local.get 6
      select
      local.set 29
      local.get 6
      br_if 0 (;@1;)
      local.get 19
      i64.const 255
      i64.xor
      local.get 23
      i64.or
      local.get 21
      local.get 22
      i64.or
      i64.or
      i64.eqz
      br_if 0 (;@1;)
      local.get 5
      i32.const 288
      i32.add
      i32.const 40
      i32.add
      local.get 2
      i64.store align=1
      local.get 5
      i32.const 320
      i32.add
      local.tee 6
      local.get 20
      i64.store align=1
      i64.const 0
      local.set 33
      local.get 5
      i32.const 288
      i32.add
      i32.const 24
      i32.add
      i64.const 0
      i64.store align=1
      local.get 5
      i32.const 288
      i32.add
      i32.const 48
      i32.add
      local.get 4
      i64.store align=1
      local.get 5
      i32.const 288
      i32.add
      i32.const 56
      i32.add
      local.get 16
      i64.store align=1
      local.get 5
      i64.const 0
      i64.store offset=304 align=1
      local.get 5
      i64.const 0
      i64.store offset=296 align=1
      local.get 5
      i64.const 0
      i64.store offset=288 align=1
      local.get 6
      i32.const 255
      local.get 19
      i32.wrap_i64
      i32.sub
      local.tee 7
      i32.const 3
      i32.shr_u
      i32.const 31
      i32.and
      i32.sub
      local.tee 6
      i32.const 8
      i32.add
      i64.load align=1
      local.tee 1
      local.get 7
      i32.const 7
      i32.and
      local.tee 7
      i64.extend_i32_u
      local.tee 3
      i64.shl
      local.get 6
      i64.load align=1
      local.tee 17
      i64.const 1
      i64.shr_u
      local.get 7
      i32.const 63
      i32.xor
      i64.extend_i32_u
      local.tee 15
      i64.shr_u
      i64.or
      local.set 14
      local.get 6
      i32.const 24
      i32.add
      i64.load align=1
      local.get 3
      i64.shl
      local.get 6
      i32.const 16
      i32.add
      i64.load align=1
      local.tee 24
      i64.const 1
      i64.shr_u
      local.get 15
      i64.shr_u
      i64.or
      local.set 18
      local.get 24
      local.get 3
      i64.shl
      local.get 1
      i64.const 1
      i64.shr_u
      local.get 7
      i32.const -1
      i32.xor
      i32.const 63
      i32.and
      i64.extend_i32_u
      i64.shr_u
      i64.or
      local.set 15
      local.get 17
      local.get 3
      i64.shl
      local.set 17
      block  ;; label = @2
        block  ;; label = @3
          local.get 19
          i64.const 1
          i64.add
          local.tee 1
          local.get 23
          local.get 1
          local.get 19
          i64.lt_u
          local.tee 6
          local.get 21
          local.get 6
          i64.extend_i32_u
          i64.add
          local.tee 3
          local.get 21
          i64.lt_u
          local.get 1
          local.get 19
          i64.ge_u
          select
          i64.extend_i32_u
          i64.add
          local.tee 19
          i64.or
          local.get 3
          local.get 22
          local.get 19
          local.get 23
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.tee 34
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 30
          local.get 5
          i32.const 224
          i32.add
          i32.const 56
          i32.add
          i64.const 0
          i64.store align=1
          local.get 5
          i32.const 224
          i32.add
          i32.const 48
          i32.add
          i64.const 0
          i64.store align=1
          local.get 5
          i32.const 224
          i32.add
          i32.const 40
          i32.add
          i64.const 0
          i64.store align=1
          local.get 5
          i32.const 224
          i32.add
          i32.const 24
          i32.add
          local.get 16
          i64.store align=1
          local.get 5
          i64.const 0
          i64.store offset=256 align=1
          local.get 5
          local.get 20
          i64.store offset=224 align=1
          local.get 5
          local.get 2
          i64.store offset=232 align=1
          local.get 5
          local.get 4
          i64.store offset=240 align=1
          local.get 5
          i32.const 224
          i32.add
          local.get 1
          i32.wrap_i64
          local.tee 7
          i32.const 3
          i32.shr_u
          i32.const 31
          i32.and
          i32.add
          local.tee 6
          i32.const 16
          i32.add
          i64.load align=1
          local.tee 4
          local.get 1
          i64.const 7
          i64.and
          local.tee 16
          i64.shr_u
          local.get 6
          i32.const 24
          i32.add
          i64.load align=1
          local.tee 2
          i64.const 1
          i64.shl
          local.get 7
          i32.const 7
          i32.and
          local.tee 7
          i32.const 63
          i32.xor
          i64.extend_i32_u
          local.tee 22
          i64.shl
          i64.or
          local.set 20
          local.get 6
          i32.const 8
          i32.add
          i64.load align=1
          local.tee 23
          local.get 16
          i64.shr_u
          local.get 4
          i64.const 1
          i64.shl
          local.get 7
          i32.const -1
          i32.xor
          i32.const 63
          i32.and
          i64.extend_i32_u
          i64.shl
          i64.or
          local.set 21
          local.get 6
          i64.load align=1
          local.get 16
          i64.shr_u
          local.get 23
          i64.const 1
          i64.shl
          local.get 22
          i64.shl
          i64.or
          local.set 22
          local.get 10
          local.get 13
          i64.const -1
          i64.add
          local.tee 4
          local.get 13
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 4
          local.get 8
          i64.const -1
          i64.add
          local.tee 35
          local.get 8
          i64.lt_u
          local.tee 6
          local.get 12
          local.get 6
          i64.extend_i32_u
          i64.add
          i64.const -1
          i64.add
          local.tee 24
          local.get 12
          i64.lt_u
          local.get 24
          local.get 12
          i64.eq
          select
          i64.extend_i32_u
          i64.add
          local.tee 36
          local.get 4
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.const -1
          i64.add
          local.set 37
          local.get 2
          local.get 16
          i64.shr_u
          local.set 38
          i64.const 0
          local.set 39
          loop  ;; label = @4
            local.get 20
            i64.const 1
            i64.shl
            local.get 21
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 2
            local.get 37
            local.get 38
            i64.const 1
            i64.shl
            local.get 20
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 38
            i64.sub
            local.get 36
            local.get 2
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.get 36
            local.get 2
            i64.sub
            local.get 35
            local.get 22
            i64.const 1
            i64.shl
            local.get 18
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 23
            i64.lt_u
            local.get 24
            local.get 21
            i64.const 1
            i64.shl
            local.get 22
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 16
            i64.lt_u
            local.get 24
            local.get 16
            i64.eq
            select
            i64.extend_i32_u
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            i64.const 63
            i64.shr_s
            local.tee 4
            local.get 13
            i64.and
            local.tee 22
            i64.sub
            local.tee 40
            local.get 23
            local.get 4
            local.get 8
            i64.and
            local.tee 41
            i64.lt_u
            local.tee 6
            local.get 16
            local.get 4
            local.get 12
            i64.and
            local.tee 21
            i64.lt_u
            local.get 16
            local.get 21
            i64.eq
            select
            i64.extend_i32_u
            local.tee 33
            i64.sub
            local.set 20
            local.get 38
            local.get 4
            local.get 10
            i64.and
            i64.sub
            local.get 2
            local.get 22
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.get 40
            local.get 33
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.set 38
            local.get 16
            local.get 21
            i64.sub
            local.get 6
            i64.extend_i32_u
            i64.sub
            local.set 21
            local.get 23
            local.get 41
            i64.sub
            local.set 22
            local.get 3
            local.get 1
            i64.const -1
            i64.add
            local.tee 2
            local.get 1
            i64.lt_u
            local.tee 6
            i64.extend_i32_u
            i64.add
            i64.const -1
            i64.add
            local.tee 16
            local.get 3
            i64.eq
            local.set 7
            local.get 16
            local.get 3
            i64.lt_u
            local.set 9
            local.get 19
            i64.const -1
            i64.add
            local.tee 23
            local.get 19
            i64.lt_u
            local.set 11
            local.get 17
            i64.const 63
            i64.shr_u
            local.set 40
            local.get 14
            i64.const 63
            i64.shr_u
            local.set 41
            i64.const 0
            local.get 18
            i64.const 1
            i64.shl
            local.get 15
            i64.const 63
            i64.shr_u
            i64.or
            i64.or
            local.set 18
            local.get 39
            local.get 17
            i64.const 1
            i64.shl
            i64.or
            local.set 17
            local.get 4
            i64.const 1
            i64.and
            local.tee 33
            local.set 39
            local.get 2
            local.set 1
            local.get 16
            local.set 3
            local.get 23
            local.get 6
            local.get 9
            local.get 7
            select
            i64.extend_i32_u
            i64.add
            local.tee 4
            local.set 19
            i64.const 0
            local.get 40
            local.get 14
            i64.const 1
            i64.shl
            i64.or
            i64.or
            local.tee 40
            local.set 14
            i64.const 0
            local.get 41
            local.get 15
            i64.const 1
            i64.shl
            i64.or
            i64.or
            local.tee 41
            local.set 15
            local.get 2
            local.get 4
            i64.or
            local.get 16
            local.get 34
            local.get 11
            i64.extend_i32_u
            i64.add
            local.get 4
            local.get 23
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.const -1
            i64.add
            local.tee 34
            i64.or
            i64.or
            i64.eqz
            i32.eqz
            br_if 0 (;@4;)
          end
          i64.const 0
          local.set 12
          i64.const 0
          local.set 8
          local.get 40
          local.set 14
          local.get 41
          local.set 15
          br 1 (;@2;)
        end
        i64.const 0
        local.set 30
        i64.const 0
        local.set 12
        i64.const 0
        local.set 8
      end
      local.get 30
      local.get 14
      i64.const 1
      i64.shl
      local.get 17
      i64.const 63
      i64.shr_u
      i64.or
      i64.or
      local.set 30
      local.get 12
      local.get 15
      i64.const 1
      i64.shl
      local.get 14
      i64.const 63
      i64.shr_u
      i64.or
      i64.or
      local.set 31
      local.get 8
      local.get 18
      i64.const 1
      i64.shl
      local.get 15
      i64.const 63
      i64.shr_u
      i64.or
      i64.or
      local.set 32
      local.get 33
      local.get 17
      i64.const 1
      i64.shl
      i64.or
      local.set 29
    end
    local.get 25
    local.get 32
    i64.store
    local.get 5
    local.get 29
    i64.store offset=4768
    local.get 5
    local.get 30
    i64.store offset=4776
    local.get 5
    local.get 31
    i64.store offset=4784
    local.get 5
    i32.const 4768
    i32.add
    i32.const 32
    local.get 5
    i32.const 4736
    i32.add
    call $wrapper_u256_shr
    local.get 28
    i64.load
    local.set 42
    local.get 27
    i64.load
    local.set 43
    local.get 26
    i64.load
    local.set 44
    local.get 5
    i64.load offset=4736
    local.set 45
    i32.const 66512
    local.get 5
    i32.const 4640
    i32.add
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 5
      i64.load offset=4640
      local.tee 40
      local.get 5
      i32.const 4640
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 33
      i64.or
      local.get 5
      i32.const 4640
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 39
      local.get 5
      i32.const 4640
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 41
      i64.or
      i64.or
      local.tee 12
      i64.const 0
      i64.ne
      br_if 0 (;@1;)
      i32.const 0
      i32.const 65776
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 18
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    i64.const 0
    local.get 32
    local.get 12
    i64.eqz
    local.get 29
    local.get 31
    i64.or
    local.get 30
    local.get 32
    i64.or
    i64.or
    i64.eqz
    i32.or
    i64.const 0
    local.get 41
    i64.clz
    local.get 33
    i64.clz
    i64.const 64
    i64.add
    local.get 41
    i64.const 0
    i64.ne
    select
    local.get 39
    i64.clz
    local.get 40
    i64.clz
    i64.const 64
    i64.add
    local.get 39
    i64.const 0
    i64.ne
    select
    local.tee 12
    i64.const 128
    i64.add
    local.tee 8
    local.get 33
    local.get 41
    i64.or
    i64.const 0
    i64.ne
    local.tee 6
    select
    local.tee 10
    local.get 32
    i64.clz
    local.get 31
    i64.clz
    i64.const 64
    i64.add
    local.get 32
    i64.const 0
    i64.ne
    select
    local.get 30
    i64.clz
    local.get 29
    i64.clz
    i64.const 64
    i64.add
    local.get 30
    i64.const 0
    i64.ne
    select
    local.tee 13
    i64.const 128
    i64.add
    local.tee 16
    local.get 31
    local.get 32
    i64.or
    i64.const 0
    i64.ne
    local.tee 7
    select
    local.tee 4
    i64.lt_u
    local.tee 9
    i64.const 0
    local.get 8
    local.get 12
    i64.lt_u
    i64.extend_i32_u
    local.get 6
    select
    local.tee 12
    i64.const 0
    local.get 16
    local.get 13
    i64.lt_u
    i64.extend_i32_u
    local.get 7
    select
    local.tee 8
    i64.lt_u
    local.get 12
    local.get 8
    i64.eq
    select
    local.tee 6
    i64.extend_i32_u
    i64.sub
    local.tee 17
    i64.const 0
    i64.ne
    i64.const 0
    local.get 6
    i32.const 0
    i32.ne
    i64.extend_i32_u
    i64.sub
    local.tee 15
    i64.const 0
    i64.ne
    local.get 15
    i64.eqz
    select
    local.get 10
    local.get 4
    i64.sub
    local.tee 14
    i64.const 255
    i64.gt_u
    local.get 12
    local.get 8
    i64.sub
    local.get 9
    i64.extend_i32_u
    i64.sub
    local.tee 13
    i64.const 0
    i64.ne
    local.get 13
    i64.eqz
    select
    local.get 6
    select
    i32.or
    local.tee 6
    select
    local.set 10
    i64.const 0
    local.get 31
    local.get 6
    select
    local.set 16
    i64.const 0
    local.get 30
    local.get 6
    select
    local.set 12
    i64.const 0
    local.get 29
    local.get 6
    select
    local.set 8
    block  ;; label = @1
      local.get 6
      br_if 0 (;@1;)
      local.get 14
      i64.const 255
      i64.xor
      local.get 17
      i64.or
      local.get 13
      local.get 15
      i64.or
      i64.or
      i64.eqz
      br_if 0 (;@1;)
      local.get 5
      i32.const 160
      i32.add
      i32.const 40
      i32.add
      local.get 30
      i64.store align=1
      local.get 5
      i32.const 192
      i32.add
      local.tee 6
      local.get 29
      i64.store align=1
      i64.const 0
      local.set 38
      local.get 5
      i32.const 160
      i32.add
      i32.const 24
      i32.add
      i64.const 0
      i64.store align=1
      local.get 5
      i32.const 160
      i32.add
      i32.const 48
      i32.add
      local.get 31
      i64.store align=1
      local.get 5
      i32.const 160
      i32.add
      i32.const 56
      i32.add
      local.get 32
      i64.store align=1
      local.get 5
      i64.const 0
      i64.store offset=176 align=1
      local.get 5
      i64.const 0
      i64.store offset=168 align=1
      local.get 5
      i64.const 0
      i64.store offset=160 align=1
      local.get 6
      i32.const 255
      local.get 14
      i32.wrap_i64
      i32.sub
      local.tee 7
      i32.const 3
      i32.shr_u
      i32.const 31
      i32.and
      i32.sub
      local.tee 6
      i32.const 8
      i32.add
      i64.load align=1
      local.tee 8
      local.get 7
      i32.const 7
      i32.and
      local.tee 7
      i64.extend_i32_u
      local.tee 12
      i64.shl
      local.get 6
      i64.load align=1
      local.tee 10
      i64.const 1
      i64.shr_u
      local.get 7
      i32.const 63
      i32.xor
      i64.extend_i32_u
      local.tee 16
      i64.shr_u
      i64.or
      local.set 4
      local.get 6
      i32.const 24
      i32.add
      i64.load align=1
      local.get 12
      i64.shl
      local.get 6
      i32.const 16
      i32.add
      i64.load align=1
      local.tee 3
      i64.const 1
      i64.shr_u
      local.get 16
      i64.shr_u
      i64.or
      local.set 1
      local.get 3
      local.get 12
      i64.shl
      local.get 8
      i64.const 1
      i64.shr_u
      local.get 7
      i32.const -1
      i32.xor
      i32.const 63
      i32.and
      i64.extend_i32_u
      i64.shr_u
      i64.or
      local.set 3
      local.get 10
      local.get 12
      i64.shl
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 14
          i64.const 1
          i64.add
          local.tee 16
          local.get 17
          local.get 16
          local.get 14
          i64.lt_u
          local.tee 6
          local.get 13
          local.get 6
          i64.extend_i32_u
          i64.add
          local.tee 10
          local.get 13
          i64.lt_u
          local.get 16
          local.get 14
          i64.ge_u
          select
          i64.extend_i32_u
          i64.add
          local.tee 14
          i64.or
          local.get 10
          local.get 15
          local.get 14
          local.get 17
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.tee 21
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 46
          local.get 5
          i32.const 96
          i32.add
          i32.const 56
          i32.add
          i64.const 0
          i64.store align=1
          local.get 5
          i32.const 96
          i32.add
          i32.const 48
          i32.add
          i64.const 0
          i64.store align=1
          local.get 5
          i32.const 96
          i32.add
          i32.const 40
          i32.add
          i64.const 0
          i64.store align=1
          local.get 5
          i32.const 96
          i32.add
          i32.const 24
          i32.add
          local.get 32
          i64.store align=1
          local.get 5
          i64.const 0
          i64.store offset=128 align=1
          local.get 5
          local.get 29
          i64.store offset=96 align=1
          local.get 5
          local.get 30
          i64.store offset=104 align=1
          local.get 5
          local.get 31
          i64.store offset=112 align=1
          local.get 5
          i32.const 96
          i32.add
          local.get 16
          i32.wrap_i64
          local.tee 7
          i32.const 3
          i32.shr_u
          i32.const 31
          i32.and
          i32.add
          local.tee 6
          i32.const 16
          i32.add
          i64.load align=1
          local.tee 8
          local.get 16
          i64.const 7
          i64.and
          local.tee 12
          i64.shr_u
          local.get 6
          i32.const 24
          i32.add
          i64.load align=1
          local.tee 13
          i64.const 1
          i64.shl
          local.get 7
          i32.const 7
          i32.and
          local.tee 7
          i32.const 63
          i32.xor
          i64.extend_i32_u
          local.tee 18
          i64.shl
          i64.or
          local.set 15
          local.get 6
          i32.const 8
          i32.add
          i64.load align=1
          local.tee 19
          local.get 12
          i64.shr_u
          local.get 8
          i64.const 1
          i64.shl
          local.get 7
          i32.const -1
          i32.xor
          i32.const 63
          i32.and
          i64.extend_i32_u
          i64.shl
          i64.or
          local.set 17
          local.get 6
          i64.load align=1
          local.get 12
          i64.shr_u
          local.get 19
          i64.const 1
          i64.shl
          local.get 18
          i64.shl
          i64.or
          local.set 18
          local.get 41
          local.get 33
          i64.const -1
          i64.add
          local.tee 8
          local.get 33
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 8
          local.get 40
          i64.const -1
          i64.add
          local.tee 35
          local.get 40
          i64.lt_u
          local.tee 6
          local.get 39
          local.get 6
          i64.extend_i32_u
          i64.add
          i64.const -1
          i64.add
          local.tee 20
          local.get 39
          i64.lt_u
          local.get 20
          local.get 39
          i64.eq
          select
          i64.extend_i32_u
          i64.add
          local.tee 22
          local.get 8
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.const -1
          i64.add
          local.set 37
          local.get 13
          local.get 12
          i64.shr_u
          local.set 23
          i64.const 0
          local.set 24
          loop  ;; label = @4
            local.get 15
            i64.const 1
            i64.shl
            local.get 17
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 13
            local.get 37
            local.get 23
            i64.const 1
            i64.shl
            local.get 15
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 23
            i64.sub
            local.get 22
            local.get 13
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.get 22
            local.get 13
            i64.sub
            local.get 35
            local.get 18
            i64.const 1
            i64.shl
            local.get 1
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 19
            i64.lt_u
            local.get 20
            local.get 17
            i64.const 1
            i64.shl
            local.get 18
            i64.const 63
            i64.shr_u
            i64.or
            local.tee 12
            i64.lt_u
            local.get 20
            local.get 12
            i64.eq
            select
            i64.extend_i32_u
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            i64.const 63
            i64.shr_s
            local.tee 8
            local.get 33
            i64.and
            local.tee 18
            i64.sub
            local.tee 34
            local.get 19
            local.get 8
            local.get 40
            i64.and
            local.tee 36
            i64.lt_u
            local.tee 6
            local.get 12
            local.get 8
            local.get 39
            i64.and
            local.tee 17
            i64.lt_u
            local.get 12
            local.get 17
            i64.eq
            select
            i64.extend_i32_u
            local.tee 38
            i64.sub
            local.set 15
            local.get 23
            local.get 8
            local.get 41
            i64.and
            i64.sub
            local.get 13
            local.get 18
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.get 34
            local.get 38
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.set 23
            local.get 12
            local.get 17
            i64.sub
            local.get 6
            i64.extend_i32_u
            i64.sub
            local.set 17
            local.get 19
            local.get 36
            i64.sub
            local.set 18
            local.get 10
            local.get 16
            i64.const -1
            i64.add
            local.tee 13
            local.get 16
            i64.lt_u
            local.tee 6
            i64.extend_i32_u
            i64.add
            i64.const -1
            i64.add
            local.tee 12
            local.get 10
            i64.eq
            local.set 7
            local.get 12
            local.get 10
            i64.lt_u
            local.set 9
            local.get 14
            i64.const -1
            i64.add
            local.tee 19
            local.get 14
            i64.lt_u
            local.set 11
            local.get 2
            i64.const 63
            i64.shr_u
            local.set 34
            local.get 4
            i64.const 63
            i64.shr_u
            local.set 36
            i64.const 0
            local.get 1
            i64.const 1
            i64.shl
            local.get 3
            i64.const 63
            i64.shr_u
            i64.or
            i64.or
            local.set 1
            local.get 24
            local.get 2
            i64.const 1
            i64.shl
            i64.or
            local.set 2
            local.get 8
            i64.const 1
            i64.and
            local.tee 38
            local.set 24
            local.get 13
            local.set 16
            local.get 12
            local.set 10
            local.get 19
            local.get 6
            local.get 9
            local.get 7
            select
            i64.extend_i32_u
            i64.add
            local.tee 8
            local.set 14
            i64.const 0
            local.get 34
            local.get 4
            i64.const 1
            i64.shl
            i64.or
            i64.or
            local.tee 34
            local.set 4
            i64.const 0
            local.get 36
            local.get 3
            i64.const 1
            i64.shl
            i64.or
            i64.or
            local.tee 36
            local.set 3
            local.get 13
            local.get 8
            i64.or
            local.get 12
            local.get 21
            local.get 11
            i64.extend_i32_u
            i64.add
            local.get 8
            local.get 19
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.const -1
            i64.add
            local.tee 21
            i64.or
            i64.or
            i64.eqz
            i32.eqz
            br_if 0 (;@4;)
          end
          i64.const 0
          local.set 8
          i64.const 0
          local.set 10
          local.get 34
          local.set 4
          local.get 36
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 46
        i64.const 0
        local.set 8
        i64.const 0
        local.set 10
      end
      local.get 46
      local.get 4
      i64.const 1
      i64.shl
      local.get 2
      i64.const 63
      i64.shr_u
      i64.or
      i64.or
      local.set 12
      local.get 8
      local.get 3
      i64.const 1
      i64.shl
      local.get 4
      i64.const 63
      i64.shr_u
      i64.or
      i64.or
      local.set 16
      local.get 10
      local.get 1
      i64.const 1
      i64.shl
      local.get 3
      i64.const 63
      i64.shr_u
      i64.or
      i64.or
      local.set 10
      local.get 38
      local.get 2
      i64.const 1
      i64.shl
      i64.or
      local.set 8
    end
    local.get 5
    i32.const 80
    i32.add
    local.get 8
    local.get 12
    local.get 33
    local.get 41
    call $__multi3
    local.get 5
    i32.const 64
    i32.add
    local.get 16
    local.get 10
    local.get 40
    local.get 39
    call $__multi3
    local.get 5
    i32.const 16
    i32.add
    local.get 40
    i64.const 0
    local.get 8
    i64.const 0
    call $__multi3
    local.get 5
    local.get 39
    i64.const 0
    local.get 8
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 32
    i32.add
    local.get 40
    i64.const 0
    local.get 12
    i64.const 0
    call $__multi3
    local.get 5
    i32.const 48
    i32.add
    local.get 39
    i64.const 0
    local.get 12
    i64.const 0
    call $__multi3
    block  ;; label = @1
      local.get 43
      local.get 45
      local.get 29
      local.get 5
      i64.load offset=16
      local.tee 13
      i64.sub
      local.get 31
      local.get 5
      i64.load offset=48
      local.tee 16
      local.get 5
      i32.const 8
      i32.add
      i64.load
      local.get 5
      i64.load
      local.tee 12
      local.get 5
      i32.const 16
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.add
      local.tee 8
      local.get 12
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 4
      local.get 5
      i32.const 32
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 5
      i64.load offset=32
      local.tee 10
      local.get 8
      i64.add
      local.tee 12
      local.get 10
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.add
      local.tee 3
      i64.add
      local.tee 8
      local.get 5
      i64.load offset=64
      local.tee 2
      local.get 5
      i64.load offset=80
      i64.add
      local.tee 1
      i64.add
      local.tee 10
      i64.sub
      local.tee 14
      local.get 29
      local.get 13
      i64.lt_u
      local.tee 6
      local.get 30
      local.get 12
      i64.lt_u
      local.get 30
      local.get 12
      i64.eq
      select
      i64.extend_i32_u
      local.tee 13
      i64.sub
      i64.or
      local.get 30
      local.get 12
      i64.sub
      local.get 6
      i64.extend_i32_u
      i64.sub
      local.get 32
      local.get 5
      i32.const 48
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 3
      local.get 4
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 8
      local.get 16
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 5
      i32.const 64
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 5
      i32.const 80
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.add
      local.get 1
      local.get 2
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.add
      local.get 10
      local.get 8
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.sub
      local.get 31
      local.get 10
      i64.lt_u
      i64.extend_i32_u
      i64.sub
      local.get 14
      local.get 13
      i64.lt_u
      i64.extend_i32_u
      i64.sub
      i64.or
      i64.or
      i64.const 0
      i64.ne
      i64.extend_i32_u
      i64.add
      local.tee 12
      local.get 45
      i64.lt_u
      local.tee 6
      local.get 44
      local.get 6
      i64.extend_i32_u
      i64.add
      local.tee 8
      local.get 44
      i64.lt_u
      local.get 12
      local.get 45
      i64.ge_u
      local.tee 6
      select
      local.tee 7
      i64.extend_i32_u
      i64.add
      local.tee 10
      local.get 43
      i64.ge_u
      local.tee 9
      local.get 42
      local.get 10
      local.get 43
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 13
      local.get 42
      i64.ge_u
      local.get 9
      select
      local.get 6
      local.get 8
      local.get 44
      i64.ge_u
      local.get 6
      select
      local.get 7
      select
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
    local.get 5
    i32.const 4768
    i32.add
    i32.const 24
    i32.add
    local.get 13
    i64.store
    local.get 5
    local.get 10
    i64.store offset=4784
    local.get 5
    local.get 8
    i64.store offset=4776
    local.get 5
    local.get 12
    i64.store offset=4768
    local.get 5
    i32.const 4768
    i32.add
    local.get 5
    i32.const 4704
    i32.add
    call $u256_to_big_endian_bytes
    local.get 5
    i32.const 4704
    i32.add
    i32.const 65584
    local.get 5
    i32.const 4672
    i32.add
    call $wrapper_bytes32_and
    local.get 5
    i32.const 4672
    i32.add
    local.get 5
    i32.const 4736
    i32.add
    call $u256_from_big_endian_bytes
    local.get 5
    i32.const 4736
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 12
    local.get 5
    i32.const 4736
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 8
    local.get 5
    i64.load offset=4736
    local.set 10
    local.get 0
    local.get 5
    i32.const 4752
    i32.add
    i64.load
    i64.store offset=16
    local.get 0
    local.get 8
    i64.store offset=8
    local.get 0
    local.get 10
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 12
    i64.store
    local.get 5
    i32.const 4800
    i32.add
    global.set $__stack_pointer)
  (func $call (type 4)
    (local i32)
    global.get $__stack_pointer
    i32.const 96
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
      call $wrapper_calldataload_bytes32
      local.get 0
      local.get 0
      i32.const 64
      i32.add
      call $u256_from_big_endian_bytes
      local.get 0
      i32.const 64
      i32.add
      i32.const 224
      local.get 0
      i32.const 32
      i32.add
      call $wrapper_u256_shr
      local.get 0
      i64.load offset=32
      i64.const 1249760547
      i64.xor
      local.get 0
      i32.const 48
      i32.add
      i64.load
      i64.or
      local.get 0
      i32.const 40
      i32.add
      i64.load
      local.get 0
      i32.const 56
      i32.add
      i64.load
      i64.or
      i64.or
      i64.const 0
      i64.ne
      br_if 0 (;@1;)
      call $TickMathPilot_27_deployed.TickMathPilot_27_deployed.external_fun_generate_26
    end
    i32.const 0
    i32.const 0
    call $wrapper_revert
    local.get 0
    i32.const 96
    i32.add
    global.set $__stack_pointer)
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
    i32.const 83072
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
  (data (;2;) (i32.const 65596) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\80")
  (data (;3;) (i32.const 65648) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\f2v\18\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\80\00\00\08\c3y\a0")
  (data (;4;) (i32.const 65759) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ffNH{q")
  (data (;5;) (i32.const 65823) "\01")
  (data (;6;) (i32.const 65856) "\ff\fc\b93\bdo\ad7\aa-\16-\1aY@\01")
  (data (;7;) (i32.const 65888) "\ff\f9rr7=A2Y\a4i\90X\0e!:")
  (data (;8;) (i32.const 65920) "\ff\f2\e5\0f_ei2\ef\125|\f3\c7\fd\cc")
  (data (;9;) (i32.const 65952) "\ff\e5\ca\ca~\10\e4\e6\1c6$\ea\a0\94\1c\d0")
  (data (;10;) (i32.const 65984) "\ff\cb\98C\d6\0faY\c9\dbX\83\5c\92fD")
  (data (;11;) (i32.const 66016) "\ff\97;A\fa\98\c0\81G.h\96\df\b2T\c0")
  (data (;12;) (i32.const 66048) "\ff.\a1df\c9j8C\ecx\b3&\b5(a")
  (data (;13;) (i32.const 66080) "\fe]\ee\04j\99\a2\a8\11\c4a\f1\96\9c0S")
  (data (;14;) (i32.const 66112) "\fc\be\86\c7\90\0a\88\ae\dc\ff\c8;G\9a\a3\a4")
  (data (;15;) (i32.const 66144) "\f9\87\a7%:\c4\13\17o+\07L\f7\81^T")
  (data (;16;) (i32.const 66176) "\f39+\08\22\b7\00\05\94\0cz9\8eKp\f3")
  (data (;17;) (i32.const 66208) "\e7\15\94u\a2\c2\9btC\b2\9c\7f\a6\e8\89\d9")
  (data (;18;) (i32.const 66240) "\d0\97\f3\bd\fd \22\b8\84Z\d8\f7\92\aaX%")
  (data (;19;) (i32.const 66272) "\a9\f7FF-\87\0f\df\8ae\dc\1f\90\e0a\e5")
  (data (;20;) (i32.const 66304) "p\d8i\a1V\d2\a1\b8\90\bb=\f6+\af2\f7")
  (data (;21;) (i32.const 66336) "1\be\13_\97\d0\8f\d9\81#\15\05T/\cf\a6")
  (data (;22;) (i32.const 66368) "\09\aaP\8b[z\84\e1\c6w\deT\f3\e9\9b\c9")
  (data (;23;) (i32.const 66401) "]j\f8\de\db\81\19f\99\c3)\22^\e6\04")
  (data (;24;) (i32.const 66434) "\22\16\e5\84\f5\fa\1e\a9&\04\1b\ed\fe\98")
  (data (;25;) (i32.const 66468) "\04\8a\17\03\91\f7\dcBDN\8f\a2\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;26;) (i32.const 66539) "\01")
  (data (;27;) (i32.const 66664) "\01")
  (data (;28;) (i32.const 66670) "\02\00\00\00\03")
  (data (;29;) (i32.const 66682) "\01")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "producers" "\02\08language\01\03C99\00\0cprocessed-by\02\05clangV11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\0cUbuntu clang@16.0.6 (++20231112100510+7cbf1a259152-1~exp1~20231112100554.106)")
  (@custom "name" "\01\d5\05\22\00\0fgetCallDataSize\01\0ccallDataCopy\02\0cgetCallValue\03\06revert\04\06finish\05\0bgetCodeSize\06\08codeCopy\07\11__wasm_call_ctors\08\08__multi3\09\1au256_from_big_endian_bytes\0a\18u256_to_big_endian_bytes\0b\1cwrapper_calldataload_bytes32\0c\15wrapper_calldata_size\0d\1awrapper_callvalue_not_zero\0e\0ewrapper_revert\0f\13evm_get_memory_addr\10\10wrapper_codecopy\11\14wrapper_memory_guard\12\16wrapper_mstore_bytes32\13\13wrapper_mstore_u256\14\12wrapper_mstore_u32\15\12wrapper_mload_u256\16\0ewrapper_return\17\13set_is_deploying_tx\18\13wrapper_sign_extend\19\0f__init_evm_heap\1a\12wrapper_bytes32_eq\1b\13wrapper_bytes32_and\1c\10wrapper_u256_shr\1dLTickMathPilot_27_deployed.TickMathPilot_27_deployed.external_fun_generate_26\1eNTickMathPilot_27_deployed.TickMathPilot_27_deployed.fun_getSqrtRatioAtTick_425\1f\04call \06_start!\06deploy\07\12\01\00\0f__stack_pointer\09\08\01\00\05.data")
  (@custom ".debug_str" "y\00x\00low\00wasisdk://v12.0/build/compiler-rt\00du_int\00ti_int\00di_int\00long long int\00long long unsigned int\00uint64_t\00twords\00r\00all\00lower_mask\00high\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins/multi3.c\00b\00a\00__int128\00__multi3\00__mulddi3\00bits_in_dword_2\00clang version 11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\00")
  (@custom ".debug_line" "M\01\00\00\04\00\c2\00\00\00\01\01\01\fb\0e\0d\00\01\01\01\01\00\00\00\01\00\00\01wasisdk://v12.0/build/install/opt/wasi-sdk/share/wasi-sysroot/include/bits\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins\00\00alltypes.h\00\01\00\00int_types.h\00\02\00\00multi3.c\00\02\00\00\00\04\03\00\05\02\05\00\00\00\03'\01\05\03\0aD\05,-\05\18\06X\05\0c\06\03rX\05\0b\1eo\05&`\05\0c\06<\05#\06\03u \05\10\06\ac\05\1e\90\03i<\05\16\06\03\18J\05\1f\22\05\05\06X\03f \05\10\06\03\1cJ\05\22\03\13 \05\0f\03n \05\1f\92\05\05\06X\03a \05\11\06\03!J\05\0c\03\0e \05\03!\05\1f\03pX\05\0b\03yX\97\05\03\03\10 \02\04\00\01\01")
  (@custom ".debug_abbrev" "\01\11\01%\0e\13\05\03\0e\10\17\1b\0e\11\01\12\06\00\00\02$\00\03\0e>\0b\0b\0b\00\00\03\16\00I\13\03\0e:\0b;\0b\00\00\04.\01\03\0e:\0b;\0b'\19I\13 \0b\00\00\05\05\00\03\0e:\0b;\0bI\13\00\00\064\00\03\0e:\0b;\0bI\13\00\00\07\17\01\0b\0b:\0b;\0b\00\00\08\0d\00\03\0eI\13:\0b;\0b8\0b\00\00\09\13\01\0b\0b:\0b;\0b\00\00\0a&\00I\13\00\00\0b.\01\11\01\12\06@\18\97B\19\03\0e:\0b;\0b'\19I\13?\19\00\00\0c\05\00\02\17\03\0e:\0b;\0bI\13\00\00\0d4\00\02\17\03\0e:\0b;\0bI\13\00\00\0e\1d\011\13U\17X\0bY\0bW\0b\00\00\0f\05\001\13\00\00\104\00\02\171\13\00\00\114\00\1c\0d1\13\00\00\124\00\1c\0f1\13\00\00\00")
  (@custom ".debug_ranges" "\0f\00\00\00G\00\00\00H\00\00\00\5c\00\00\00b\00\00\00q\00\00\00\00\00\00\00\00\00\00\00")
  (@custom ".debug_loc" "\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\007\00\00\009\00\00\00\06\00\ed\02\02\9f\93\089\00\00\00G\00\00\00\06\00\ed\00\05\9f\93\08G\00\00\00H\00\00\00\0c\00\ed\00\05\9f\93\08\ed\02\02\9f\93\08H\00\00\00p\00\00\00\06\00\ed\00\05\9f\93\08p\00\00\00q\00\00\00\06\00\ed\02\02\9f\93\08q\00\00\00t\00\00\00\06\00\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00]\00\00\00`\00\00\00\08\00\93\08\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00<\00\00\00B\00\00\00\04\00\ed\02\02\9fQ\00\00\00Y\00\00\00\04\00\ed\02\02\9fY\00\00\00u\00\00\00\04\00\ed\00\03\9f\00\00\00\00\00\00\00\00")
  (@custom ".debug_info" "\b4\01\00\00\04\00\00\00\00\00\04\01\fd\00\00\00\0c\00\8a\00\00\00\00\00\00\00\08\00\00\00\05\00\00\00u\00\00\00\02`\00\00\00\05\04\038\00\00\00*\00\00\00\02&\03C\00\00\00d\00\00\00\01\aa\02M\00\00\00\07\08\04\e3\00\00\00\03\13\99\00\00\00\01\05\cf\00\00\00\03\13-\00\00\00\05\cd\00\00\00\03\13-\00\00\00\06t\00\00\00\03\14\ab\00\00\00\06\ed\00\00\00\03\15\0d\01\00\00\06z\00\00\00\03\16\12\01\00\00\06k\00\00\00\03\18-\00\00\00\00\03\a4\00\00\001\00\00\00\02O\02\d1\00\00\00\05\10\03\b6\00\00\00m\00\00\00\02]\07\10\02R\08v\00\00\00\99\00\00\00\02S\00\08r\00\00\00\d2\00\00\00\02\5c\00\09\10\02T\08\04\00\00\00-\00\00\00\02V\00\08\85\00\00\00\f0\00\00\00\02W\08\00\00\03\fb\00\00\008\00\00\00\02%\03\06\01\00\00e\00\00\00\01\91\02?\00\00\00\05\08\0a&\00\00\00\0a-\00\00\00\0b\05\00\00\00u\00\00\00\07\ed\03\00\00\00\00\9f\da\00\00\00\03(\99\00\00\00\0c\00\00\00\00\cf\00\00\00\03(\99\00\00\00\0c\14\00\00\00\cd\00\00\00\03(\99\00\00\00\0d(\00\00\00\00\00\00\00\03+\ab\00\00\00\0d\aa\00\00\00\02\00\00\00\03)\ab\00\00\00\0d\be\00\00\00t\00\00\00\03-\ab\00\00\00\0eJ\00\00\00\00\00\00\00\03.\0b\0fV\00\00\00\0fa\00\00\00\10<\00\00\00l\00\00\00\11 w\00\00\00\12\ff\ff\ff\ff\0f\82\00\00\00\10\d8\00\00\00\8d\00\00\00\00\00\00"))
