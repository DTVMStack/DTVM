(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32 i32)))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func (param i32 i32 i32 i32)))
  (type (;5;) (func))
  (type (;6;) (func (param i32 i64 i64 i64 i64)))
  (type (;7;) (func (param i32) (result i32)))
  (type (;8;) (func (param i32 i64 i64 i64 i64 i64 i64 i64 i64)))
  (type (;9;) (func (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)))
  (import "env" "getCallDataSize" (func $getCallDataSize (type 0)))
  (import "env" "callDataCopy" (func $callDataCopy (type 1)))
  (import "env" "getCallValue" (func $getCallValue (type 2)))
  (import "env" "revert" (func $revert (type 3)))
  (import "env" "finish" (func $finish (type 3)))
  (import "env" "getCodeSize" (func $getCodeSize (type 0)))
  (import "env" "codeCopy" (func $codeCopy (type 1)))
  (import "env" "keccak256" (func $keccak256 (type 1)))
  (import "env" "addmod" (func $addmod (type 4)))
  (import "env" "mulmod" (func $mulmod (type 4)))
  (func $__wasm_call_ctors (type 5))
  (func $__multi3 (type 6) (param i32 i64 i64 i64 i64)
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
              i32.load8_u offset=65860
              br_if 0 (;@5;)
              i32.const 65760
              i32.const 0
              local.get 3
              call $callDataCopy
              i32.const 0
              i32.const 1
              i32.store8 offset=65860
            end
            local.get 4
            i32.eqz
            br_if 2 (;@2;)
            local.get 0
            i32.const 65760
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
            i32.load8_u offset=65860
            br_if 0 (;@4;)
            i32.const 65760
            i32.const 0
            local.get 2
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=65860
          end
          local.get 1
          local.get 0
          i32.const 65760
          i32.add
          i32.load8_u
          i32.store8
          local.get 1
          local.get 0
          i32.const 65761
          i32.add
          i32.load8_u
          i32.store8 offset=1
          local.get 1
          local.get 0
          i32.const 65762
          i32.add
          i32.load8_u
          i32.store8 offset=2
          local.get 1
          local.get 0
          i32.const 65763
          i32.add
          i32.load8_u
          i32.store8 offset=3
          local.get 1
          local.get 0
          i32.const 65764
          i32.add
          i32.load8_u
          i32.store8 offset=4
          local.get 1
          local.get 0
          i32.const 65765
          i32.add
          i32.load8_u
          i32.store8 offset=5
          local.get 1
          local.get 0
          i32.const 65766
          i32.add
          i32.load8_u
          i32.store8 offset=6
          local.get 1
          local.get 0
          i32.const 65767
          i32.add
          i32.load8_u
          i32.store8 offset=7
          local.get 1
          local.get 0
          i32.const 65768
          i32.add
          i32.load8_u
          i32.store8 offset=8
          local.get 1
          local.get 0
          i32.const 65769
          i32.add
          i32.load8_u
          i32.store8 offset=9
          local.get 1
          local.get 0
          i32.const 65770
          i32.add
          i32.load8_u
          i32.store8 offset=10
          local.get 1
          local.get 0
          i32.const 65771
          i32.add
          i32.load8_u
          i32.store8 offset=11
          local.get 1
          local.get 0
          i32.const 65772
          i32.add
          i32.load8_u
          i32.store8 offset=12
          local.get 1
          local.get 0
          i32.const 65773
          i32.add
          i32.load8_u
          i32.store8 offset=13
          local.get 1
          local.get 0
          i32.const 65774
          i32.add
          i32.load8_u
          i32.store8 offset=14
          local.get 1
          local.get 0
          i32.const 65775
          i32.add
          i32.load8_u
          i32.store8 offset=15
          local.get 1
          local.get 0
          i32.const 65776
          i32.add
          i32.load8_u
          i32.store8 offset=16
          local.get 1
          local.get 0
          i32.const 65777
          i32.add
          i32.load8_u
          i32.store8 offset=17
          local.get 1
          local.get 0
          i32.const 65778
          i32.add
          i32.load8_u
          i32.store8 offset=18
          local.get 1
          local.get 0
          i32.const 65779
          i32.add
          i32.load8_u
          i32.store8 offset=19
          local.get 1
          local.get 0
          i32.const 65780
          i32.add
          i32.load8_u
          i32.store8 offset=20
          local.get 1
          local.get 0
          i32.const 65781
          i32.add
          i32.load8_u
          i32.store8 offset=21
          local.get 1
          local.get 0
          i32.const 65782
          i32.add
          i32.load8_u
          i32.store8 offset=22
          local.get 1
          local.get 0
          i32.const 65783
          i32.add
          i32.load8_u
          i32.store8 offset=23
          local.get 1
          local.get 0
          i32.const 65784
          i32.add
          i32.load8_u
          i32.store8 offset=24
          local.get 1
          local.get 0
          i32.const 65785
          i32.add
          i32.load8_u
          i32.store8 offset=25
          local.get 1
          local.get 0
          i32.const 65786
          i32.add
          i32.load8_u
          i32.store8 offset=26
          local.get 1
          local.get 0
          i32.const 65787
          i32.add
          i32.load8_u
          i32.store8 offset=27
          local.get 1
          local.get 0
          i32.const 65788
          i32.add
          i32.load8_u
          i32.store8 offset=28
          local.get 1
          local.get 0
          i32.const 65789
          i32.add
          i32.load8_u
          i32.store8 offset=29
          local.get 1
          local.get 0
          i32.const 65790
          i32.add
          i32.load8_u
          i32.store8 offset=30
          local.get 1
          local.get 0
          i32.const 65791
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
    i32.load offset=65868
    local.get 0
    i32.add
    local.get 1
    call $revert)
  (func $evm_get_memory_addr (type 7) (param i32) (result i32)
    i32.const 0
    i32.load offset=65868
    local.get 0
    i32.add)
  (func $wrapper_codecopy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=65880
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
        i32.store offset=65876
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=65880
        i32.const 0
        i32.const 0
        i32.load offset=65872
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=65872
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=65876
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=65876
    end
    i32.const 0
    i32.load offset=65868
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
          i32.load8_u offset=65860
          br_if 0 (;@3;)
          i32.const 65760
          i32.const 0
          local.get 1
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=65860
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.const 65760
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
  (func $wrapper_memory_guard (type 7) (param i32) (result i32)
    (local i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=65880
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
      i32.store offset=65876
      i32.const 0
      local.get 2
      i32.const -65536
      i32.and
      i32.store offset=65880
      i32.const 0
      i32.const 0
      i32.load offset=65872
      local.get 1
      i32.const 16
      i32.shl
      i32.add
      i32.store offset=65872
      i32.const 96
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=65876
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 0
      i32.store offset=65876
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
          i32.load offset=65880
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
          i32.store offset=65876
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=65880
          i32.const 0
          i32.const 0
          i32.load offset=65872
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65872
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65876
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65876
      end
      i32.const 0
      i32.load offset=65868
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
          i32.load offset=65880
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
          i32.store offset=65876
          i32.const 0
          local.get 7
          i32.const -65536
          i32.and
          i32.store offset=65880
          i32.const 0
          i32.const 0
          i32.load offset=65872
          local.get 1
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65872
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65876
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65876
      end
      i32.const 0
      i32.load offset=65868
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
          i32.load offset=65880
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
          i32.store offset=65876
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=65880
          i32.const 0
          i32.const 0
          i32.load offset=65872
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=65872
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=65876
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=65876
      end
      i32.const 0
      i32.load offset=65868
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
    i32.load offset=65868
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
  (func $wrapper_keccak256 (type 1) (param i32 i32 i32)
    i32.const 0
    i32.load offset=65868
    local.get 0
    i32.add
    local.get 1
    local.get 2
    call $keccak256)
  (func $wrapper_return (type 3) (param i32 i32)
    i32.const 0
    i32.load offset=65868
    local.get 0
    i32.add
    local.get 1
    call $finish)
  (func $wrapper_calldata_copy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=65880
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
        i32.store offset=65876
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=65880
        i32.const 0
        i32.const 0
        i32.load offset=65872
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=65872
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=65876
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=65876
    end
    i32.const 0
    i32.load offset=65868
    local.set 3
    block  ;; label = @1
      i32.const 0
      i32.load offset=65536
      local.tee 4
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 4
      i32.store offset=65536
    end
    local.get 3
    local.get 0
    i32.add
    local.set 0
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        local.get 1
        i32.gt_u
        br_if 0 (;@2;)
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
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
            i32.const 0
            i32.store8
            local.get 0
            i32.const 1
            i32.add
            local.set 0
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
        loop  ;; label = @3
          local.get 0
          i64.const 0
          i64.store align=1
          local.get 0
          i32.const 8
          i32.add
          local.set 0
          local.get 4
          i32.const -8
          i32.add
          local.tee 4
          br_if 0 (;@3;)
          br 2 (;@1;)
        end
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          local.get 1
          i32.add
          local.get 4
          i32.le_u
          br_if 0 (;@3;)
          local.get 4
          local.set 3
          block  ;; label = @4
            local.get 4
            i32.const -1
            i32.gt_s
            br_if 0 (;@4;)
            i32.const 0
            call $getCallDataSize
            local.tee 3
            i32.store offset=65536
          end
          local.get 4
          local.get 1
          i32.sub
          local.set 5
          block  ;; label = @4
            local.get 3
            i32.const 101
            i32.lt_s
            br_if 0 (;@4;)
            local.get 0
            local.get 1
            local.get 5
            call $callDataCopy
            br 2 (;@2;)
          end
          block  ;; label = @4
            i32.const 0
            i32.load8_u offset=65860
            br_if 0 (;@4;)
            i32.const 65760
            i32.const 0
            local.get 3
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=65860
          end
          local.get 5
          i32.eqz
          br_if 1 (;@2;)
          local.get 1
          i32.const 65760
          i32.add
          local.set 4
          block  ;; label = @4
            block  ;; label = @5
              local.get 5
              i32.const 7
              i32.and
              local.tee 3
              br_if 0 (;@5;)
              local.get 5
              local.set 3
              local.get 0
              local.set 1
              br 1 (;@4;)
            end
            local.get 0
            local.set 1
            loop  ;; label = @5
              local.get 1
              local.get 4
              i32.load8_u
              i32.store8
              local.get 1
              i32.const 1
              i32.add
              local.set 1
              local.get 4
              i32.const 1
              i32.add
              local.set 4
              local.get 3
              i32.const -1
              i32.add
              local.tee 3
              br_if 0 (;@5;)
            end
            local.get 5
            i32.const -8
            i32.and
            local.set 3
          end
          local.get 5
          i32.const 8
          i32.lt_u
          br_if 1 (;@2;)
          local.get 3
          i32.const -8
          i32.add
          local.set 3
          loop  ;; label = @4
            local.get 1
            local.get 4
            i32.load8_u
            i32.store8
            local.get 1
            local.get 4
            i32.load8_u offset=1
            i32.store8 offset=1
            local.get 1
            local.get 4
            i32.load8_u offset=2
            i32.store8 offset=2
            local.get 1
            local.get 4
            i32.load8_u offset=3
            i32.store8 offset=3
            local.get 1
            local.get 4
            i32.load8_u offset=4
            i32.store8 offset=4
            local.get 1
            local.get 4
            i32.load8_u offset=5
            i32.store8 offset=5
            local.get 1
            local.get 4
            i32.load8_u offset=6
            i32.store8 offset=6
            local.get 1
            local.get 4
            i32.load8_u offset=7
            i32.store8 offset=7
            local.get 3
            i32.eqz
            br_if 2 (;@2;)
            local.get 3
            i32.const -8
            i32.add
            local.set 3
            local.get 4
            i32.const 8
            i32.add
            local.set 4
            local.get 1
            i32.const 8
            i32.add
            local.set 1
            br 0 (;@4;)
          end
        end
        block  ;; label = @3
          local.get 4
          i32.const -1
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 0
          call $getCallDataSize
          local.tee 4
          i32.store offset=65536
        end
        block  ;; label = @3
          local.get 4
          i32.const 101
          i32.lt_s
          br_if 0 (;@3;)
          local.get 0
          local.get 1
          local.get 2
          call $callDataCopy
          return
        end
        block  ;; label = @3
          i32.const 0
          i32.load8_u offset=65860
          br_if 0 (;@3;)
          i32.const 65760
          i32.const 0
          local.get 4
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=65860
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        i32.const 65760
        i32.add
        local.set 4
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i32.const 7
            i32.and
            local.tee 1
            br_if 0 (;@4;)
            local.get 2
            local.set 1
            br 1 (;@3;)
          end
          loop  ;; label = @4
            local.get 0
            local.get 4
            i32.load8_u
            i32.store8
            local.get 0
            i32.const 1
            i32.add
            local.set 0
            local.get 4
            i32.const 1
            i32.add
            local.set 4
            local.get 1
            i32.const -1
            i32.add
            local.tee 1
            br_if 0 (;@4;)
          end
          local.get 2
          i32.const -8
          i32.and
          local.set 1
        end
        local.get 2
        i32.const 8
        i32.lt_u
        br_if 1 (;@1;)
        local.get 1
        i32.const -8
        i32.add
        local.set 1
        loop  ;; label = @3
          local.get 0
          local.get 4
          i32.load8_u
          i32.store8
          local.get 0
          local.get 4
          i32.load8_u offset=1
          i32.store8 offset=1
          local.get 0
          local.get 4
          i32.load8_u offset=2
          i32.store8 offset=2
          local.get 0
          local.get 4
          i32.load8_u offset=3
          i32.store8 offset=3
          local.get 0
          local.get 4
          i32.load8_u offset=4
          i32.store8 offset=4
          local.get 0
          local.get 4
          i32.load8_u offset=5
          i32.store8 offset=5
          local.get 0
          local.get 4
          i32.load8_u offset=6
          i32.store8 offset=6
          local.get 0
          local.get 4
          i32.load8_u offset=7
          i32.store8 offset=7
          local.get 1
          i32.eqz
          br_if 2 (;@1;)
          local.get 1
          i32.const -8
          i32.add
          local.set 1
          local.get 4
          i32.const 8
          i32.add
          local.set 4
          local.get 0
          i32.const 8
          i32.add
          local.set 0
          br 0 (;@3;)
        end
      end
      local.get 2
      local.get 5
      i32.sub
      local.tee 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 5
      i32.add
      local.set 0
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.const 7
          i32.and
          local.tee 4
          br_if 0 (;@3;)
          local.get 1
          local.set 4
          br 1 (;@2;)
        end
        loop  ;; label = @3
          local.get 0
          i32.const 0
          i32.store8
          local.get 0
          i32.const 1
          i32.add
          local.set 0
          local.get 4
          i32.const -1
          i32.add
          local.tee 4
          br_if 0 (;@3;)
        end
        local.get 1
        i32.const -8
        i32.and
        local.set 4
      end
      local.get 1
      i32.const 8
      i32.lt_u
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 0
        i64.const 0
        i64.store align=1
        local.get 0
        i32.const 8
        i32.add
        local.set 0
        local.get 4
        i32.const -8
        i32.add
        local.tee 4
        br_if 0 (;@2;)
      end
    end)
  (func $set_is_deploying_tx (type 5)
    i32.const 0
    i32.const 1
    i32.store8 offset=65744)
  (func $wrapper_addmod (type 4) (param i32 i32 i32 i32)
    local.get 0
    local.get 1
    local.get 2
    local.get 3
    call $addmod)
  (func $wrapper_mulmod (type 4) (param i32 i32 i32 i32)
    local.get 0
    local.get 1
    local.get 2
    local.get 3
    call $mulmod)
  (func $__init_evm_heap (type 2) (param i32)
    (local i32)
    block  ;; label = @1
      i32.const 0
      i32.load8_u offset=65864
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
          i32.store offset=65868
          i32.const 1
          memory.grow
          drop
          memory.size
          i32.const 16
          i32.shl
          local.tee 0
          i32.const 0
          i32.load offset=65868
          i32.sub
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 65888
        i32.store offset=65868
        i32.const 82272
        local.set 0
        i32.const 16384
        local.set 1
      end
      i32.const 0
      local.get 0
      i32.store offset=65872
      i32.const 0
      local.get 1
      i32.store offset=65880
      i32.const 0
      i32.const 1
      i32.store8 offset=65864
      i32.const 0
      i32.const 0
      i32.store offset=65876
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
  (func $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_benchmark_261 (type 2) (param i32)
    (local i32 i64 i64 i64 i64 i32 i64 i64 i64 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i64 i32 i32 i64 i32 i32)
    global.get $__stack_pointer
    i32.const 288
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    i32.const 224
    i32.add
    i64.const 8
    i64.const 0
    i64.const 0
    i64.const 0
    call $MerkleProof_262_deployed.MerkleProof_262_deployed.allocate_and_zero_memory_array_t_array$_t_uint256_$dyn_memory_ptr
    local.get 1
    i32.const 224
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 2
    local.get 1
    i32.const 224
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 3
    local.get 1
    i32.const 224
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 4
    local.get 1
    i64.load offset=224
    local.set 5
    local.get 1
    i32.const 192
    i32.add
    i64.const 8
    i64.const 0
    i64.const 0
    i64.const 0
    call $MerkleProof_262_deployed.MerkleProof_262_deployed.allocate_and_zero_memory_array_t_array$_t_uint256_$dyn_memory_ptr
    local.get 5
    i32.wrap_i64
    local.set 6
    local.get 1
    i32.const 192
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 7
    local.get 1
    i32.const 192
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 1
    i32.const 192
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 9
    local.get 1
    i64.load offset=192
    local.tee 10
    i32.wrap_i64
    local.set 11
    i64.const 42
    local.set 12
    i64.const 0
    local.set 13
    i64.const 0
    local.set 14
    i64.const 0
    local.set 15
    i64.const 0
    local.set 16
    i64.const 0
    local.set 17
    i64.const 0
    local.set 18
    i64.const 0
    local.set 19
    loop  ;; label = @1
      local.get 1
      i32.const 176
      i32.add
      local.get 15
      local.tee 20
      local.get 16
      i64.const 7
      i64.const 0
      call $__multi3
      local.get 1
      i32.const 112
      i32.add
      local.get 13
      local.tee 21
      i64.const 0
      i64.const 7
      i64.const 0
      call $__multi3
      local.get 1
      i32.const 144
      i32.add
      local.get 14
      local.tee 22
      i64.const 0
      i64.const 7
      i64.const 0
      call $__multi3
      local.get 1
      i32.const 160
      i32.add
      local.get 21
      local.get 22
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 1
      i32.const 96
      i32.add
      local.get 21
      i64.const 0
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 1
      i32.const 128
      i32.add
      local.get 22
      i64.const 0
      i64.const 0
      i64.const 0
      call $__multi3
      local.get 6
      local.get 1
      i32.const 256
      i32.add
      call $wrapper_mload_u256
      local.get 1
      i32.const 128
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 1
      i32.const 144
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 1
      i64.load offset=144
      local.tee 13
      local.get 1
      i32.const 112
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.add
      local.tee 14
      local.get 13
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 15
      local.get 1
      i32.const 96
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 1
      i64.load offset=96
      local.tee 23
      local.get 14
      i64.add
      local.tee 13
      local.get 23
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.add
      local.tee 14
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 1
      i64.load offset=128
      local.tee 15
      local.get 14
      i64.add
      local.tee 14
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 1
      i32.const 160
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.get 1
      i32.const 176
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.add
      local.get 1
      i64.load offset=160
      local.tee 15
      local.get 1
      i64.load offset=176
      i64.add
      local.tee 23
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.add
      local.get 14
      local.get 23
      i64.add
      local.tee 15
      local.get 14
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 15
      local.get 1
      i64.load offset=112
      local.tee 14
      i64.const 13
      i64.add
      local.tee 23
      local.get 14
      i64.lt_u
      local.tee 24
      local.get 13
      local.get 24
      i64.extend_i32_u
      i64.add
      local.tee 25
      local.get 13
      i64.lt_u
      local.get 23
      local.get 14
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 14
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.set 15
      block  ;; label = @2
        local.get 1
        i64.load offset=256
        local.get 21
        i64.gt_u
        local.get 1
        i32.const 256
        i32.add
        i32.const 8
        i32.add
        local.tee 26
        i64.load
        local.tee 13
        local.get 22
        i64.gt_u
        local.get 13
        local.get 22
        i64.eq
        select
        local.get 1
        i32.const 256
        i32.add
        i32.const 16
        i32.add
        local.tee 27
        i64.load
        local.tee 28
        local.get 20
        i64.gt_u
        local.get 1
        i32.const 256
        i32.add
        i32.const 24
        i32.add
        local.tee 24
        i64.load
        local.tee 13
        local.get 16
        i64.gt_u
        local.get 13
        local.get 16
        i64.eq
        select
        local.get 28
        local.get 20
        i64.xor
        local.get 13
        local.get 16
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65648
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 50
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 24
      local.get 15
      i64.store
      local.get 1
      local.get 23
      i64.store offset=256
      local.get 1
      local.get 25
      i64.store offset=264
      local.get 1
      local.get 14
      i64.store offset=272
      local.get 21
      i64.const 5
      i64.shl
      i64.const 32
      i64.add
      local.tee 14
      local.get 5
      i64.add
      i32.wrap_i64
      local.tee 29
      local.get 1
      i32.const 256
      i32.add
      call $wrapper_mstore_u256
      local.get 11
      local.get 1
      i32.const 256
      i32.add
      call $wrapper_mload_u256
      local.get 21
      i64.const 1
      i64.and
      local.set 15
      block  ;; label = @2
        local.get 1
        i64.load offset=256
        local.get 21
        i64.gt_u
        local.get 26
        i64.load
        local.tee 13
        local.get 22
        i64.gt_u
        local.get 13
        local.get 22
        i64.eq
        select
        local.get 27
        i64.load
        local.tee 23
        local.get 20
        i64.gt_u
        local.get 24
        i64.load
        local.tee 13
        local.get 16
        i64.gt_u
        local.get 13
        local.get 16
        i64.eq
        select
        local.get 23
        local.get 20
        i64.xor
        local.get 13
        local.get 16
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65648
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 50
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 24
      i64.const 0
      i64.store
      local.get 1
      i64.const 0
      i64.store offset=272
      local.get 1
      i64.const 0
      i64.store offset=264
      local.get 1
      local.get 15
      i64.store offset=256
      local.get 14
      local.get 10
      i64.add
      i32.wrap_i64
      local.tee 30
      local.get 1
      i32.const 256
      i32.add
      call $wrapper_mstore_u256
      local.get 11
      local.get 1
      i32.const 256
      i32.add
      call $wrapper_mload_u256
      block  ;; label = @2
        local.get 1
        i64.load offset=256
        local.get 21
        i64.gt_u
        local.get 26
        i64.load
        local.tee 13
        local.get 22
        i64.gt_u
        local.get 13
        local.get 22
        i64.eq
        select
        local.get 27
        i64.load
        local.tee 14
        local.get 20
        i64.gt_u
        local.get 24
        i64.load
        local.tee 13
        local.get 16
        i64.gt_u
        local.get 13
        local.get 16
        i64.eq
        select
        local.get 14
        local.get 20
        i64.xor
        local.get 13
        local.get 16
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65648
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 50
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 30
      local.get 1
      i32.const 256
      i32.add
      call $wrapper_mload_u256
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i64.load offset=256
          local.get 27
          i64.load
          i64.or
          local.get 26
          i64.load
          local.get 24
          i64.load
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          local.get 6
          local.get 1
          i32.const 256
          i32.add
          call $wrapper_mload_u256
          block  ;; label = @4
            local.get 1
            i64.load offset=256
            local.get 21
            i64.gt_u
            local.get 26
            i64.load
            local.tee 13
            local.get 22
            i64.gt_u
            local.get 13
            local.get 22
            i64.eq
            select
            local.get 27
            i64.load
            local.tee 14
            local.get 20
            i64.gt_u
            local.get 24
            i64.load
            local.tee 13
            local.get 16
            i64.gt_u
            local.get 13
            local.get 16
            i64.eq
            select
            local.get 14
            local.get 20
            i64.xor
            local.get 13
            local.get 16
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
            i32.const 0
            i32.const 65648
            call $wrapper_mstore_bytes32
            i32.const 4
            i32.const 50
            call $wrapper_mstore_u32
            i32.const 0
            i32.const 36
            call $wrapper_revert
          end
          local.get 29
          local.get 1
          i32.const 256
          i32.add
          call $wrapper_mload_u256
          local.get 1
          i32.const 64
          i32.add
          local.get 1
          i64.load offset=256
          local.get 26
          i64.load
          local.get 27
          i64.load
          local.get 24
          i64.load
          local.get 12
          local.get 17
          local.get 18
          local.get 19
          call $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_mimcHash_99
          local.get 1
          i32.const 64
          i32.add
          i32.const 24
          i32.add
          i64.load
          local.set 19
          local.get 1
          i32.const 64
          i32.add
          i32.const 16
          i32.add
          i64.load
          local.set 18
          local.get 1
          i32.const 64
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.set 17
          local.get 1
          i64.load offset=64
          local.set 12
          br 1 (;@2;)
        end
        local.get 6
        local.get 1
        i32.const 256
        i32.add
        call $wrapper_mload_u256
        block  ;; label = @3
          local.get 1
          i64.load offset=256
          local.get 21
          i64.gt_u
          local.get 26
          i64.load
          local.tee 13
          local.get 22
          i64.gt_u
          local.get 13
          local.get 22
          i64.eq
          select
          local.get 27
          i64.load
          local.tee 14
          local.get 20
          i64.gt_u
          local.get 24
          i64.load
          local.tee 13
          local.get 16
          i64.gt_u
          local.get 13
          local.get 16
          i64.eq
          select
          local.get 14
          local.get 20
          i64.xor
          local.get 13
          local.get 16
          i64.xor
          i64.or
          i64.eqz
          select
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65648
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 50
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        local.get 29
        local.get 1
        i32.const 256
        i32.add
        call $wrapper_mload_u256
        local.get 1
        i32.const 32
        i32.add
        local.get 12
        local.get 17
        local.get 18
        local.get 19
        local.get 1
        i64.load offset=256
        local.get 26
        i64.load
        local.get 27
        i64.load
        local.get 24
        i64.load
        call $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_mimcHash_99
        local.get 1
        i32.const 32
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.set 19
        local.get 1
        i32.const 32
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.set 18
        local.get 1
        i32.const 32
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.set 17
        local.get 1
        i64.load offset=32
        local.set 12
      end
      local.get 16
      i64.const 0
      i64.ne
      local.set 24
      local.get 16
      i64.eqz
      local.set 26
      local.get 20
      local.get 16
      i64.or
      local.set 23
      local.get 16
      local.get 20
      local.get 21
      i64.const 1
      i64.add
      local.tee 13
      local.get 21
      i64.lt_u
      local.tee 27
      local.get 22
      local.get 27
      i64.extend_i32_u
      i64.add
      local.tee 14
      local.get 22
      i64.lt_u
      local.get 13
      local.get 21
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 15
      local.get 20
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.set 16
      local.get 21
      i64.const 6
      i64.gt_u
      local.get 22
      i64.const 0
      i64.ne
      local.get 22
      i64.eqz
      select
      local.get 20
      i64.const 0
      i64.ne
      local.get 24
      local.get 26
      select
      local.get 23
      i64.eqz
      select
      i32.eqz
      br_if 0 (;@1;)
    end
    local.get 1
    local.get 5
    local.get 4
    local.get 3
    local.get 2
    local.get 12
    local.get 17
    local.get 18
    local.get 19
    i64.const 42
    i64.const 0
    i64.const 0
    i64.const 0
    local.get 10
    local.get 9
    local.get 8
    local.get 7
    call $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_verify_162
    local.get 1
    i32.const 24
    i32.add
    i64.load
    local.set 16
    local.get 1
    i32.const 8
    i32.add
    i64.load
    local.set 22
    local.get 1
    i64.load
    local.set 21
    local.get 0
    local.get 1
    i32.const 16
    i32.add
    i64.load
    i64.store offset=16
    local.get 0
    local.get 21
    i64.store
    local.get 0
    local.get 22
    i64.store offset=8
    local.get 0
    i32.const 24
    i32.add
    local.get 16
    i64.store
    local.get 1
    i32.const 288
    i32.add
    global.set $__stack_pointer)
  (func $MerkleProof_262_deployed.MerkleProof_262_deployed.allocate_and_zero_memory_array_t_array$_t_uint256_$dyn_memory_ptr (type 6) (param i32 i64 i64 i64 i64)
    (local i32 i32 i64 i32 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    i32.const 65616
    local.get 5
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 5
      i64.load offset=64
      local.get 1
      i64.ge_u
      local.get 5
      i32.const 64
      i32.add
      i32.const 8
      i32.add
      local.tee 6
      i64.load
      local.tee 7
      local.get 2
      i64.ge_u
      local.get 7
      local.get 2
      i64.eq
      select
      local.get 5
      i32.const 64
      i32.add
      i32.const 16
      i32.add
      local.tee 8
      i64.load
      local.tee 9
      local.get 3
      i64.ge_u
      local.get 5
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      local.tee 10
      i64.load
      local.tee 7
      local.get 4
      i64.ge_u
      local.get 7
      local.get 4
      i64.eq
      select
      local.get 9
      local.get 3
      i64.xor
      local.get 7
      local.get 4
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      i32.const 0
      i32.const 65552
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    i32.const 64
    local.get 5
    i32.const 64
    i32.add
    call $wrapper_mload_u256
    local.get 6
    i64.load
    local.set 11
    local.get 8
    i64.load
    local.set 9
    local.get 10
    i64.load
    local.set 12
    local.get 5
    i64.load offset=64
    local.set 13
    i32.const 65584
    local.get 5
    i32.const 32
    i32.add
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      block  ;; label = @2
        local.get 13
        local.get 1
        i64.const 5
        i64.shl
        local.tee 14
        i64.const 63
        i64.add
        local.tee 7
        i64.const -32
        i64.and
        i64.add
        local.tee 15
        local.get 13
        i64.lt_u
        local.tee 6
        local.get 11
        local.get 2
        i64.const 5
        i64.shl
        local.get 1
        i64.const 59
        i64.shr_u
        i64.or
        local.tee 16
        local.get 7
        local.get 14
        i64.lt_u
        local.tee 8
        i64.extend_i32_u
        i64.add
        local.tee 17
        i64.add
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 18
        local.get 11
        i64.lt_u
        local.get 18
        local.get 11
        i64.eq
        select
        local.tee 6
        local.get 9
        local.get 3
        i64.const 5
        i64.shl
        local.get 2
        i64.const 59
        i64.shr_u
        i64.or
        local.tee 19
        local.get 8
        local.get 17
        local.get 16
        i64.lt_u
        local.get 7
        local.get 14
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 17
        i64.add
        local.tee 7
        local.get 6
        i64.extend_i32_u
        i64.add
        local.tee 16
        local.get 9
        i64.lt_u
        local.get 12
        local.get 4
        i64.const 5
        i64.shl
        local.get 3
        i64.const 59
        i64.shr_u
        i64.or
        local.get 17
        local.get 19
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 7
        local.get 9
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 16
        local.get 7
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 7
        local.get 12
        i64.lt_u
        local.get 7
        local.get 12
        i64.eq
        select
        local.get 16
        local.get 9
        i64.xor
        local.get 7
        local.get 12
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        local.get 15
        local.get 5
        i64.load offset=32
        i64.le_u
        local.get 18
        local.get 5
        i32.const 32
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 17
        i64.le_u
        local.get 18
        local.get 17
        i64.eq
        select
        local.get 16
        local.get 5
        i32.const 32
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.tee 19
        i64.le_u
        local.get 7
        local.get 5
        i32.const 32
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.tee 17
        i64.le_u
        local.get 7
        local.get 17
        i64.eq
        select
        local.get 16
        local.get 19
        i64.xor
        local.get 7
        local.get 17
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 1 (;@1;)
      end
      i32.const 0
      i32.const 65552
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 5
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    local.tee 6
    local.get 7
    i64.store
    local.get 5
    local.get 15
    i64.store offset=64
    local.get 5
    local.get 18
    i64.store offset=72
    local.get 5
    local.get 16
    i64.store offset=80
    i32.const 64
    local.get 5
    i32.const 64
    i32.add
    call $wrapper_mstore_u256
    local.get 5
    local.get 1
    i64.store
    local.get 5
    local.get 2
    i64.store offset=8
    local.get 5
    local.get 3
    i64.store offset=16
    local.get 5
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 13
    i32.wrap_i64
    local.tee 8
    local.get 5
    call $wrapper_mstore_u256
    i32.const 65616
    local.get 5
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 5
      i64.load offset=64
      local.get 1
      i64.ge_u
      local.get 5
      i32.const 72
      i32.add
      i64.load
      local.tee 7
      local.get 2
      i64.ge_u
      local.get 7
      local.get 2
      i64.eq
      select
      local.get 5
      i32.const 80
      i32.add
      i64.load
      local.tee 7
      local.get 3
      i64.ge_u
      local.get 6
      i64.load
      local.tee 2
      local.get 4
      i64.ge_u
      local.get 2
      local.get 4
      i64.eq
      select
      local.get 7
      local.get 3
      i64.xor
      local.get 2
      local.get 4
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      i32.const 0
      i32.const 65552
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 8
    i32.const 32
    i32.add
    call $wrapper_calldata_size
    local.get 14
    i32.wrap_i64
    call $wrapper_calldata_copy
    local.get 0
    local.get 9
    i64.store offset=16
    local.get 0
    local.get 11
    i64.store offset=8
    local.get 0
    local.get 13
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 12
    i64.store
    local.get 5
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_mimcHash_99 (type 8) (param i32 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 1440
    i32.sub
    local.tee 9
    global.set $__stack_pointer
    local.get 9
    i32.const 1408
    i32.add
    i32.const 24
    i32.add
    local.set 10
    local.get 9
    i32.const 1408
    i32.add
    i32.const 8
    i32.add
    local.set 11
    local.get 9
    i32.const 1408
    i32.add
    i32.const 16
    i32.add
    local.set 12
    i64.const 0
    local.set 13
    i64.const 0
    local.set 14
    i64.const 0
    local.set 15
    i64.const 0
    local.set 16
    i64.const 0
    local.set 17
    i64.const 0
    local.set 18
    i64.const 0
    local.set 19
    i64.const 0
    local.set 20
    loop  ;; label = @1
      local.get 16
      local.set 21
      local.get 15
      local.set 22
      local.get 14
      local.set 23
      local.get 13
      local.set 24
      i32.const 65712
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        local.get 9
        i64.load offset=1408
        local.tee 13
        local.get 12
        i64.load
        local.tee 14
        i64.or
        local.get 11
        i64.load
        local.tee 15
        local.get 10
        i64.load
        local.tee 16
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65680
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 9
      i32.const 96
      i32.add
      i32.const 24
      i32.add
      local.get 4
      i64.store
      local.get 9
      local.get 1
      i64.store offset=96
      local.get 9
      local.get 2
      i64.store offset=104
      local.get 9
      local.get 3
      i64.store offset=112
      local.get 9
      i32.const 96
      i32.add
      local.get 9
      i32.const 128
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 160
      i32.add
      i32.const 24
      i32.add
      local.get 20
      i64.store
      local.get 9
      local.get 19
      i64.store offset=176
      local.get 9
      local.get 18
      i64.store offset=168
      local.get 9
      local.get 17
      i64.store offset=160
      local.get 9
      i32.const 160
      i32.add
      local.get 9
      i32.const 192
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 224
      i32.add
      i32.const 24
      i32.add
      local.get 16
      i64.store
      local.get 9
      local.get 14
      i64.store offset=240
      local.get 9
      local.get 15
      i64.store offset=232
      local.get 9
      local.get 13
      i64.store offset=224
      local.get 9
      i32.const 224
      i32.add
      local.get 9
      i32.const 256
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 128
      i32.add
      local.get 9
      i32.const 192
      i32.add
      local.get 9
      i32.const 256
      i32.add
      local.get 9
      i32.const 288
      i32.add
      call $wrapper_addmod
      i32.const 65712
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        local.get 9
        i64.load offset=1408
        local.tee 13
        local.get 12
        i64.load
        local.tee 4
        i64.or
        local.get 11
        i64.load
        local.tee 3
        local.get 10
        i64.load
        local.tee 2
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65680
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 9
      i32.const 320
      i32.add
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 9
      local.get 5
      i64.store offset=320
      local.get 9
      local.get 6
      i64.store offset=328
      local.get 9
      local.get 7
      i64.store offset=336
      local.get 9
      i32.const 320
      i32.add
      local.get 9
      i32.const 352
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 384
      i32.add
      i32.const 24
      i32.add
      local.get 2
      i64.store
      local.get 9
      local.get 4
      i64.store offset=400
      local.get 9
      local.get 3
      i64.store offset=392
      local.get 9
      local.get 13
      i64.store offset=384
      local.get 9
      i32.const 384
      i32.add
      local.get 9
      i32.const 416
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 288
      i32.add
      local.get 9
      i32.const 352
      i32.add
      local.get 9
      i32.const 416
      i32.add
      local.get 9
      i32.const 448
      i32.add
      call $wrapper_addmod
      i32.const 65712
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        local.get 9
        i64.load offset=1408
        local.tee 13
        local.get 12
        i64.load
        local.tee 4
        i64.or
        local.get 11
        i64.load
        local.tee 3
        local.get 10
        i64.load
        local.tee 2
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65680
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 9
      i32.const 480
      i32.add
      i32.const 24
      i32.add
      local.get 2
      i64.store
      local.get 9
      local.get 13
      i64.store offset=480
      local.get 9
      local.get 3
      i64.store offset=488
      local.get 9
      local.get 4
      i64.store offset=496
      local.get 9
      i32.const 480
      i32.add
      local.get 9
      i32.const 512
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 448
      i32.add
      local.get 9
      i32.const 448
      i32.add
      local.get 9
      i32.const 512
      i32.add
      local.get 9
      i32.const 544
      i32.add
      call $wrapper_mulmod
      i32.const 65712
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        local.get 9
        i64.load offset=1408
        local.tee 13
        local.get 12
        i64.load
        local.tee 4
        i64.or
        local.get 11
        i64.load
        local.tee 3
        local.get 10
        i64.load
        local.tee 2
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65680
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 9
      i32.const 576
      i32.add
      i32.const 24
      i32.add
      local.get 2
      i64.store
      local.get 9
      local.get 13
      i64.store offset=576
      local.get 9
      local.get 3
      i64.store offset=584
      local.get 9
      local.get 4
      i64.store offset=592
      local.get 9
      i32.const 576
      i32.add
      local.get 9
      i32.const 608
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 544
      i32.add
      local.get 9
      i32.const 544
      i32.add
      local.get 9
      i32.const 608
      i32.add
      local.get 9
      i32.const 640
      i32.add
      call $wrapper_mulmod
      i32.const 65712
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        local.get 9
        i64.load offset=1408
        local.tee 13
        local.get 12
        i64.load
        local.tee 4
        i64.or
        local.get 11
        i64.load
        local.tee 3
        local.get 10
        i64.load
        local.tee 2
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65680
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 9
      i32.const 672
      i32.add
      i32.const 24
      i32.add
      local.get 2
      i64.store
      local.get 9
      local.get 13
      i64.store offset=672
      local.get 9
      local.get 3
      i64.store offset=680
      local.get 9
      local.get 4
      i64.store offset=688
      local.get 9
      i32.const 672
      i32.add
      local.get 9
      i32.const 704
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 640
      i32.add
      local.get 9
      i32.const 544
      i32.add
      local.get 9
      i32.const 704
      i32.add
      local.get 9
      i32.const 736
      i32.add
      call $wrapper_mulmod
      i32.const 65712
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        local.get 9
        i64.load offset=1408
        local.tee 13
        local.get 12
        i64.load
        local.tee 4
        i64.or
        local.get 11
        i64.load
        local.tee 3
        local.get 10
        i64.load
        local.tee 2
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65680
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 9
      i32.const 768
      i32.add
      i32.const 24
      i32.add
      local.get 2
      i64.store
      local.get 9
      local.get 13
      i64.store offset=768
      local.get 9
      local.get 3
      i64.store offset=776
      local.get 9
      local.get 4
      i64.store offset=784
      local.get 9
      i32.const 768
      i32.add
      local.get 9
      i32.const 800
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 736
      i32.add
      local.get 9
      i32.const 448
      i32.add
      local.get 9
      i32.const 800
      i32.add
      local.get 9
      i32.const 832
      i32.add
      call $wrapper_mulmod
      local.get 9
      i32.const 832
      i32.add
      local.get 9
      call $u256_from_big_endian_bytes
      i32.const 64
      local.get 9
      i32.const 1408
      i32.add
      call $wrapper_mload_u256
      local.get 10
      i64.load
      local.set 16
      local.get 12
      i64.load
      local.set 3
      local.get 11
      i64.load
      local.set 2
      local.get 9
      i64.load offset=1408
      local.set 13
      local.get 10
      local.get 21
      i64.store
      local.get 9
      local.get 22
      i64.store offset=1424
      local.get 9
      local.get 23
      i64.store offset=1416
      local.get 9
      local.get 24
      i64.store offset=1408
      local.get 13
      i32.wrap_i64
      local.tee 25
      i32.const 32
      i32.add
      local.tee 26
      local.get 9
      i32.const 1408
      i32.add
      call $wrapper_mstore_u256
      local.get 9
      i32.const 864
      i32.add
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 9
      i64.const 0
      i64.store offset=880
      local.get 9
      i64.const 0
      i64.store offset=872
      local.get 9
      i64.const 32
      i64.store offset=864
      local.get 25
      local.get 9
      i32.const 864
      i32.add
      call $wrapper_mstore_u256
      i32.const 65584
      local.get 9
      i32.const 1376
      i32.add
      call $u256_from_big_endian_bytes
      local.get 16
      local.get 3
      local.get 13
      i64.const 64
      i64.add
      local.tee 1
      local.get 13
      i64.lt_u
      local.tee 27
      local.get 2
      local.get 27
      i64.extend_i32_u
      i64.add
      local.tee 14
      local.get 2
      i64.lt_u
      local.get 1
      local.get 13
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 15
      local.get 3
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.set 4
      local.get 9
      i32.const 1376
      i32.add
      i32.const 24
      i32.add
      local.set 27
      local.get 9
      i32.const 1376
      i32.add
      i32.const 16
      i32.add
      local.set 28
      local.get 9
      i32.const 1376
      i32.add
      i32.const 8
      i32.add
      local.set 29
      block  ;; label = @2
        block  ;; label = @3
          local.get 13
          i64.const -65
          i64.gt_u
          i32.const 0
          local.get 2
          i64.const -1
          i64.eq
          select
          i32.const 0
          local.get 3
          local.get 16
          i64.and
          i64.const -1
          i64.eq
          select
          br_if 0 (;@3;)
          local.get 1
          local.get 9
          i64.load offset=1376
          i64.le_u
          local.get 14
          local.get 29
          i64.load
          local.tee 13
          i64.le_u
          local.get 14
          local.get 13
          i64.eq
          select
          local.get 15
          local.get 28
          i64.load
          local.tee 3
          i64.le_u
          local.get 4
          local.get 27
          i64.load
          local.tee 13
          i64.le_u
          local.get 4
          local.get 13
          i64.eq
          select
          local.get 15
          local.get 3
          i64.xor
          local.get 4
          local.get 13
          i64.xor
          i64.or
          i64.eqz
          select
          br_if 1 (;@2;)
        end
        i32.const 0
        i32.const 65552
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 65
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 10
      local.get 4
      i64.store
      local.get 9
      local.get 1
      i64.store offset=1408
      local.get 9
      local.get 14
      i64.store offset=1416
      local.get 9
      local.get 15
      i64.store offset=1424
      i32.const 64
      local.get 9
      i32.const 1408
      i32.add
      call $wrapper_mstore_u256
      local.get 25
      local.get 9
      i32.const 1408
      i32.add
      call $wrapper_mload_u256
      local.get 26
      local.get 9
      i32.load offset=1408
      local.get 9
      i32.const 896
      i32.add
      call $wrapper_keccak256
      local.get 9
      i32.const 896
      i32.add
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      local.get 9
      i32.const 1408
      i32.add
      i32.const 0
      local.get 9
      i32.const 1376
      i32.add
      call $wrapper_u256_shr
      local.get 27
      i64.load
      local.set 13
      local.get 28
      i64.load
      local.set 4
      local.get 29
      i64.load
      local.set 3
      local.get 9
      i64.load offset=1376
      local.set 2
      i32.const 65712
      local.get 9
      i32.const 1408
      i32.add
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        local.get 9
        i64.load offset=1408
        local.tee 1
        local.get 12
        i64.load
        local.tee 14
        i64.or
        local.get 11
        i64.load
        local.tee 15
        local.get 10
        i64.load
        local.tee 16
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 65680
        call $wrapper_mstore_bytes32
        i32.const 4
        i32.const 18
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 9
      i32.const 928
      i32.add
      i32.const 24
      i32.add
      local.get 20
      i64.store
      local.get 9
      local.get 17
      i64.store offset=928
      local.get 9
      local.get 18
      i64.store offset=936
      local.get 9
      local.get 19
      i64.store offset=944
      local.get 9
      i32.const 928
      i32.add
      local.get 9
      i32.const 960
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 992
      i32.add
      i32.const 24
      i32.add
      local.get 13
      i64.store
      local.get 9
      local.get 4
      i64.store offset=1008
      local.get 9
      local.get 3
      i64.store offset=1000
      local.get 9
      local.get 2
      i64.store offset=992
      local.get 9
      i32.const 992
      i32.add
      local.get 9
      i32.const 1024
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 1056
      i32.add
      i32.const 24
      i32.add
      local.get 16
      i64.store
      local.get 9
      local.get 14
      i64.store offset=1072
      local.get 9
      local.get 15
      i64.store offset=1064
      local.get 9
      local.get 1
      i64.store offset=1056
      local.get 21
      local.get 22
      local.get 24
      i64.const 1
      i64.add
      local.tee 13
      local.get 24
      i64.lt_u
      local.tee 25
      local.get 23
      local.get 25
      i64.extend_i32_u
      i64.add
      local.tee 14
      local.get 23
      i64.lt_u
      local.get 13
      local.get 24
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 15
      local.get 22
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.set 16
      local.get 9
      i32.const 1056
      i32.add
      local.get 9
      i32.const 1088
      i32.add
      call $u256_to_big_endian_bytes
      local.get 9
      i32.const 960
      i32.add
      local.get 9
      i32.const 1024
      i32.add
      local.get 9
      i32.const 1088
      i32.add
      local.get 9
      i32.const 1120
      i32.add
      call $wrapper_addmod
      local.get 9
      i32.const 1120
      i32.add
      local.get 9
      i32.const 32
      i32.add
      call $u256_from_big_endian_bytes
      local.get 9
      i32.const 24
      i32.add
      i64.load
      local.set 4
      local.get 9
      i32.const 16
      i32.add
      i64.load
      local.set 3
      local.get 9
      i32.const 8
      i32.add
      i64.load
      local.set 2
      local.get 9
      i32.const 32
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 20
      local.get 9
      i32.const 32
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 19
      local.get 9
      i32.const 32
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 18
      local.get 9
      i64.load
      local.set 1
      local.get 9
      i64.load offset=32
      local.set 17
      local.get 24
      i64.const 90
      i64.lt_u
      i32.const 0
      local.get 23
      i64.eqz
      select
      i32.const 0
      local.get 22
      local.get 21
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
    end
    i32.const 65712
    local.get 9
    i32.const 1408
    i32.add
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 9
      i64.load offset=1408
      local.tee 24
      local.get 9
      i32.const 1408
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 13
      i64.or
      local.get 9
      i32.const 1408
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 22
      local.get 9
      i32.const 1408
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.tee 23
      i64.or
      i64.or
      i64.eqz
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      i32.const 65680
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 18
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 9
    i32.const 1152
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 9
    local.get 1
    i64.store offset=1152
    local.get 9
    local.get 2
    i64.store offset=1160
    local.get 9
    local.get 3
    i64.store offset=1168
    local.get 9
    i32.const 1152
    i32.add
    local.get 9
    i32.const 1184
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 1216
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 9
    local.get 7
    i64.store offset=1232
    local.get 9
    local.get 6
    i64.store offset=1224
    local.get 9
    local.get 5
    i64.store offset=1216
    local.get 9
    i32.const 1216
    i32.add
    local.get 9
    i32.const 1248
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 1280
    i32.add
    i32.const 24
    i32.add
    local.get 23
    i64.store
    local.get 9
    local.get 13
    i64.store offset=1296
    local.get 9
    local.get 22
    i64.store offset=1288
    local.get 9
    local.get 24
    i64.store offset=1280
    local.get 9
    i32.const 1280
    i32.add
    local.get 9
    i32.const 1312
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 1184
    i32.add
    local.get 9
    i32.const 1248
    i32.add
    local.get 9
    i32.const 1312
    i32.add
    local.get 9
    i32.const 1344
    i32.add
    call $wrapper_addmod
    local.get 9
    i32.const 1344
    i32.add
    local.get 9
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    local.get 0
    local.get 9
    i32.const 64
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.store offset=16
    local.get 0
    local.get 9
    i32.const 64
    i32.add
    i32.const 8
    i32.add
    i64.load
    i64.store offset=8
    local.get 0
    local.get 9
    i64.load offset=64
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 9
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 9
    i32.const 1440
    i32.add
    global.set $__stack_pointer)
  (func $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_verify_162 (type 9) (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i32)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 17
    global.set $__stack_pointer
    local.get 1
    i32.wrap_i64
    local.tee 18
    local.get 17
    i32.const 64
    i32.add
    call $wrapper_mload_u256
    block  ;; label = @1
      local.get 17
      i64.load offset=64
      local.get 17
      i32.const 64
      i32.add
      i32.const 16
      i32.add
      local.tee 19
      i64.load
      i64.or
      local.get 17
      i32.const 64
      i32.add
      i32.const 8
      i32.add
      local.tee 20
      i64.load
      local.get 17
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      local.tee 21
      i64.load
      i64.or
      i64.or
      i64.eqz
      br_if 0 (;@1;)
      local.get 13
      i32.wrap_i64
      local.set 22
      i64.const 0
      local.set 23
      i64.const 0
      local.set 24
      i64.const 0
      local.set 25
      i64.const 0
      local.set 26
      loop  ;; label = @2
        local.get 22
        local.get 17
        i32.const 64
        i32.add
        call $wrapper_mload_u256
        block  ;; label = @3
          local.get 17
          i64.load offset=64
          local.get 23
          local.tee 27
          i64.gt_u
          local.get 20
          i64.load
          local.tee 28
          local.get 24
          local.tee 29
          i64.gt_u
          local.get 28
          local.get 29
          i64.eq
          select
          local.get 19
          i64.load
          local.tee 24
          local.get 25
          local.tee 28
          i64.gt_u
          local.get 21
          i64.load
          local.tee 23
          local.get 26
          i64.gt_u
          local.get 23
          local.get 26
          i64.eq
          select
          local.get 24
          local.get 28
          i64.xor
          local.get 23
          local.get 26
          i64.xor
          i64.or
          i64.eqz
          select
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65648
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 50
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        local.get 27
        i64.const 5
        i64.shl
        i64.const 32
        i64.add
        local.tee 23
        local.get 13
        i64.add
        i32.wrap_i64
        local.get 17
        i32.const 64
        i32.add
        call $wrapper_mload_u256
        block  ;; label = @3
          block  ;; label = @4
            local.get 17
            i64.load offset=64
            local.get 19
            i64.load
            i64.or
            local.get 20
            i64.load
            local.get 21
            i64.load
            i64.or
            i64.or
            i64.eqz
            br_if 0 (;@4;)
            local.get 18
            local.get 17
            i32.const 64
            i32.add
            call $wrapper_mload_u256
            block  ;; label = @5
              local.get 17
              i64.load offset=64
              local.get 27
              i64.gt_u
              local.get 20
              i64.load
              local.tee 24
              local.get 29
              i64.gt_u
              local.get 24
              local.get 29
              i64.eq
              select
              local.get 19
              i64.load
              local.tee 25
              local.get 28
              i64.gt_u
              local.get 21
              i64.load
              local.tee 24
              local.get 26
              i64.gt_u
              local.get 24
              local.get 26
              i64.eq
              select
              local.get 25
              local.get 28
              i64.xor
              local.get 24
              local.get 26
              i64.xor
              i64.or
              i64.eqz
              select
              br_if 0 (;@5;)
              i32.const 0
              i32.const 65648
              call $wrapper_mstore_bytes32
              i32.const 4
              i32.const 50
              call $wrapper_mstore_u32
              i32.const 0
              i32.const 36
              call $wrapper_revert
            end
            local.get 23
            local.get 1
            i64.add
            i32.wrap_i64
            local.get 17
            i32.const 64
            i32.add
            call $wrapper_mload_u256
            local.get 17
            i32.const 32
            i32.add
            local.get 17
            i64.load offset=64
            local.get 20
            i64.load
            local.get 19
            i64.load
            local.get 21
            i64.load
            local.get 9
            local.get 10
            local.get 11
            local.get 12
            call $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_mimcHash_99
            local.get 17
            i32.const 32
            i32.add
            i32.const 24
            i32.add
            i64.load
            local.set 12
            local.get 17
            i32.const 32
            i32.add
            i32.const 16
            i32.add
            i64.load
            local.set 11
            local.get 17
            i32.const 32
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.set 10
            local.get 17
            i64.load offset=32
            local.set 9
            br 1 (;@3;)
          end
          local.get 18
          local.get 17
          i32.const 64
          i32.add
          call $wrapper_mload_u256
          block  ;; label = @4
            local.get 17
            i64.load offset=64
            local.get 27
            i64.gt_u
            local.get 20
            i64.load
            local.tee 24
            local.get 29
            i64.gt_u
            local.get 24
            local.get 29
            i64.eq
            select
            local.get 19
            i64.load
            local.tee 25
            local.get 28
            i64.gt_u
            local.get 21
            i64.load
            local.tee 24
            local.get 26
            i64.gt_u
            local.get 24
            local.get 26
            i64.eq
            select
            local.get 25
            local.get 28
            i64.xor
            local.get 24
            local.get 26
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
            i32.const 0
            i32.const 65648
            call $wrapper_mstore_bytes32
            i32.const 4
            i32.const 50
            call $wrapper_mstore_u32
            i32.const 0
            i32.const 36
            call $wrapper_revert
          end
          local.get 23
          local.get 1
          i64.add
          i32.wrap_i64
          local.get 17
          i32.const 64
          i32.add
          call $wrapper_mload_u256
          local.get 17
          local.get 9
          local.get 10
          local.get 11
          local.get 12
          local.get 17
          i64.load offset=64
          local.get 20
          i64.load
          local.get 19
          i64.load
          local.get 21
          i64.load
          call $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_mimcHash_99
          local.get 17
          i32.const 24
          i32.add
          i64.load
          local.set 12
          local.get 17
          i32.const 16
          i32.add
          i64.load
          local.set 11
          local.get 17
          i32.const 8
          i32.add
          i64.load
          local.set 10
          local.get 17
          i64.load
          local.set 9
        end
        local.get 18
        local.get 17
        i32.const 64
        i32.add
        call $wrapper_mload_u256
        local.get 27
        i64.const 1
        i64.add
        local.tee 23
        local.get 17
        i64.load offset=64
        i64.ge_u
        local.get 29
        local.get 23
        local.get 27
        i64.lt_u
        local.tee 30
        i64.extend_i32_u
        i64.add
        local.tee 24
        local.get 20
        i64.load
        local.tee 25
        i64.ge_u
        local.get 24
        local.get 25
        i64.eq
        select
        local.get 28
        local.get 30
        local.get 24
        local.get 29
        i64.lt_u
        local.get 23
        local.get 27
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 25
        local.get 19
        i64.load
        local.tee 29
        i64.ge_u
        local.get 26
        local.get 25
        local.get 28
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 26
        local.get 21
        i64.load
        local.tee 27
        i64.ge_u
        local.get 26
        local.get 27
        i64.eq
        select
        local.get 25
        local.get 29
        i64.xor
        local.get 26
        local.get 27
        i64.xor
        i64.or
        i64.eqz
        select
        i32.eqz
        br_if 0 (;@2;)
      end
    end
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    local.get 9
    local.get 5
    i64.xor
    local.get 11
    local.get 7
    i64.xor
    i64.or
    local.get 10
    local.get 6
    i64.xor
    local.get 12
    local.get 8
    i64.xor
    i64.or
    i64.or
    i64.eqz
    i64.extend_i32_u
    i64.store
    local.get 17
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $MerkleProof_262_deployed.MerkleProof_262_deployed.init (type 5)
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
      i64.const 2298725794
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
        i32.const 3
        i32.gt_u
        br_if 0 (;@2;)
        i32.const 0
        i32.const 0
        call $wrapper_revert
      end
      local.get 0
      call $MerkleProof_262_deployed.MerkleProof_262_deployed.fun_benchmark_261
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 1
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 2
      local.get 0
      i32.const 8
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
      i64.const 0
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=112
      local.get 0
      i64.const 0
      i64.store offset=104
      local.get 0
      local.get 4
      local.get 1
      i64.or
      local.get 3
      local.get 2
      i64.or
      i64.or
      i64.const 0
      i64.ne
      i64.extend_i32_u
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
  (func $call (type 5)
    call $MerkleProof_262_deployed.MerkleProof_262_deployed.init)
  (func $_start (type 5)
    i32.const 1
    call $__init_evm_heap)
  (func $deploy (type 5)
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
    i32.const 82272
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
  (data (;2;) (i32.const 65608) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;3;) (i32.const 65640) "\ff\ff\ff\ff\ff\ff\ff\ffNH{q")
  (data (;4;) (i32.const 65680) "NH{q")
  (data (;5;) (i32.const 65712) "0dNr\e11\a0)\b8PE\b6\81\81X](3\e8Hy\b9p\91C\e1\f5\93\f0\00\00\01")
  (data (;6;) (i32.const 65864) "\01")
  (data (;7;) (i32.const 65870) "\02\00\00\00\03")
  (data (;8;) (i32.const 65882) "\01")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "producers" "\02\08language\01\03C99\00\0cprocessed-by\02\05clangV11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\0cUbuntu clang@16.0.6 (++20231112100510+7cbf1a259152-1~exp1~20231112100554.106)")
  (@custom "name" "\01\d5\07)\00\0fgetCallDataSize\01\0ccallDataCopy\02\0cgetCallValue\03\06revert\04\06finish\05\0bgetCodeSize\06\08codeCopy\07\09keccak256\08\06addmod\09\06mulmod\0a\11__wasm_call_ctors\0b\08__multi3\0c\1au256_from_big_endian_bytes\0d\18u256_to_big_endian_bytes\0e\1cwrapper_calldataload_bytes32\0f\15wrapper_calldata_size\10\1awrapper_callvalue_not_zero\11\0ewrapper_revert\12\13evm_get_memory_addr\13\10wrapper_codecopy\14\14wrapper_memory_guard\15\16wrapper_mstore_bytes32\16\13wrapper_mstore_u256\17\12wrapper_mstore_u32\18\12wrapper_mload_u256\19\11wrapper_keccak256\1a\0ewrapper_return\1b\15wrapper_calldata_copy\1c\13set_is_deploying_tx\1d\0ewrapper_addmod\1e\0ewrapper_mulmod\1f\0f__init_evm_heap \10wrapper_u256_shr!CMerkleProof_262_deployed.MerkleProof_262_deployed.fun_benchmark_261\22sMerkleProof_262_deployed.MerkleProof_262_deployed.allocate_and_zero_memory_array_t_array$_t_uint256_$dyn_memory_ptr#AMerkleProof_262_deployed.MerkleProof_262_deployed.fun_mimcHash_99$@MerkleProof_262_deployed.MerkleProof_262_deployed.fun_verify_162%6MerkleProof_262_deployed.MerkleProof_262_deployed.init&\04call'\06_start(\06deploy\07\12\01\00\0f__stack_pointer\09\08\01\00\05.data")
  (@custom ".debug_str" "y\00x\00low\00wasisdk://v12.0/build/compiler-rt\00du_int\00ti_int\00di_int\00long long int\00long long unsigned int\00uint64_t\00twords\00r\00all\00lower_mask\00high\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins/multi3.c\00b\00a\00__int128\00__multi3\00__mulddi3\00bits_in_dword_2\00clang version 11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\00")
  (@custom ".debug_line" "M\01\00\00\04\00\c2\00\00\00\01\01\01\fb\0e\0d\00\01\01\01\01\00\00\00\01\00\00\01wasisdk://v12.0/build/install/opt/wasi-sdk/share/wasi-sysroot/include/bits\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins\00\00alltypes.h\00\01\00\00int_types.h\00\02\00\00multi3.c\00\02\00\00\00\04\03\00\05\02\05\00\00\00\03'\01\05\03\0aD\05,-\05\18\06X\05\0c\06\03rX\05\0b\1eo\05&`\05\0c\06<\05#\06\03u \05\10\06\ac\05\1e\90\03i<\05\16\06\03\18J\05\1f\22\05\05\06X\03f \05\10\06\03\1cJ\05\22\03\13 \05\0f\03n \05\1f\92\05\05\06X\03a \05\11\06\03!J\05\0c\03\0e \05\03!\05\1f\03pX\05\0b\03yX\97\05\03\03\10 \02\04\00\01\01")
  (@custom ".debug_abbrev" "\01\11\01%\0e\13\05\03\0e\10\17\1b\0e\11\01\12\06\00\00\02$\00\03\0e>\0b\0b\0b\00\00\03\16\00I\13\03\0e:\0b;\0b\00\00\04.\01\03\0e:\0b;\0b'\19I\13 \0b\00\00\05\05\00\03\0e:\0b;\0bI\13\00\00\064\00\03\0e:\0b;\0bI\13\00\00\07\17\01\0b\0b:\0b;\0b\00\00\08\0d\00\03\0eI\13:\0b;\0b8\0b\00\00\09\13\01\0b\0b:\0b;\0b\00\00\0a&\00I\13\00\00\0b.\01\11\01\12\06@\18\97B\19\03\0e:\0b;\0b'\19I\13?\19\00\00\0c\05\00\02\17\03\0e:\0b;\0bI\13\00\00\0d4\00\02\17\03\0e:\0b;\0bI\13\00\00\0e\1d\011\13U\17X\0bY\0bW\0b\00\00\0f\05\001\13\00\00\104\00\02\171\13\00\00\114\00\1c\0d1\13\00\00\124\00\1c\0f1\13\00\00\00")
  (@custom ".debug_ranges" "\0f\00\00\00G\00\00\00H\00\00\00\5c\00\00\00b\00\00\00q\00\00\00\00\00\00\00\00\00\00\00")
  (@custom ".debug_loc" "\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\007\00\00\009\00\00\00\06\00\ed\02\02\9f\93\089\00\00\00G\00\00\00\06\00\ed\00\05\9f\93\08G\00\00\00H\00\00\00\0c\00\ed\00\05\9f\93\08\ed\02\02\9f\93\08H\00\00\00p\00\00\00\06\00\ed\00\05\9f\93\08p\00\00\00q\00\00\00\06\00\ed\02\02\9f\93\08q\00\00\00t\00\00\00\06\00\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00]\00\00\00`\00\00\00\08\00\93\08\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00<\00\00\00B\00\00\00\04\00\ed\02\02\9fQ\00\00\00Y\00\00\00\04\00\ed\02\02\9fY\00\00\00u\00\00\00\04\00\ed\00\03\9f\00\00\00\00\00\00\00\00")
  (@custom ".debug_info" "\b4\01\00\00\04\00\00\00\00\00\04\01\fd\00\00\00\0c\00\8a\00\00\00\00\00\00\00\08\00\00\00\05\00\00\00u\00\00\00\02`\00\00\00\05\04\038\00\00\00*\00\00\00\02&\03C\00\00\00d\00\00\00\01\aa\02M\00\00\00\07\08\04\e3\00\00\00\03\13\99\00\00\00\01\05\cf\00\00\00\03\13-\00\00\00\05\cd\00\00\00\03\13-\00\00\00\06t\00\00\00\03\14\ab\00\00\00\06\ed\00\00\00\03\15\0d\01\00\00\06z\00\00\00\03\16\12\01\00\00\06k\00\00\00\03\18-\00\00\00\00\03\a4\00\00\001\00\00\00\02O\02\d1\00\00\00\05\10\03\b6\00\00\00m\00\00\00\02]\07\10\02R\08v\00\00\00\99\00\00\00\02S\00\08r\00\00\00\d2\00\00\00\02\5c\00\09\10\02T\08\04\00\00\00-\00\00\00\02V\00\08\85\00\00\00\f0\00\00\00\02W\08\00\00\03\fb\00\00\008\00\00\00\02%\03\06\01\00\00e\00\00\00\01\91\02?\00\00\00\05\08\0a&\00\00\00\0a-\00\00\00\0b\05\00\00\00u\00\00\00\07\ed\03\00\00\00\00\9f\da\00\00\00\03(\99\00\00\00\0c\00\00\00\00\cf\00\00\00\03(\99\00\00\00\0c\14\00\00\00\cd\00\00\00\03(\99\00\00\00\0d(\00\00\00\00\00\00\00\03+\ab\00\00\00\0d\aa\00\00\00\02\00\00\00\03)\ab\00\00\00\0d\be\00\00\00t\00\00\00\03-\ab\00\00\00\0eJ\00\00\00\00\00\00\00\03.\0b\0fV\00\00\00\0fa\00\00\00\10<\00\00\00l\00\00\00\11 w\00\00\00\12\ff\ff\ff\ff\0f\82\00\00\00\10\d8\00\00\00\8d\00\00\00\00\00\00"))
