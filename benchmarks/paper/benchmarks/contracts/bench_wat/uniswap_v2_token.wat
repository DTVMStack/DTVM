(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32 i32)))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func (param i32 i32 i32 i32 i32 i32 i32)))
  (type (;5;) (func))
  (type (;6;) (func (param i32) (result i32)))
  (type (;7;) (func (param i32 i32 i32 i32 i32)))
  (import "env" "getCallDataSize" (func $getCallDataSize (type 0)))
  (import "env" "callDataCopy" (func $callDataCopy (type 1)))
  (import "env" "getCaller" (func $getCaller (type 2)))
  (import "env" "getCallValue" (func $getCallValue (type 2)))
  (import "env" "revert" (func $revert (type 3)))
  (import "env" "finish" (func $finish (type 3)))
  (import "env" "getCodeSize" (func $getCodeSize (type 0)))
  (import "env" "codeCopy" (func $codeCopy (type 1)))
  (import "env" "storageStoreLittleEndian" (func $storageStoreLittleEndian (type 3)))
  (import "env" "storageLoadLittleEndian" (func $storageLoadLittleEndian (type 3)))
  (import "env" "keccak256" (func $keccak256 (type 1)))
  (import "env" "emitLogEvent" (func $emitLogEvent (type 4)))
  (func $__wasm_call_ctors (type 5))
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
  (func $i32_from_big_endian_bytes32 (type 6) (param i32) (result i32)
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
      i32.load offset=32884
      local.tee 2
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 2
      i32.store offset=32884
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
              i32.store offset=32884
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
              i32.load8_u offset=33300
              br_if 0 (;@5;)
              i32.const 33200
              i32.const 0
              local.get 3
              call $callDataCopy
              i32.const 0
              i32.const 1
              i32.store8 offset=33300
            end
            local.get 4
            i32.eqz
            br_if 2 (;@2;)
            local.get 0
            i32.const 33200
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
            i32.store offset=32884
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
            i32.load8_u offset=33300
            br_if 0 (;@4;)
            i32.const 33200
            i32.const 0
            local.get 2
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=33300
          end
          local.get 1
          local.get 0
          i32.const 33200
          i32.add
          i32.load8_u
          i32.store8
          local.get 1
          local.get 0
          i32.const 33201
          i32.add
          i32.load8_u
          i32.store8 offset=1
          local.get 1
          local.get 0
          i32.const 33202
          i32.add
          i32.load8_u
          i32.store8 offset=2
          local.get 1
          local.get 0
          i32.const 33203
          i32.add
          i32.load8_u
          i32.store8 offset=3
          local.get 1
          local.get 0
          i32.const 33204
          i32.add
          i32.load8_u
          i32.store8 offset=4
          local.get 1
          local.get 0
          i32.const 33205
          i32.add
          i32.load8_u
          i32.store8 offset=5
          local.get 1
          local.get 0
          i32.const 33206
          i32.add
          i32.load8_u
          i32.store8 offset=6
          local.get 1
          local.get 0
          i32.const 33207
          i32.add
          i32.load8_u
          i32.store8 offset=7
          local.get 1
          local.get 0
          i32.const 33208
          i32.add
          i32.load8_u
          i32.store8 offset=8
          local.get 1
          local.get 0
          i32.const 33209
          i32.add
          i32.load8_u
          i32.store8 offset=9
          local.get 1
          local.get 0
          i32.const 33210
          i32.add
          i32.load8_u
          i32.store8 offset=10
          local.get 1
          local.get 0
          i32.const 33211
          i32.add
          i32.load8_u
          i32.store8 offset=11
          local.get 1
          local.get 0
          i32.const 33212
          i32.add
          i32.load8_u
          i32.store8 offset=12
          local.get 1
          local.get 0
          i32.const 33213
          i32.add
          i32.load8_u
          i32.store8 offset=13
          local.get 1
          local.get 0
          i32.const 33214
          i32.add
          i32.load8_u
          i32.store8 offset=14
          local.get 1
          local.get 0
          i32.const 33215
          i32.add
          i32.load8_u
          i32.store8 offset=15
          local.get 1
          local.get 0
          i32.const 33216
          i32.add
          i32.load8_u
          i32.store8 offset=16
          local.get 1
          local.get 0
          i32.const 33217
          i32.add
          i32.load8_u
          i32.store8 offset=17
          local.get 1
          local.get 0
          i32.const 33218
          i32.add
          i32.load8_u
          i32.store8 offset=18
          local.get 1
          local.get 0
          i32.const 33219
          i32.add
          i32.load8_u
          i32.store8 offset=19
          local.get 1
          local.get 0
          i32.const 33220
          i32.add
          i32.load8_u
          i32.store8 offset=20
          local.get 1
          local.get 0
          i32.const 33221
          i32.add
          i32.load8_u
          i32.store8 offset=21
          local.get 1
          local.get 0
          i32.const 33222
          i32.add
          i32.load8_u
          i32.store8 offset=22
          local.get 1
          local.get 0
          i32.const 33223
          i32.add
          i32.load8_u
          i32.store8 offset=23
          local.get 1
          local.get 0
          i32.const 33224
          i32.add
          i32.load8_u
          i32.store8 offset=24
          local.get 1
          local.get 0
          i32.const 33225
          i32.add
          i32.load8_u
          i32.store8 offset=25
          local.get 1
          local.get 0
          i32.const 33226
          i32.add
          i32.load8_u
          i32.store8 offset=26
          local.get 1
          local.get 0
          i32.const 33227
          i32.add
          i32.load8_u
          i32.store8 offset=27
          local.get 1
          local.get 0
          i32.const 33228
          i32.add
          i32.load8_u
          i32.store8 offset=28
          local.get 1
          local.get 0
          i32.const 33229
          i32.add
          i32.load8_u
          i32.store8 offset=29
          local.get 1
          local.get 0
          i32.const 33230
          i32.add
          i32.load8_u
          i32.store8 offset=30
          local.get 1
          local.get 0
          i32.const 33231
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
      i32.load offset=32884
      local.tee 2
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 2
      i32.store offset=32884
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
          i32.load8_u offset=33300
          br_if 0 (;@3;)
          i32.const 33200
          i32.const 0
          local.get 2
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=33300
        end
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.const 4
              i32.ge_u
              br_if 0 (;@5;)
              i32.const 33200
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
            i32.const 33200
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
              i32.const 33200
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
        i32.store offset=32884
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
          i32.load8_u offset=33300
          br_if 0 (;@3;)
          i32.const 33200
          i32.const 0
          local.get 2
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=33300
        end
        local.get 0
        i32.const 0
        i32.load offset=33200
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
      i32.load offset=32884
      local.tee 0
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 0
      i32.store offset=32884
    end
    local.get 0)
  (func $wrapper_caller (type 2) (param i32)
    local.get 0
    i32.const 12
    i32.add
    call $getCaller
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    i64.const 0
    i64.store align=4)
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
    i32.load offset=33308
    local.get 0
    i32.add
    local.get 1
    call $revert)
  (func $evm_get_memory_addr (type 6) (param i32) (result i32)
    i32.const 0
    i32.load offset=33308
    local.get 0
    i32.add)
  (func $wrapper_codecopy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=33320
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
        i32.store offset=33316
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=33320
        i32.const 0
        i32.const 0
        i32.load offset=33312
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=33312
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=33316
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=33316
    end
    i32.const 0
    i32.load offset=33308
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
          i32.load offset=32884
          local.tee 1
          i32.const -1
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 0
          call $getCallDataSize
          local.tee 1
          i32.store offset=32884
          local.get 1
          i32.const -1
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 0
          call $getCallDataSize
          local.tee 1
          i32.store offset=32884
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
          i32.load8_u offset=33300
          br_if 0 (;@3;)
          i32.const 33200
          i32.const 0
          local.get 1
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=33300
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.const 33200
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
      i32.load offset=33320
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
      i32.store offset=33316
      i32.const 0
      local.get 2
      i32.const -65536
      i32.and
      i32.store offset=33320
      i32.const 0
      i32.const 0
      i32.load offset=33312
      local.get 1
      i32.const 16
      i32.shl
      i32.add
      i32.store offset=33312
      i32.const 96
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=33316
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 0
      i32.store offset=33316
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
          i32.load offset=33320
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
          i32.store offset=33316
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=33320
          i32.const 0
          i32.const 0
          i32.load offset=33312
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=33312
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=33316
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=33316
      end
      i32.const 0
      i32.load offset=33308
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
          i32.load offset=33320
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
          i32.store offset=33316
          i32.const 0
          local.get 7
          i32.const -65536
          i32.and
          i32.store offset=33320
          i32.const 0
          i32.const 0
          i32.load offset=33312
          local.get 1
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=33312
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=33316
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=33316
      end
      i32.const 0
      i32.load offset=33308
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
          i32.load offset=33320
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
          i32.store offset=33316
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=33320
          i32.const 0
          i32.const 0
          i32.load offset=33312
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=33312
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=33316
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=33316
      end
      i32.const 0
      i32.load offset=33308
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
    i32.load offset=33308
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
  (func $wrapper_mload_bytes32 (type 3) (param i32 i32)
    local.get 1
    i32.const 0
    i32.load offset=33308
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
  (func $wrapper_sstore_u256_using_little_endian_hostapi (type 3) (param i32 i32)
    local.get 0
    local.get 1
    call $storageStoreLittleEndian)
  (func $wrapper_sload_u256_using_little_endian_hostapi (type 3) (param i32 i32)
    local.get 0
    local.get 1
    call $storageLoadLittleEndian)
  (func $wrapper_keccak256 (type 1) (param i32 i32 i32)
    i32.const 0
    i32.load offset=33308
    local.get 0
    i32.add
    local.get 1
    local.get 2
    call $keccak256)
  (func $wrapper_return (type 3) (param i32 i32)
    i32.const 0
    i32.load offset=33308
    local.get 0
    i32.add
    local.get 1
    call $finish)
  (func $wrapper_log3 (type 7) (param i32 i32 i32 i32 i32)
    i32.const 0
    i32.load offset=33308
    local.get 0
    i32.add
    local.get 1
    i32.const 3
    local.get 2
    local.get 3
    local.get 4
    i32.const 0
    call $emitLogEvent)
  (func $set_is_deploying_tx (type 5)
    i32.const 0
    i32.const 1
    i32.store8 offset=33184)
  (func $wrapper_current_contract_code_size (type 0) (result i32)
    (local i32 i32)
    i32.const 0
    i32.load8_u offset=33184
    local.set 0
    call $getCodeSize
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      local.get 1
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=32884
      local.tee 0
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 0
      i32.store offset=32884
    end
    block  ;; label = @1
      local.get 0
      i32.const 0
      i32.lt_s
      local.get 1
      local.get 0
      i32.add
      local.tee 0
      local.get 1
      i32.lt_s
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      return
    end
    unreachable
    unreachable)
  (func $wrapper_current_contract_pure_contract_size (type 0) (result i32)
    call $getCodeSize)
  (func $wrapper_data_copy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=33320
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
        i32.store offset=33316
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=33320
        i32.const 0
        i32.const 0
        i32.load offset=33312
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=33312
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=33316
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=33316
    end
    block  ;; label = @1
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      i32.load offset=33308
      local.tee 3
      local.get 0
      i32.add
      local.set 4
      local.get 3
      local.get 1
      i32.add
      local.set 0
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.const 7
          i32.and
          local.tee 1
          br_if 0 (;@3;)
          local.get 2
          local.set 1
          br 1 (;@2;)
        end
        loop  ;; label = @3
          local.get 4
          local.get 0
          i32.load8_u
          i32.store8
          local.get 4
          i32.const 1
          i32.add
          local.set 4
          local.get 0
          i32.const 1
          i32.add
          local.set 0
          local.get 1
          i32.const -1
          i32.add
          local.tee 1
          br_if 0 (;@3;)
        end
        local.get 2
        i32.const -8
        i32.and
        local.set 1
      end
      local.get 2
      i32.const 8
      i32.lt_u
      br_if 0 (;@1;)
      local.get 1
      i32.const -8
      i32.add
      local.set 1
      loop  ;; label = @2
        local.get 4
        local.get 0
        i32.load8_u
        i32.store8
        local.get 4
        local.get 0
        i32.load8_u offset=1
        i32.store8 offset=1
        local.get 4
        local.get 0
        i32.load8_u offset=2
        i32.store8 offset=2
        local.get 4
        local.get 0
        i32.load8_u offset=3
        i32.store8 offset=3
        local.get 4
        local.get 0
        i32.load8_u offset=4
        i32.store8 offset=4
        local.get 4
        local.get 0
        i32.load8_u offset=5
        i32.store8 offset=5
        local.get 4
        local.get 0
        i32.load8_u offset=6
        i32.store8 offset=6
        local.get 4
        local.get 0
        i32.load8_u offset=7
        i32.store8 offset=7
        local.get 1
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        i32.const -8
        i32.add
        local.set 1
        local.get 0
        i32.const 8
        i32.add
        local.set 0
        local.get 4
        i32.const 8
        i32.add
        local.set 4
        br 0 (;@2;)
      end
    end)
  (func $wrapper_calldata_size_minus_4 (type 0) (result i32)
    (local i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=32884
      local.tee 0
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 0
      i32.store offset=32884
    end
    local.get 0
    i32.const -4
    i32.add)
  (func $wrapper_set_memptr_global (type 2) (param i32)
    i32.const 0
    local.get 0
    i32.store offset=33188)
  (func $wrapper_get_memptr_global (type 0) (result i32)
    i32.const 0
    i32.load offset=33188)
  (func $wrapper_optimized_erc20_fun_transfer (type 1) (param i32 i32 i32)
    (local i32 i64 i64 i64 i32 i64 i64 i32 i32 i64 i64 i32 i64 i32)
    global.get $__stack_pointer
    i32.const 304
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i64.load offset=12
        local.tee 4
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        local.get 0
        i64.load offset=20
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load offset=28
        br_if 0 (;@2;)
        i32.const 32800
        i32.const 36
        call $revert
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i64.load offset=12
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        local.get 1
        i64.load offset=20
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=28
        br_if 0 (;@2;)
        i32.const 32848
        i32.const 36
        call $revert
        br 1 (;@1;)
      end
      local.get 3
      i32.const 264
      i32.add
      i64.const 0
      i64.store
      local.get 3
      i32.const 256
      i32.add
      i64.const 0
      i64.store
      local.get 3
      i32.const 248
      i32.add
      i64.const 0
      i64.store
      local.get 3
      i64.const 0
      i64.store offset=240
      local.get 3
      local.get 4
      i64.const 56
      i64.shr_u
      i32.wrap_i64
      i32.store8 offset=227
      local.get 3
      local.get 4
      i64.const 48
      i64.shr_u
      i32.wrap_i64
      i32.store8 offset=226
      local.get 3
      local.get 4
      i64.const 40
      i64.shr_u
      i32.wrap_i64
      i32.store8 offset=225
      local.get 3
      local.get 4
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.store8 offset=224
      local.get 3
      local.get 4
      i64.const 24
      i64.shr_u
      i32.wrap_i64
      i32.store8 offset=223
      local.get 3
      local.get 4
      i64.const 16
      i64.shr_u
      i32.wrap_i64
      i32.store8 offset=222
      local.get 3
      local.get 4
      i64.const 8
      i64.shr_u
      i32.wrap_i64
      i32.store8 offset=221
      local.get 3
      local.get 4
      i32.wrap_i64
      i32.store8 offset=220
      local.get 3
      local.get 0
      i32.load8_u
      i32.store8 offset=208
      local.get 3
      local.get 0
      i32.load16_u offset=1 align=1
      i32.store16 offset=209 align=1
      local.get 3
      local.get 0
      i64.load offset=3 align=1
      i64.store offset=211 align=1
      local.get 3
      local.get 0
      i32.load8_u offset=11
      i32.store8 offset=219
      local.get 3
      local.get 0
      i32.load8_u offset=20
      i32.store8 offset=228
      local.get 3
      local.get 0
      i64.load offset=21 align=1
      i64.store offset=229 align=1
      local.get 3
      local.get 0
      i32.load16_u offset=29 align=1
      i32.store16 offset=237 align=1
      local.get 3
      local.get 0
      i32.load8_u offset=31
      i32.store8 offset=239
      local.get 3
      i32.const 208
      i32.add
      i32.const 64
      local.get 3
      i32.const 272
      i32.add
      call $keccak256
      local.get 3
      i32.const 272
      i32.add
      local.get 3
      i32.const 176
      i32.add
      call $storageLoadLittleEndian
      block  ;; label = @2
        local.get 3
        i64.load offset=176
        local.tee 5
        local.get 2
        i64.load offset=24 align=1
        local.tee 4
        i64.const 56
        i64.shl
        local.get 4
        i64.const 65280
        i64.and
        i64.const 40
        i64.shl
        i64.or
        local.get 4
        i64.const 16711680
        i64.and
        i64.const 24
        i64.shl
        local.get 4
        i64.const 4278190080
        i64.and
        i64.const 8
        i64.shl
        i64.or
        i64.or
        local.get 4
        i64.const 8
        i64.shr_u
        i64.const 4278190080
        i64.and
        local.get 4
        i64.const 24
        i64.shr_u
        i64.const 16711680
        i64.and
        i64.or
        local.get 4
        i64.const 40
        i64.shr_u
        i64.const 65280
        i64.and
        local.get 4
        i64.const 56
        i64.shr_u
        i64.or
        i64.or
        i64.or
        local.tee 6
        i64.ge_u
        local.get 3
        i32.const 176
        i32.add
        i32.const 8
        i32.add
        local.tee 7
        i64.load
        local.tee 8
        local.get 2
        i64.load8_u offset=23
        local.get 2
        i64.load8_u offset=22
        i64.const 8
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=21
        i64.const 16
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=20
        i64.const 24
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=19
        i64.const 32
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=18
        i64.const 40
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=17
        i64.const 48
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=16
        i64.const 56
        i64.shl
        i64.or
        local.tee 9
        i64.ge_u
        local.get 8
        local.get 9
        i64.eq
        local.tee 10
        select
        local.get 3
        i32.const 176
        i32.add
        i32.const 16
        i32.add
        local.tee 11
        i64.load
        local.tee 12
        local.get 2
        i64.load8_u offset=15
        local.get 2
        i64.load8_u offset=14
        i64.const 8
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=13
        i64.const 16
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=12
        i64.const 24
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=11
        i64.const 32
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=10
        i64.const 40
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=9
        i64.const 48
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=8
        i64.const 56
        i64.shl
        i64.or
        local.tee 13
        i64.ge_u
        local.get 3
        i32.const 176
        i32.add
        i32.const 24
        i32.add
        local.tee 14
        i64.load
        local.tee 4
        local.get 2
        i64.load8_u offset=7
        local.get 2
        i64.load8_u offset=6
        i64.const 8
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=5
        i64.const 16
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=4
        i64.const 24
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=3
        i64.const 32
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=2
        i64.const 40
        i64.shl
        i64.or
        local.get 2
        i64.load8_u offset=1
        i64.const 48
        i64.shl
        i64.or
        local.get 2
        i64.load8_u
        i64.const 56
        i64.shl
        i64.or
        local.tee 15
        i64.ge_u
        local.get 4
        local.get 15
        i64.eq
        select
        local.get 12
        local.get 13
        i64.xor
        local.get 4
        local.get 15
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        local.get 3
        i32.const 160
        i32.add
        i32.const 0
        i32.store
        local.get 3
        i32.const 152
        i32.add
        i64.const 0
        i64.store
        local.get 3
        i64.const 0
        i64.store offset=144
        local.get 3
        i32.const -1932308252
        i32.store offset=64
        local.get 3
        local.get 0
        i32.load16_u align=1
        i32.store16 offset=68
        local.get 3
        local.get 0
        i64.load offset=2 align=1
        i64.store offset=70 align=2
        local.get 3
        local.get 0
        i64.load offset=10 align=1
        i64.store offset=78 align=2
        local.get 3
        local.get 0
        i32.load offset=18 align=1
        i32.store offset=86 align=2
        local.get 3
        local.get 0
        i32.load16_u offset=22 align=1
        i32.store16 offset=90
        local.get 3
        local.get 0
        i32.load8_u offset=24
        i32.store8 offset=92
        local.get 3
        local.get 0
        i32.load8_u offset=25
        i32.store8 offset=93
        local.get 3
        local.get 5
        i64.const 32
        i64.shr_u
        i64.store8 offset=127
        local.get 3
        local.get 5
        i64.const 40
        i64.shr_u
        i64.store8 offset=126
        local.get 3
        local.get 5
        i64.const 48
        i64.shr_u
        i64.store8 offset=125
        local.get 3
        local.get 5
        i64.const 56
        i64.shr_u
        i64.store8 offset=124
        local.get 3
        local.get 8
        i64.const 32
        i64.shr_u
        i64.store8 offset=119
        local.get 3
        local.get 8
        i64.const 40
        i64.shr_u
        i64.store8 offset=118
        local.get 3
        local.get 8
        i64.const 48
        i64.shr_u
        i64.store8 offset=117
        local.get 3
        local.get 8
        i64.const 56
        i64.shr_u
        i64.store8 offset=116
        local.get 3
        local.get 0
        i32.load16_u offset=26 align=1
        i32.store16 offset=94
        local.get 3
        local.get 0
        i32.load offset=28 align=1
        i32.store offset=96
        local.get 3
        local.get 12
        i64.const 32
        i64.shr_u
        i64.store8 offset=111
        local.get 3
        local.get 12
        i64.const 40
        i64.shr_u
        i64.store8 offset=110
        local.get 3
        local.get 12
        i64.const 48
        i64.shr_u
        i64.store8 offset=109
        local.get 3
        local.get 12
        i64.const 56
        i64.shr_u
        i64.store8 offset=108
        local.get 3
        local.get 5
        i32.wrap_i64
        local.tee 0
        i32.store8 offset=131
        local.get 3
        local.get 0
        i32.const 8
        i32.shr_u
        i32.store8 offset=130
        local.get 3
        local.get 0
        i32.const 16
        i32.shr_u
        i32.store8 offset=129
        local.get 3
        local.get 0
        i32.const 24
        i32.shr_u
        i32.store8 offset=128
        local.get 3
        local.get 8
        i32.wrap_i64
        local.tee 0
        i32.store8 offset=123
        local.get 3
        local.get 0
        i32.const 8
        i32.shr_u
        i32.store8 offset=122
        local.get 3
        local.get 0
        i32.const 16
        i32.shr_u
        i32.store8 offset=121
        local.get 3
        local.get 0
        i32.const 24
        i32.shr_u
        i32.store8 offset=120
        local.get 3
        local.get 4
        i64.const 32
        i64.shr_u
        i64.store8 offset=103
        local.get 3
        local.get 4
        i64.const 40
        i64.shr_u
        i64.store8 offset=102
        local.get 3
        local.get 4
        i64.const 48
        i64.shr_u
        i64.store8 offset=101
        local.get 3
        local.get 4
        i64.const 56
        i64.shr_u
        i64.store8 offset=100
        local.get 3
        local.get 12
        i32.wrap_i64
        local.tee 0
        i32.store8 offset=115
        local.get 3
        local.get 0
        i32.const 8
        i32.shr_u
        i32.store8 offset=114
        local.get 3
        local.get 0
        i32.const 16
        i32.shr_u
        i32.store8 offset=113
        local.get 3
        local.get 0
        i32.const 24
        i32.shr_u
        i32.store8 offset=112
        local.get 3
        local.get 4
        i32.wrap_i64
        local.tee 0
        i32.store8 offset=107
        local.get 3
        local.get 0
        i32.const 8
        i32.shr_u
        i32.store8 offset=106
        local.get 3
        local.get 0
        i32.const 16
        i32.shr_u
        i32.store8 offset=105
        local.get 3
        local.get 0
        i32.const 24
        i32.shr_u
        i32.store8 offset=104
        local.get 3
        local.get 2
        i32.load8_u
        i32.store8 offset=132
        local.get 3
        local.get 2
        i32.load offset=1 align=1
        i32.store offset=133 align=1
        local.get 3
        local.get 2
        i64.load offset=5 align=1
        i64.store offset=137 align=1
        local.get 3
        local.get 2
        i64.load offset=13 align=1
        i64.store offset=145 align=1
        local.get 3
        local.get 2
        i64.load offset=21 align=1
        i64.store offset=153 align=1
        local.get 3
        local.get 2
        i32.load16_u offset=29 align=1
        i32.store16 offset=161 align=1
        local.get 3
        local.get 2
        i32.load8_u offset=31
        i32.store8 offset=163
        local.get 3
        i32.const 64
        i32.add
        i32.const 100
        call $revert
        br 1 (;@1;)
      end
      local.get 3
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      local.get 4
      local.get 15
      i64.sub
      local.get 12
      local.get 13
      i64.lt_u
      i64.extend_i32_u
      i64.sub
      local.get 12
      local.get 13
      i64.sub
      local.tee 4
      local.get 5
      local.get 6
      i64.lt_u
      local.tee 16
      local.get 8
      local.get 9
      i64.lt_u
      local.get 10
      select
      i64.extend_i32_u
      local.tee 12
      i64.lt_u
      i64.extend_i32_u
      i64.sub
      i64.store
      local.get 3
      local.get 5
      local.get 6
      i64.sub
      i64.store offset=64
      local.get 3
      local.get 8
      local.get 9
      i64.sub
      local.get 16
      i64.extend_i32_u
      i64.sub
      i64.store offset=72
      local.get 3
      local.get 4
      local.get 12
      i64.sub
      i64.store offset=80
      local.get 3
      i32.const 272
      i32.add
      local.get 3
      i32.const 64
      i32.add
      call $storageStoreLittleEndian
      local.get 3
      local.get 1
      i32.load8_u
      i32.store8 offset=208
      local.get 3
      local.get 1
      i32.load offset=1 align=1
      i32.store offset=209 align=1
      local.get 3
      local.get 1
      i64.load offset=5 align=1
      i64.store offset=213 align=1
      local.get 3
      local.get 1
      i64.load offset=13 align=1
      i64.store offset=221 align=1
      local.get 3
      local.get 1
      i64.load offset=21 align=1
      i64.store offset=229 align=1
      local.get 3
      local.get 1
      i32.load16_u offset=29 align=1
      i32.store16 offset=237 align=1
      local.get 3
      local.get 1
      i32.load8_u offset=31
      i32.store8 offset=239
      local.get 3
      i32.const 208
      i32.add
      i32.const 64
      local.get 3
      i32.const 272
      i32.add
      call $keccak256
      local.get 3
      i32.const 272
      i32.add
      local.get 3
      i32.const 176
      i32.add
      call $storageLoadLittleEndian
      local.get 7
      i64.load
      local.set 4
      local.get 3
      local.get 3
      i64.load offset=176
      local.tee 8
      local.get 6
      i64.add
      local.tee 12
      i64.store offset=32
      local.get 3
      local.get 4
      local.get 9
      i64.add
      local.get 12
      local.get 8
      i64.lt_u
      local.tee 7
      i64.extend_i32_u
      i64.add
      local.tee 8
      i64.store offset=40
      local.get 3
      local.get 11
      i64.load
      local.tee 5
      local.get 13
      i64.add
      local.tee 12
      local.get 7
      local.get 8
      local.get 4
      i64.lt_u
      local.get 8
      local.get 4
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 4
      i64.store offset=48
      local.get 3
      i32.const 32
      i32.add
      i32.const 24
      i32.add
      local.get 14
      i64.load
      local.get 15
      i64.add
      local.get 12
      local.get 5
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 4
      local.get 12
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 3
      i32.const 272
      i32.add
      local.get 3
      i32.const 32
      i32.add
      call $storageStoreLittleEndian
      local.get 3
      i32.const 24
      i32.add
      i32.const 0
      i64.load offset=32792
      i64.store
      local.get 3
      i32.const 16
      i32.add
      i32.const 0
      i64.load offset=32784
      i64.store
      local.get 3
      i32.const 0
      i64.load offset=32776
      i64.store offset=8
      local.get 3
      i32.const 0
      i64.load offset=32768
      i64.store
      local.get 2
      i32.const 32
      i32.const 3
      local.get 3
      local.get 0
      local.get 1
      i32.const 0
      call $emitLogEvent
    end
    local.get 3
    i32.const 304
    i32.add
    global.set $__stack_pointer)
  (func $__init_evm_heap (type 5)
    (local i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load8_u offset=33304
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
          i32.store offset=33308
          i32.const 1
          memory.grow
          drop
          memory.size
          i32.const 16
          i32.shl
          local.tee 0
          i32.const 0
          i32.load offset=33308
          i32.sub
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 33328
        i32.store offset=33308
        i32.const 49712
        local.set 0
        i32.const 16384
        local.set 1
      end
      i32.const 0
      local.get 0
      i32.store offset=33312
      i32.const 0
      local.get 1
      i32.store offset=33320
      i32.const 0
      i32.const 1
      i32.store8 offset=33304
      i32.const 0
      i32.const 0
      i32.store offset=33316
    end)
  (func $wrapper_bytes32_iszero (type 6) (param i32) (result i32)
    (local i32)
    i32.const 0
    local.set 1
    block  ;; label = @1
      local.get 0
      i64.load
      i64.const 0
      i64.ne
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=8
      i64.const 0
      i64.ne
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=16
      i64.const 0
      i64.ne
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=24
      i64.eqz
      local.set 1
    end
    local.get 1)
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
  (func $wrapper_u256_shl (type 1) (param i32 i32 i32)
    (local i32 i64 i64 i64 i64 i32 i64 i64)
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
      i32.const 32
      i32.add
      local.tee 8
      local.get 0
      i64.load
      i64.store align=1
      local.get 3
      i32.const 24
      i32.add
      i64.const 0
      i64.store align=1
      local.get 3
      i32.const 56
      i32.add
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.store align=1
      local.get 3
      i32.const 48
      i32.add
      local.get 0
      i32.const 16
      i32.add
      i64.load
      i64.store align=1
      local.get 3
      i32.const 40
      i32.add
      local.get 0
      i32.const 8
      i32.add
      i64.load
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
      local.get 8
      local.get 1
      i32.const 3
      i32.shr_u
      i32.const 31
      i32.and
      i32.sub
      local.tee 0
      i32.const 8
      i32.add
      i64.load align=1
      local.tee 5
      local.get 1
      i32.const 7
      i32.and
      local.tee 3
      i64.extend_i32_u
      local.tee 7
      i64.shl
      local.get 0
      i64.load align=1
      local.tee 9
      i64.const 1
      i64.shr_u
      local.get 3
      i32.const 63
      i32.xor
      i64.extend_i32_u
      local.tee 4
      i64.shr_u
      i64.or
      local.set 6
      local.get 0
      i32.const 24
      i32.add
      i64.load align=1
      local.get 7
      i64.shl
      local.get 0
      i32.const 16
      i32.add
      i64.load align=1
      local.tee 10
      i64.const 1
      i64.shr_u
      local.get 4
      i64.shr_u
      i64.or
      local.set 4
      local.get 10
      local.get 7
      i64.shl
      local.get 5
      i64.const 1
      i64.shr_u
      local.get 3
      i32.const -1
      i32.xor
      i32.const 63
      i32.and
      i64.extend_i32_u
      i64.shr_u
      i64.or
      local.set 5
      local.get 9
      local.get 7
      i64.shl
      local.set 7
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
  (func $GLDToken_48477_deployed.GLDToken_48477_deployed.init (type 5)
    (local i32 i32 i32 i64 i64 i64 i64 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 96
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
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  block  ;; label = @8
                    block  ;; label = @9
                      block  ;; label = @10
                        block  ;; label = @11
                          call $wrapper_calldata_load_selector
                          local.tee 2
                          i32.const 404098524
                          i32.gt_s
                          br_if 0 (;@11;)
                          block  ;; label = @12
                            local.get 2
                            i32.const -580719299
                            i32.gt_s
                            br_if 0 (;@12;)
                            local.get 2
                            i32.const -1780966591
                            i32.eq
                            br_if 7 (;@5;)
                            local.get 2
                            i32.const -1459249989
                            i32.ne
                            br_if 11 (;@1;)
                            block  ;; label = @13
                              call $wrapper_callvalue_not_zero
                              i32.eqz
                              br_if 0 (;@13;)
                              i32.const 0
                              i32.const 0
                              call $wrapper_revert
                            end
                            block  ;; label = @13
                              call $wrapper_calldata_size_minus_4
                              i32.const 63
                              i32.gt_u
                              br_if 0 (;@13;)
                              i32.const 0
                              i32.const 0
                              call $wrapper_revert
                            end
                            i32.const 4
                            local.get 1
                            call $wrapper_calldataload_bytes32
                            local.get 1
                            local.get 1
                            i32.const 64
                            i32.add
                            call $u256_from_big_endian_bytes
                            local.get 1
                            i32.const 72
                            i32.add
                            i64.load
                            local.set 3
                            local.get 1
                            i32.const 80
                            i32.add
                            i64.load
                            local.set 4
                            local.get 1
                            i32.const 64
                            i32.add
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 5
                            local.get 1
                            i64.load offset=64
                            local.set 6
                            local.get 0
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 0
                            global.set $__stack_pointer
                            local.get 2
                            call $wrapper_caller
                            local.get 0
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 7
                            global.set $__stack_pointer
                            local.get 0
                            i32.const 24
                            i32.add
                            local.get 5
                            i64.store
                            local.get 0
                            local.get 4
                            i64.store offset=16
                            local.get 0
                            local.get 3
                            i64.store offset=8
                            local.get 0
                            local.get 6
                            i64.store
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 7
                            local.tee 8
                            global.set $__stack_pointer
                            local.get 0
                            local.get 7
                            call $u256_to_big_endian_bytes
                            local.get 8
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 8
                            global.set $__stack_pointer
                            i32.const 36
                            local.get 0
                            call $wrapper_calldataload_bytes32
                            local.get 2
                            local.get 7
                            local.get 0
                            call $wrapper_optimized_erc20_fun_transfer
                            local.get 8
                            i32.const -32
                            i32.add
                            local.tee 0
                            global.set $__stack_pointer
                            i32.const 64
                            local.get 0
                            call $wrapper_mload_bytes32
                            local.get 0
                            call $i32_from_big_endian_bytes32
                            local.tee 0
                            i32.const 1
                            call $wrapper_mstore_u32
                            local.get 0
                            i32.const 32
                            call $wrapper_return
                            br 11 (;@1;)
                          end
                          local.get 2
                          i32.const -580719298
                          i32.eq
                          br_if 7 (;@4;)
                          local.get 2
                          i32.const 117300739
                          i32.eq
                          br_if 1 (;@10;)
                          local.get 2
                          i32.const 157198259
                          i32.ne
                          br_if 10 (;@1;)
                          block  ;; label = @12
                            call $wrapper_callvalue_not_zero
                            i32.eqz
                            br_if 0 (;@12;)
                            i32.const 0
                            i32.const 0
                            call $wrapper_revert
                          end
                          block  ;; label = @12
                            call $wrapper_calldata_size_minus_4
                            i32.const 63
                            i32.gt_u
                            br_if 0 (;@12;)
                            i32.const 0
                            i32.const 0
                            call $wrapper_revert
                          end
                          i32.const 4
                          local.get 1
                          call $wrapper_calldataload_bytes32
                          local.get 1
                          local.get 1
                          i32.const 64
                          i32.add
                          call $u256_from_big_endian_bytes
                          local.get 1
                          i32.const 64
                          i32.add
                          i32.const 24
                          i32.add
                          i64.load
                          local.set 3
                          local.get 1
                          i32.const 64
                          i32.add
                          i32.const 16
                          i32.add
                          i64.load
                          local.set 4
                          local.get 1
                          i32.const 64
                          i32.add
                          i32.const 8
                          i32.add
                          i64.load
                          local.set 5
                          local.get 1
                          i64.load offset=64
                          local.set 6
                          local.get 0
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 2
                          global.set $__stack_pointer
                          i32.const 36
                          local.get 0
                          call $wrapper_calldataload_bytes32
                          local.get 2
                          i32.const -32
                          i32.add
                          local.tee 7
                          local.tee 2
                          global.set $__stack_pointer
                          local.get 7
                          call $wrapper_caller
                          block  ;; label = @12
                            local.get 7
                            call $wrapper_bytes32_iszero
                            i32.eqz
                            br_if 0 (;@12;)
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 8
                            local.tee 2
                            global.set $__stack_pointer
                            i32.const 64
                            local.get 8
                            call $wrapper_mload_bytes32
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 7
                            global.set $__stack_pointer
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 7
                            local.tee 9
                            global.set $__stack_pointer
                            local.get 7
                            i32.const 24
                            i32.add
                            i32.const 32928
                            i32.const 24
                            i32.add
                            i64.load
                            i64.store align=1
                            local.get 7
                            i32.const 16
                            i32.add
                            i32.const 32928
                            i32.const 16
                            i32.add
                            i64.load
                            i64.store align=1
                            local.get 7
                            i32.const 8
                            i32.add
                            i32.const 32928
                            i32.const 8
                            i32.add
                            i64.load
                            i64.store align=1
                            local.get 7
                            i32.const 0
                            i64.load offset=32928
                            i64.store align=1
                            local.get 7
                            local.get 2
                            call $u256_from_big_endian_bytes
                            local.get 2
                            i64.load
                            local.set 10
                            local.get 2
                            i32.const 8
                            i32.add
                            i64.load
                            local.set 11
                            local.get 2
                            i32.const 16
                            i32.add
                            i64.load
                            local.set 12
                            local.get 2
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 13
                            local.get 9
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 7
                            global.set $__stack_pointer
                            local.get 2
                            i32.const 24
                            i32.add
                            local.get 13
                            i64.store
                            local.get 2
                            local.get 12
                            i64.store offset=16
                            local.get 2
                            local.get 11
                            i64.store offset=8
                            local.get 2
                            local.get 10
                            i64.store
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 7
                            local.tee 9
                            global.set $__stack_pointer
                            local.get 2
                            i32.const 224
                            local.get 7
                            call $wrapper_u256_shl
                            local.get 7
                            i64.load
                            local.set 10
                            local.get 7
                            i32.const 8
                            i32.add
                            i64.load
                            local.set 11
                            local.get 7
                            i32.const 16
                            i32.add
                            i64.load
                            local.set 12
                            local.get 7
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 13
                            local.get 8
                            call $i32_from_big_endian_bytes32
                            local.set 7
                            local.get 9
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 9
                            global.set $__stack_pointer
                            local.get 2
                            i32.const 24
                            i32.add
                            local.get 13
                            i64.store
                            local.get 2
                            local.get 12
                            i64.store offset=16
                            local.get 2
                            local.get 11
                            i64.store offset=8
                            local.get 2
                            local.get 10
                            i64.store
                            local.get 7
                            local.get 2
                            call $wrapper_mstore_u256
                            local.get 9
                            i32.const -32
                            i32.add
                            local.tee 9
                            local.tee 2
                            global.set $__stack_pointer
                            local.get 8
                            local.get 9
                            call $u256_from_big_endian_bytes
                            local.get 9
                            i32.load
                            i32.const 4
                            i32.add
                            i32.const 0
                            call $wrapper_mstore_u32
                            local.get 7
                            i32.const 36
                            call $wrapper_revert
                          end
                          block  ;; label = @12
                            local.get 6
                            local.get 4
                            i64.or
                            local.get 5
                            local.get 3
                            i64.or
                            i64.or
                            i64.const 0
                            i64.ne
                            br_if 0 (;@12;)
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 7
                            local.tee 2
                            global.set $__stack_pointer
                            i32.const 64
                            local.get 7
                            call $wrapper_mload_bytes32
                            local.get 7
                            call $i32_from_big_endian_bytes32
                            local.set 8
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 9
                            global.set $__stack_pointer
                            local.get 2
                            i32.const 24
                            i32.add
                            i64.const -7770946442469834752
                            i64.store
                            local.get 2
                            i64.const 0
                            i64.store offset=16
                            local.get 2
                            i64.const 0
                            i64.store offset=8
                            local.get 2
                            i64.const 0
                            i64.store
                            local.get 8
                            local.get 2
                            call $wrapper_mstore_u256
                            local.get 9
                            i32.const -32
                            i32.add
                            local.tee 9
                            local.tee 2
                            global.set $__stack_pointer
                            local.get 7
                            local.get 9
                            call $u256_from_big_endian_bytes
                            local.get 9
                            i32.load
                            i32.const 4
                            i32.add
                            i32.const 0
                            call $wrapper_mstore_u32
                            local.get 8
                            i32.const 36
                            call $wrapper_revert
                          end
                          local.get 2
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 7
                          global.set $__stack_pointer
                          local.get 2
                          call $wrapper_caller
                          i32.const 0
                          local.get 2
                          call $wrapper_mstore_bytes32
                          i32.const 32
                          i32.const 1
                          call $wrapper_mstore_u32
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 7
                          local.tee 2
                          global.set $__stack_pointer
                          i32.const 0
                          i32.const 64
                          local.get 7
                          call $wrapper_keccak256
                          local.get 2
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 8
                          global.set $__stack_pointer
                          local.get 2
                          i32.const 24
                          i32.add
                          local.get 3
                          i64.store
                          local.get 2
                          local.get 4
                          i64.store offset=16
                          local.get 2
                          local.get 5
                          i64.store offset=8
                          local.get 2
                          local.get 6
                          i64.store
                          i32.const 0
                          local.get 2
                          call $wrapper_mstore_u256
                          i32.const 32
                          local.get 7
                          call $wrapper_mstore_bytes32
                          local.get 8
                          i32.const -32
                          i32.add
                          local.tee 8
                          local.tee 2
                          global.set $__stack_pointer
                          i32.const 0
                          i32.const 64
                          local.get 8
                          call $wrapper_keccak256
                          local.get 2
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 7
                          global.set $__stack_pointer
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 7
                          local.tee 9
                          global.set $__stack_pointer
                          local.get 7
                          i32.const 24
                          i32.add
                          local.get 0
                          i32.const 24
                          i32.add
                          i64.load align=1
                          i64.store align=1
                          local.get 7
                          i32.const 16
                          i32.add
                          local.get 0
                          i32.const 16
                          i32.add
                          i64.load align=1
                          i64.store align=1
                          local.get 7
                          i32.const 8
                          i32.add
                          local.get 0
                          i32.const 8
                          i32.add
                          i64.load align=1
                          i64.store align=1
                          local.get 7
                          local.get 0
                          i64.load align=1
                          i64.store align=1
                          local.get 7
                          local.get 2
                          call $u256_from_big_endian_bytes
                          local.get 2
                          i64.load
                          local.set 10
                          local.get 2
                          i32.const 8
                          i32.add
                          i64.load
                          local.set 11
                          local.get 2
                          i32.const 16
                          i32.add
                          i64.load
                          local.set 12
                          local.get 2
                          i32.const 24
                          i32.add
                          i64.load
                          local.set 13
                          local.get 9
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 7
                          global.set $__stack_pointer
                          local.get 2
                          i32.const 24
                          i32.add
                          local.get 13
                          i64.store
                          local.get 2
                          local.get 12
                          i64.store offset=16
                          local.get 2
                          local.get 11
                          i64.store offset=8
                          local.get 2
                          local.get 10
                          i64.store
                          local.get 8
                          local.get 2
                          call $wrapper_sstore_u256_using_little_endian_hostapi
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 7
                          global.set $__stack_pointer
                          i32.const 64
                          local.get 2
                          call $wrapper_mload_bytes32
                          local.get 2
                          call $i32_from_big_endian_bytes32
                          local.tee 8
                          local.get 0
                          call $wrapper_mstore_bytes32
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 0
                          global.set $__stack_pointer
                          local.get 2
                          call $wrapper_caller
                          local.get 0
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 7
                          global.set $__stack_pointer
                          local.get 0
                          i32.const 24
                          i32.add
                          local.get 3
                          i64.store
                          local.get 0
                          local.get 4
                          i64.store offset=16
                          local.get 0
                          local.get 5
                          i64.store offset=8
                          local.get 0
                          local.get 6
                          i64.store
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 7
                          local.tee 9
                          global.set $__stack_pointer
                          local.get 0
                          local.get 7
                          call $u256_to_big_endian_bytes
                          local.get 8
                          i32.const 32
                          i32.const 32960
                          local.get 2
                          local.get 7
                          call $wrapper_log3
                          local.get 9
                          i32.const -32
                          i32.add
                          local.tee 0
                          global.set $__stack_pointer
                          i32.const 64
                          local.get 0
                          call $wrapper_mload_bytes32
                          local.get 0
                          call $i32_from_big_endian_bytes32
                          local.tee 0
                          i32.const 1
                          call $wrapper_mstore_u32
                          local.get 0
                          i32.const 32
                          call $wrapper_return
                          br 10 (;@1;)
                        end
                        block  ;; label = @11
                          local.get 2
                          i32.const 826074470
                          i32.gt_s
                          br_if 0 (;@11;)
                          local.get 2
                          i32.const 404098525
                          i32.eq
                          br_if 2 (;@9;)
                          local.get 2
                          i32.const 599290589
                          i32.ne
                          br_if 10 (;@1;)
                          block  ;; label = @12
                            call $wrapper_callvalue_not_zero
                            i32.eqz
                            br_if 0 (;@12;)
                            i32.const 0
                            i32.const 0
                            call $wrapper_revert
                          end
                          block  ;; label = @12
                            call $wrapper_calldata_size_minus_4
                            i32.const 95
                            i32.gt_u
                            br_if 0 (;@12;)
                            i32.const 0
                            i32.const 0
                            call $wrapper_revert
                          end
                          i32.const 4
                          local.get 1
                          call $wrapper_calldataload_bytes32
                          local.get 1
                          local.get 1
                          i32.const 64
                          i32.add
                          call $u256_from_big_endian_bytes
                          local.get 1
                          i32.const 64
                          i32.add
                          i32.const 8
                          i32.add
                          local.tee 2
                          i64.load
                          local.set 4
                          local.get 1
                          i32.const 64
                          i32.add
                          i32.const 16
                          i32.add
                          local.tee 7
                          i64.load
                          local.set 5
                          local.get 1
                          i32.const 64
                          i32.add
                          i32.const 24
                          i32.add
                          local.tee 8
                          i64.load
                          local.set 6
                          local.get 1
                          i64.load offset=64
                          local.set 10
                          i32.const 36
                          local.get 1
                          call $wrapper_calldataload_bytes32
                          local.get 1
                          local.get 1
                          i32.const 64
                          i32.add
                          call $u256_from_big_endian_bytes
                          local.get 8
                          i64.load
                          local.set 14
                          local.get 7
                          i64.load
                          local.set 15
                          local.get 2
                          i64.load
                          local.set 16
                          local.get 1
                          i64.load offset=64
                          local.set 17
                          local.get 0
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 0
                          global.set $__stack_pointer
                          i32.const 68
                          local.get 2
                          call $wrapper_calldataload_bytes32
                          local.get 0
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 7
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
                          local.get 10
                          i64.store
                          i32.const 0
                          local.get 0
                          call $wrapper_mstore_u256
                          i32.const 32
                          i32.const 1
                          call $wrapper_mstore_u32
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 7
                          global.set $__stack_pointer
                          i32.const 0
                          i32.const 64
                          local.get 0
                          call $wrapper_keccak256
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 7
                          local.tee 8
                          global.set $__stack_pointer
                          local.get 7
                          call $wrapper_caller
                          i32.const 0
                          local.get 7
                          call $wrapper_mstore_bytes32
                          i32.const 32
                          local.get 0
                          call $wrapper_mstore_bytes32
                          local.get 8
                          i32.const -32
                          i32.add
                          local.tee 8
                          local.tee 0
                          global.set $__stack_pointer
                          i32.const 0
                          i32.const 64
                          local.get 8
                          call $wrapper_keccak256
                          local.get 0
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 7
                          global.set $__stack_pointer
                          local.get 8
                          local.get 0
                          call $wrapper_sload_u256_using_little_endian_hostapi
                          block  ;; label = @12
                            local.get 0
                            i64.load
                            local.tee 13
                            local.get 0
                            i32.const 16
                            i32.add
                            i64.load
                            local.tee 11
                            i64.and
                            local.get 0
                            i32.const 8
                            i32.add
                            i64.load
                            local.tee 3
                            local.get 0
                            i32.const 24
                            i32.add
                            i64.load
                            local.tee 12
                            i64.and
                            i64.and
                            i64.const -1
                            i64.eq
                            br_if 0 (;@12;)
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 7
                            global.set $__stack_pointer
                            local.get 2
                            local.get 0
                            call $u256_from_big_endian_bytes
                            block  ;; label = @13
                              local.get 13
                              local.get 0
                              i64.load
                              i64.lt_u
                              local.get 3
                              local.get 0
                              i32.const 8
                              i32.add
                              i64.load
                              local.tee 18
                              i64.lt_u
                              local.get 3
                              local.get 18
                              i64.eq
                              select
                              local.get 11
                              local.get 0
                              i32.const 16
                              i32.add
                              i64.load
                              local.tee 19
                              i64.lt_u
                              local.get 12
                              local.get 0
                              i32.const 24
                              i32.add
                              i64.load
                              local.tee 18
                              i64.lt_u
                              local.get 12
                              local.get 18
                              i64.eq
                              select
                              local.get 11
                              local.get 19
                              i64.xor
                              local.get 12
                              local.get 18
                              i64.xor
                              i64.or
                              i64.eqz
                              select
                              i32.eqz
                              br_if 0 (;@13;)
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 8
                              local.tee 0
                              global.set $__stack_pointer
                              i32.const 64
                              local.get 8
                              call $wrapper_mload_bytes32
                              local.get 8
                              call $i32_from_big_endian_bytes32
                              local.set 9
                              local.get 0
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 0
                              i32.const 24
                              i32.add
                              i64.const -319964815760031744
                              i64.store
                              local.get 0
                              i64.const 0
                              i64.store offset=16
                              local.get 0
                              i64.const 0
                              i64.store offset=8
                              local.get 0
                              i64.const 0
                              i64.store
                              local.get 9
                              local.get 0
                              call $wrapper_mstore_u256
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 8
                              local.get 0
                              call $u256_from_big_endian_bytes
                              local.get 0
                              i64.load
                              local.set 18
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 0
                              call $wrapper_caller
                              local.get 0
                              local.get 1
                              i32.const 64
                              i32.add
                              call $u256_from_big_endian_bytes
                              local.get 2
                              local.get 1
                              call $u256_from_big_endian_bytes
                              local.get 18
                              i32.wrap_i64
                              local.tee 0
                              i32.const 4
                              i32.add
                              local.get 1
                              i32.const 64
                              i32.add
                              call $wrapper_mstore_u256
                              local.get 1
                              i32.const 32
                              i32.add
                              i32.const 24
                              i32.add
                              local.get 12
                              i64.store
                              local.get 1
                              local.get 11
                              i64.store offset=48
                              local.get 1
                              local.get 3
                              i64.store offset=40
                              local.get 1
                              local.get 13
                              i64.store offset=32
                              local.get 0
                              i32.const 36
                              i32.add
                              local.get 1
                              i32.const 32
                              i32.add
                              call $wrapper_mstore_u256
                              local.get 0
                              i32.const 68
                              i32.add
                              local.get 1
                              call $wrapper_mstore_u256
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 8
                              local.get 0
                              call $u256_from_big_endian_bytes
                              local.get 9
                              local.get 18
                              local.get 0
                              i64.load
                              i64.sub
                              i32.wrap_i64
                              i32.const 100
                              i32.add
                              call $wrapper_revert
                            end
                            block  ;; label = @13
                              local.get 10
                              local.get 5
                              i64.or
                              local.get 4
                              local.get 6
                              i64.or
                              i64.or
                              i64.const 0
                              i64.ne
                              br_if 0 (;@13;)
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 8
                              local.tee 0
                              global.set $__stack_pointer
                              i32.const 64
                              local.get 8
                              call $wrapper_mload_bytes32
                              local.get 0
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 7
                              local.tee 9
                              global.set $__stack_pointer
                              local.get 7
                              i32.const 24
                              i32.add
                              i32.const 32992
                              i32.const 24
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 7
                              i32.const 16
                              i32.add
                              i32.const 32992
                              i32.const 16
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 7
                              i32.const 8
                              i32.add
                              i32.const 32992
                              i32.const 8
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 7
                              i32.const 0
                              i64.load offset=32992
                              i64.store align=1
                              local.get 7
                              local.get 0
                              call $u256_from_big_endian_bytes
                              local.get 0
                              i64.load
                              local.set 18
                              local.get 0
                              i32.const 8
                              i32.add
                              i64.load
                              local.set 19
                              local.get 0
                              i32.const 16
                              i32.add
                              i64.load
                              local.set 20
                              local.get 0
                              i32.const 24
                              i32.add
                              i64.load
                              local.set 21
                              local.get 9
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 0
                              i32.const 24
                              i32.add
                              local.get 21
                              i64.store
                              local.get 0
                              local.get 20
                              i64.store offset=16
                              local.get 0
                              local.get 19
                              i64.store offset=8
                              local.get 0
                              local.get 18
                              i64.store
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 7
                              local.tee 22
                              global.set $__stack_pointer
                              local.get 0
                              i32.const 224
                              local.get 7
                              call $wrapper_u256_shl
                              local.get 7
                              i64.load
                              local.set 18
                              local.get 7
                              i32.const 8
                              i32.add
                              i64.load
                              local.set 19
                              local.get 7
                              i32.const 16
                              i32.add
                              i64.load
                              local.set 20
                              local.get 7
                              i32.const 24
                              i32.add
                              i64.load
                              local.set 21
                              local.get 8
                              call $i32_from_big_endian_bytes32
                              local.set 9
                              local.get 22
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 0
                              i32.const 24
                              i32.add
                              local.get 21
                              i64.store
                              local.get 0
                              local.get 20
                              i64.store offset=16
                              local.get 0
                              local.get 19
                              i64.store offset=8
                              local.get 0
                              local.get 18
                              i64.store
                              local.get 9
                              local.get 0
                              call $wrapper_mstore_u256
                              local.get 7
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 7
                              global.set $__stack_pointer
                              local.get 8
                              local.get 0
                              call $u256_from_big_endian_bytes
                              local.get 0
                              i32.load
                              i32.const 4
                              i32.add
                              i32.const 0
                              call $wrapper_mstore_u32
                              local.get 9
                              i32.const 36
                              call $wrapper_revert
                            end
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 7
                            local.tee 0
                            global.set $__stack_pointer
                            local.get 7
                            call $wrapper_caller
                            block  ;; label = @13
                              local.get 7
                              call $wrapper_bytes32_iszero
                              i32.eqz
                              br_if 0 (;@13;)
                              local.get 0
                              i32.const -32
                              i32.add
                              local.tee 7
                              local.tee 0
                              global.set $__stack_pointer
                              i32.const 64
                              local.get 7
                              call $wrapper_mload_bytes32
                              local.get 7
                              call $i32_from_big_endian_bytes32
                              local.set 8
                              local.get 0
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 9
                              global.set $__stack_pointer
                              local.get 0
                              i32.const 24
                              i32.add
                              i64.const -7770946442469834752
                              i64.store
                              local.get 0
                              i64.const 0
                              i64.store offset=16
                              local.get 0
                              i64.const 0
                              i64.store offset=8
                              local.get 0
                              i64.const 0
                              i64.store
                              local.get 8
                              local.get 0
                              call $wrapper_mstore_u256
                              local.get 9
                              i32.const -32
                              i32.add
                              local.tee 9
                              local.tee 0
                              global.set $__stack_pointer
                              local.get 7
                              local.get 9
                              call $u256_from_big_endian_bytes
                              local.get 9
                              i32.load
                              i32.const 4
                              i32.add
                              i32.const 0
                              call $wrapper_mstore_u32
                              local.get 8
                              i32.const 36
                              call $wrapper_revert
                            end
                            local.get 0
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 7
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
                            local.get 10
                            i64.store
                            i32.const 0
                            local.get 0
                            call $wrapper_mstore_u256
                            i32.const 32
                            i32.const 1
                            call $wrapper_mstore_u32
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 7
                            global.set $__stack_pointer
                            i32.const 0
                            i32.const 64
                            local.get 0
                            call $wrapper_keccak256
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 7
                            local.tee 8
                            global.set $__stack_pointer
                            local.get 7
                            call $wrapper_caller
                            i32.const 0
                            local.get 7
                            call $wrapper_mstore_bytes32
                            i32.const 32
                            local.get 0
                            call $wrapper_mstore_bytes32
                            local.get 8
                            i32.const -32
                            i32.add
                            local.tee 8
                            local.tee 0
                            global.set $__stack_pointer
                            i32.const 0
                            i32.const 64
                            local.get 8
                            call $wrapper_keccak256
                            local.get 0
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 7
                            global.set $__stack_pointer
                            local.get 2
                            local.get 0
                            call $u256_from_big_endian_bytes
                            local.get 0
                            i32.const 8
                            i32.add
                            i64.load
                            local.set 18
                            local.get 0
                            i64.load
                            local.set 19
                            local.get 0
                            i32.const 16
                            i32.add
                            i64.load
                            local.set 20
                            local.get 0
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 21
                            local.get 7
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 7
                            global.set $__stack_pointer
                            local.get 0
                            local.get 11
                            local.get 20
                            i64.sub
                            local.tee 23
                            local.get 13
                            local.get 19
                            i64.lt_u
                            local.tee 9
                            local.get 3
                            local.get 18
                            i64.lt_u
                            local.get 3
                            local.get 18
                            i64.eq
                            select
                            i64.extend_i32_u
                            local.tee 24
                            i64.sub
                            i64.store offset=16
                            local.get 0
                            local.get 3
                            local.get 18
                            i64.sub
                            local.get 9
                            i64.extend_i32_u
                            i64.sub
                            i64.store offset=8
                            local.get 0
                            local.get 13
                            local.get 19
                            i64.sub
                            i64.store
                            local.get 0
                            i32.const 24
                            i32.add
                            local.get 12
                            local.get 21
                            i64.sub
                            local.get 11
                            local.get 20
                            i64.lt_u
                            i64.extend_i32_u
                            i64.sub
                            local.get 23
                            local.get 24
                            i64.lt_u
                            i64.extend_i32_u
                            i64.sub
                            i64.store
                            local.get 8
                            local.get 0
                            call $wrapper_sstore_u256_using_little_endian_hostapi
                          end
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 7
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
                          local.get 10
                          i64.store
                          local.get 7
                          i32.const -32
                          i32.add
                          local.tee 7
                          local.tee 8
                          global.set $__stack_pointer
                          local.get 0
                          local.get 7
                          call $u256_to_big_endian_bytes
                          local.get 8
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 8
                          global.set $__stack_pointer
                          local.get 0
                          i32.const 24
                          i32.add
                          local.get 14
                          i64.store
                          local.get 0
                          local.get 15
                          i64.store offset=16
                          local.get 0
                          local.get 16
                          i64.store offset=8
                          local.get 0
                          local.get 17
                          i64.store
                          local.get 8
                          i32.const -32
                          i32.add
                          local.tee 8
                          local.tee 9
                          global.set $__stack_pointer
                          local.get 0
                          local.get 8
                          call $u256_to_big_endian_bytes
                          local.get 7
                          local.get 8
                          local.get 2
                          call $wrapper_optimized_erc20_fun_transfer
                          local.get 9
                          i32.const -32
                          i32.add
                          local.tee 0
                          global.set $__stack_pointer
                          i32.const 64
                          local.get 0
                          call $wrapper_mload_bytes32
                          local.get 0
                          call $i32_from_big_endian_bytes32
                          local.tee 0
                          i32.const 1
                          call $wrapper_mstore_u32
                          local.get 0
                          i32.const 32
                          call $wrapper_return
                          br 10 (;@1;)
                        end
                        local.get 2
                        i32.const 826074471
                        i32.eq
                        br_if 2 (;@8;)
                        local.get 2
                        i32.const 1086394137
                        i32.eq
                        br_if 3 (;@7;)
                        local.get 2
                        i32.const 1889567281
                        i32.eq
                        br_if 4 (;@6;)
                        br 9 (;@1;)
                      end
                      block  ;; label = @10
                        call $wrapper_callvalue_not_zero
                        i32.eqz
                        br_if 0 (;@10;)
                        i32.const 0
                        i32.const 0
                        call $wrapper_revert
                      end
                      call $wrapper_calldata_size_minus_4
                      drop
                      local.get 0
                      i32.const -32
                      i32.add
                      local.tee 0
                      local.tee 2
                      global.set $__stack_pointer
                      local.get 0
                      i32.const 24
                      i32.add
                      i64.const 0
                      i64.store
                      local.get 0
                      i64.const 0
                      i64.store offset=16
                      local.get 0
                      i64.const 0
                      i64.store offset=8
                      local.get 0
                      i64.const 3
                      i64.store
                      local.get 2
                      i32.const -32
                      i32.add
                      local.tee 2
                      local.tee 7
                      global.set $__stack_pointer
                      local.get 0
                      local.get 2
                      call $u256_to_big_endian_bytes
                      local.get 7
                      i32.const -32
                      i32.add
                      local.tee 0
                      local.tee 7
                      global.set $__stack_pointer
                      local.get 2
                      local.get 0
                      call $wrapper_sload_u256_using_little_endian_hostapi
                      local.get 0
                      i64.load
                      local.set 3
                      local.get 0
                      i32.const 8
                      i32.add
                      i64.load
                      local.set 6
                      local.get 0
                      i32.const 16
                      i32.add
                      i64.load
                      local.set 10
                      local.get 0
                      i32.const 24
                      i32.add
                      i64.load
                      local.set 11
                      local.get 7
                      i32.const -32
                      i32.add
                      local.tee 0
                      local.tee 2
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
                      local.get 6
                      i64.store offset=8
                      local.get 0
                      local.get 3
                      i64.store
                      local.get 2
                      i32.const -32
                      i32.add
                      local.tee 2
                      local.tee 7
                      global.set $__stack_pointer
                      local.get 0
                      i32.const 1
                      local.get 2
                      call $wrapper_u256_shr
                      block  ;; label = @10
                        local.get 3
                        i32.wrap_i64
                        i32.const 1
                        i32.and
                        local.get 2
                        i64.load
                        local.tee 5
                        i64.const 127
                        i64.and
                        local.get 5
                        local.get 3
                        i64.const 1
                        i64.and
                        local.tee 4
                        i64.eqz
                        select
                        local.tee 21
                        i64.const 31
                        i64.gt_u
                        i64.const 0
                        local.get 4
                        i64.sub
                        local.tee 5
                        local.get 2
                        i32.const 8
                        i32.add
                        i64.load
                        i64.and
                        local.tee 15
                        i64.const 0
                        i64.ne
                        local.get 15
                        i64.eqz
                        select
                        local.get 5
                        local.get 2
                        i32.const 16
                        i32.add
                        i64.load
                        i64.and
                        local.tee 16
                        i64.const 0
                        i64.ne
                        local.get 5
                        local.get 2
                        i32.const 24
                        i32.add
                        i64.load
                        i64.and
                        local.tee 13
                        i64.const 0
                        i64.ne
                        local.get 13
                        i64.eqz
                        select
                        local.get 16
                        local.get 13
                        i64.or
                        i64.eqz
                        select
                        i32.eq
                        br_if 0 (;@10;)
                        local.get 7
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 7
                        global.set $__stack_pointer
                        local.get 0
                        i32.const 24
                        i32.add
                        i64.const 5640894258543067136
                        i64.store
                        local.get 0
                        i64.const 0
                        i64.store offset=16
                        local.get 0
                        i64.const 0
                        i64.store offset=8
                        local.get 0
                        i64.const 0
                        i64.store
                        i32.const 0
                        local.get 0
                        call $wrapper_mstore_u256
                        i32.const 4
                        i32.const 34
                        call $wrapper_mstore_u32
                        i32.const 0
                        i32.const 36
                        call $wrapper_revert
                      end
                      local.get 7
                      i32.const -32
                      i32.add
                      local.tee 0
                      local.tee 7
                      global.set $__stack_pointer
                      local.get 0
                      i32.const 24
                      i32.add
                      local.get 13
                      i64.store
                      local.get 0
                      local.get 16
                      i64.store offset=16
                      local.get 0
                      local.get 15
                      i64.store offset=8
                      local.get 0
                      local.get 21
                      i64.store
                      i32.const 96
                      local.get 0
                      call $wrapper_mstore_u256
                      block  ;; label = @10
                        local.get 4
                        i64.const 0
                        i64.ne
                        br_if 0 (;@10;)
                        local.get 7
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 2
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
                        local.get 6
                        i64.store offset=8
                        local.get 0
                        local.get 3
                        i64.const -256
                        i64.and
                        i64.store
                        i32.const 128
                        local.get 0
                        call $wrapper_mstore_u256
                        local.get 2
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 2
                        global.set $__stack_pointer
                        local.get 0
                        i32.const 24
                        i32.add
                        i64.const 0
                        i64.store
                        local.get 0
                        i64.const 0
                        i64.store offset=16
                        local.get 0
                        i64.const 0
                        i64.store offset=8
                        local.get 0
                        local.get 21
                        local.get 16
                        i64.or
                        local.get 15
                        local.get 13
                        i64.or
                        i64.or
                        i64.const 0
                        i64.ne
                        i64.extend_i32_u
                        i64.store
                        local.get 2
                        i32.const -32
                        i32.add
                        local.tee 2
                        local.tee 7
                        global.set $__stack_pointer
                        local.get 0
                        i32.const 5
                        local.get 2
                        call $wrapper_u256_shl
                        local.get 2
                        i32.const 24
                        i32.add
                        i64.load
                        local.get 2
                        i32.const 16
                        i32.add
                        i64.load
                        local.tee 6
                        local.get 2
                        i64.load
                        local.tee 5
                        i64.const 128
                        i64.add
                        local.tee 4
                        local.get 5
                        i64.lt_u
                        local.tee 0
                        local.get 2
                        i32.const 8
                        i32.add
                        i64.load
                        local.tee 10
                        local.get 0
                        i64.extend_i32_u
                        i64.add
                        local.tee 3
                        local.get 10
                        i64.lt_u
                        local.get 4
                        local.get 5
                        i64.ge_u
                        select
                        i64.extend_i32_u
                        i64.add
                        local.tee 5
                        local.get 6
                        i64.lt_u
                        i64.extend_i32_u
                        i64.add
                        local.set 6
                        br 8 (;@2;)
                      end
                      i32.const 0
                      i32.const 3
                      call $wrapper_mstore_u32
                      block  ;; label = @10
                        local.get 21
                        local.get 16
                        i64.or
                        local.get 15
                        local.get 13
                        i64.or
                        i64.or
                        i64.eqz
                        i32.eqz
                        br_if 0 (;@10;)
                        i64.const 0
                        local.set 3
                        i64.const 128
                        local.set 4
                        i64.const 0
                        local.set 5
                        i64.const 0
                        local.set 6
                        br 8 (;@2;)
                      end
                      i64.const -4442983488545014784
                      local.set 14
                      i64.const -479078342376367320
                      local.set 4
                      i64.const 7620998054141035216
                      local.set 5
                      i64.const 6783852896886847579
                      local.set 3
                      i64.const 0
                      local.set 6
                      i32.const 128
                      local.set 2
                      i64.const 0
                      local.set 10
                      i64.const 0
                      local.set 11
                      i64.const 0
                      local.set 12
                      loop  ;; label = @10
                        local.get 7
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 7
                        global.set $__stack_pointer
                        local.get 0
                        i32.const 24
                        i32.add
                        local.get 14
                        i64.store
                        local.get 0
                        local.get 4
                        i64.store offset=16
                        local.get 0
                        local.get 5
                        i64.store offset=8
                        local.get 0
                        local.get 3
                        i64.store
                        local.get 7
                        i32.const -32
                        i32.add
                        local.tee 7
                        local.tee 8
                        global.set $__stack_pointer
                        local.get 0
                        local.get 7
                        call $u256_to_big_endian_bytes
                        local.get 8
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 8
                        global.set $__stack_pointer
                        local.get 7
                        local.get 0
                        call $wrapper_sload_u256_using_little_endian_hostapi
                        local.get 0
                        i64.load
                        local.set 18
                        local.get 0
                        i32.const 8
                        i32.add
                        i64.load
                        local.set 17
                        local.get 0
                        i32.const 16
                        i32.add
                        i64.load
                        local.set 19
                        local.get 0
                        i32.const 24
                        i32.add
                        i64.load
                        local.set 20
                        local.get 8
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 7
                        global.set $__stack_pointer
                        local.get 0
                        i32.const 24
                        i32.add
                        local.get 20
                        i64.store
                        local.get 0
                        local.get 19
                        i64.store offset=16
                        local.get 0
                        local.get 17
                        i64.store offset=8
                        local.get 0
                        local.get 18
                        i64.store
                        local.get 2
                        local.get 0
                        call $wrapper_mstore_u256
                        local.get 14
                        local.get 4
                        local.get 3
                        i64.const 1
                        i64.add
                        local.tee 18
                        local.get 3
                        i64.lt_u
                        local.tee 0
                        local.get 5
                        local.get 0
                        i64.extend_i32_u
                        i64.add
                        local.tee 17
                        local.get 5
                        i64.lt_u
                        local.get 18
                        local.get 3
                        i64.ge_u
                        select
                        i64.extend_i32_u
                        i64.add
                        local.tee 19
                        local.get 4
                        i64.lt_u
                        i64.extend_i32_u
                        i64.add
                        local.set 14
                        local.get 2
                        i32.const 32
                        i32.add
                        local.set 2
                        local.get 18
                        local.set 3
                        local.get 17
                        local.set 5
                        local.get 19
                        local.set 4
                        local.get 6
                        local.tee 18
                        i64.const 32
                        i64.add
                        local.tee 6
                        local.get 21
                        i64.lt_u
                        local.get 10
                        local.tee 17
                        local.get 6
                        local.get 18
                        i64.lt_u
                        local.tee 0
                        i64.extend_i32_u
                        i64.add
                        local.tee 10
                        local.get 15
                        i64.lt_u
                        local.get 10
                        local.get 15
                        i64.eq
                        select
                        local.get 11
                        local.tee 19
                        local.get 0
                        local.get 10
                        local.get 17
                        i64.lt_u
                        local.get 6
                        local.get 18
                        i64.ge_u
                        select
                        i64.extend_i32_u
                        i64.add
                        local.tee 11
                        local.get 16
                        i64.lt_u
                        local.get 12
                        local.tee 20
                        local.get 11
                        local.get 19
                        i64.lt_u
                        i64.extend_i32_u
                        i64.add
                        local.tee 12
                        local.get 13
                        i64.lt_u
                        local.get 12
                        local.get 13
                        i64.eq
                        select
                        local.get 11
                        local.get 16
                        i64.xor
                        local.get 12
                        local.get 13
                        i64.xor
                        i64.or
                        i64.eqz
                        select
                        br_if 0 (;@10;)
                      end
                      local.get 20
                      local.get 19
                      local.get 18
                      i64.const 160
                      i64.add
                      local.tee 4
                      local.get 18
                      i64.lt_u
                      local.tee 0
                      local.get 17
                      local.get 0
                      i64.extend_i32_u
                      i64.add
                      local.tee 3
                      local.get 17
                      i64.lt_u
                      local.get 4
                      local.get 18
                      i64.ge_u
                      select
                      i64.extend_i32_u
                      i64.add
                      local.tee 5
                      local.get 19
                      i64.lt_u
                      i64.extend_i32_u
                      i64.add
                      local.set 6
                      br 7 (;@2;)
                    end
                    block  ;; label = @9
                      call $wrapper_callvalue_not_zero
                      i32.eqz
                      br_if 0 (;@9;)
                      i32.const 0
                      i32.const 0
                      call $wrapper_revert
                    end
                    call $wrapper_calldata_size_minus_4
                    drop
                    local.get 0
                    i32.const -32
                    i32.add
                    local.tee 0
                    local.tee 2
                    global.set $__stack_pointer
                    local.get 0
                    i32.const 24
                    i32.add
                    i64.const 0
                    i64.store
                    local.get 0
                    i64.const 0
                    i64.store offset=16
                    local.get 0
                    i64.const 0
                    i64.store offset=8
                    local.get 0
                    i64.const 2
                    i64.store
                    local.get 2
                    i32.const -32
                    i32.add
                    local.tee 2
                    local.tee 7
                    global.set $__stack_pointer
                    local.get 0
                    local.get 2
                    call $u256_to_big_endian_bytes
                    local.get 7
                    i32.const -32
                    i32.add
                    local.tee 0
                    local.tee 7
                    global.set $__stack_pointer
                    local.get 2
                    local.get 0
                    call $wrapper_sload_u256_using_little_endian_hostapi
                    local.get 0
                    i64.load
                    local.set 3
                    local.get 0
                    i32.const 8
                    i32.add
                    i64.load
                    local.set 4
                    local.get 0
                    i32.const 16
                    i32.add
                    i64.load
                    local.set 5
                    local.get 0
                    i32.const 24
                    i32.add
                    i64.load
                    local.set 6
                    local.get 7
                    i32.const -32
                    i32.add
                    local.tee 0
                    local.tee 7
                    global.set $__stack_pointer
                    i32.const 64
                    local.get 0
                    call $wrapper_mload_bytes32
                    local.get 0
                    call $i32_from_big_endian_bytes32
                    local.set 2
                    local.get 7
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
                    local.get 3
                    i64.store
                    local.get 2
                    local.get 0
                    call $wrapper_mstore_u256
                    local.get 2
                    i32.const 32
                    call $wrapper_return
                    br 7 (;@1;)
                  end
                  block  ;; label = @8
                    call $wrapper_callvalue_not_zero
                    i32.eqz
                    br_if 0 (;@8;)
                    i32.const 0
                    i32.const 0
                    call $wrapper_revert
                  end
                  call $wrapper_calldata_size_minus_4
                  drop
                  local.get 0
                  i32.const -32
                  i32.add
                  local.tee 0
                  global.set $__stack_pointer
                  i32.const 64
                  local.get 0
                  call $wrapper_mload_bytes32
                  local.get 0
                  call $i32_from_big_endian_bytes32
                  local.tee 0
                  i32.const 18
                  call $wrapper_mstore_u32
                  local.get 0
                  i32.const 32
                  call $wrapper_return
                  br 6 (;@1;)
                end
                block  ;; label = @7
                  call $wrapper_callvalue_not_zero
                  i32.eqz
                  br_if 0 (;@7;)
                  i32.const 0
                  i32.const 0
                  call $wrapper_revert
                end
                block  ;; label = @7
                  call $wrapper_calldata_size_minus_4
                  i32.const 63
                  i32.gt_u
                  br_if 0 (;@7;)
                  i32.const 0
                  i32.const 0
                  call $wrapper_revert
                end
                i32.const 4
                local.get 1
                call $wrapper_calldataload_bytes32
                local.get 1
                local.get 1
                i32.const 64
                i32.add
                call $u256_from_big_endian_bytes
                local.get 1
                i32.const 64
                i32.add
                i32.const 16
                i32.add
                i64.load
                local.set 5
                local.get 1
                i32.const 64
                i32.add
                i32.const 24
                i32.add
                i64.load
                local.set 6
                local.get 1
                i32.const 64
                i32.add
                i32.const 8
                i32.add
                i64.load
                local.set 10
                local.get 1
                i64.load offset=64
                local.set 11
                local.get 0
                i32.const -32
                i32.add
                local.tee 2
                local.tee 0
                global.set $__stack_pointer
                i32.const 36
                local.get 2
                call $wrapper_calldataload_bytes32
                block  ;; label = @7
                  local.get 11
                  local.get 5
                  i64.or
                  local.get 10
                  local.get 6
                  i64.or
                  i64.or
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                  local.get 0
                  i32.const -32
                  i32.add
                  local.tee 8
                  local.tee 0
                  global.set $__stack_pointer
                  i32.const 64
                  local.get 8
                  call $wrapper_mload_bytes32
                  local.get 0
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 7
                  global.set $__stack_pointer
                  local.get 7
                  i32.const -32
                  i32.add
                  local.tee 7
                  local.tee 9
                  global.set $__stack_pointer
                  local.get 7
                  i32.const 24
                  i32.add
                  i32.const 33024
                  i32.const 24
                  i32.add
                  i64.load
                  i64.store align=1
                  local.get 7
                  i32.const 16
                  i32.add
                  i32.const 33024
                  i32.const 16
                  i32.add
                  i64.load
                  i64.store align=1
                  local.get 7
                  i32.const 8
                  i32.add
                  i32.const 33024
                  i32.const 8
                  i32.add
                  i64.load
                  i64.store align=1
                  local.get 7
                  i32.const 0
                  i64.load offset=33024
                  i64.store align=1
                  local.get 7
                  local.get 0
                  call $u256_from_big_endian_bytes
                  local.get 0
                  i64.load
                  local.set 3
                  local.get 0
                  i32.const 8
                  i32.add
                  i64.load
                  local.set 4
                  local.get 0
                  i32.const 16
                  i32.add
                  i64.load
                  local.set 12
                  local.get 0
                  i32.const 24
                  i32.add
                  i64.load
                  local.set 13
                  local.get 9
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 7
                  global.set $__stack_pointer
                  local.get 0
                  i32.const 24
                  i32.add
                  local.get 13
                  i64.store
                  local.get 0
                  local.get 12
                  i64.store offset=16
                  local.get 0
                  local.get 4
                  i64.store offset=8
                  local.get 0
                  local.get 3
                  i64.store
                  local.get 7
                  i32.const -32
                  i32.add
                  local.tee 7
                  local.tee 9
                  global.set $__stack_pointer
                  local.get 0
                  i32.const 224
                  local.get 7
                  call $wrapper_u256_shl
                  local.get 7
                  i64.load
                  local.set 3
                  local.get 7
                  i32.const 8
                  i32.add
                  i64.load
                  local.set 4
                  local.get 7
                  i32.const 16
                  i32.add
                  i64.load
                  local.set 12
                  local.get 7
                  i32.const 24
                  i32.add
                  i64.load
                  local.set 13
                  local.get 8
                  call $i32_from_big_endian_bytes32
                  local.set 7
                  local.get 9
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 9
                  global.set $__stack_pointer
                  local.get 0
                  i32.const 24
                  i32.add
                  local.get 13
                  i64.store
                  local.get 0
                  local.get 12
                  i64.store offset=16
                  local.get 0
                  local.get 4
                  i64.store offset=8
                  local.get 0
                  local.get 3
                  i64.store
                  local.get 7
                  local.get 0
                  call $wrapper_mstore_u256
                  local.get 9
                  i32.const -32
                  i32.add
                  local.tee 9
                  local.tee 0
                  global.set $__stack_pointer
                  local.get 8
                  local.get 9
                  call $u256_from_big_endian_bytes
                  local.get 9
                  i32.load
                  i32.const 4
                  i32.add
                  i32.const 0
                  call $wrapper_mstore_u32
                  local.get 7
                  i32.const 36
                  call $wrapper_revert
                end
                local.get 0
                i32.const -32
                i32.add
                local.tee 0
                local.tee 7
                global.set $__stack_pointer
                local.get 0
                i32.const 24
                i32.add
                i64.const 0
                i64.store
                local.get 0
                i64.const 0
                i64.store offset=16
                local.get 0
                i64.const 0
                i64.store offset=8
                local.get 0
                i64.const 2
                i64.store
                local.get 7
                i32.const -32
                i32.add
                local.tee 7
                local.tee 8
                global.set $__stack_pointer
                local.get 0
                local.get 7
                call $u256_to_big_endian_bytes
                local.get 8
                i32.const -32
                i32.add
                local.tee 0
                local.tee 8
                global.set $__stack_pointer
                local.get 7
                local.get 0
                call $wrapper_sload_u256_using_little_endian_hostapi
                local.get 0
                i32.const 24
                i32.add
                i64.load
                local.set 3
                local.get 0
                i32.const 16
                i32.add
                i64.load
                local.set 12
                local.get 0
                i64.load
                local.set 4
                local.get 0
                i32.const 8
                i32.add
                i64.load
                local.set 13
                local.get 8
                i32.const -32
                i32.add
                local.tee 0
                local.tee 7
                global.set $__stack_pointer
                local.get 2
                local.get 0
                call $u256_from_big_endian_bytes
                block  ;; label = @7
                  local.get 4
                  local.get 4
                  local.get 0
                  i64.load
                  local.tee 15
                  i64.add
                  local.tee 14
                  i64.le_u
                  local.get 13
                  local.get 13
                  local.get 0
                  i32.const 8
                  i32.add
                  i64.load
                  local.tee 18
                  i64.add
                  local.get 14
                  local.get 15
                  i64.lt_u
                  local.tee 8
                  i64.extend_i32_u
                  i64.add
                  local.tee 4
                  i64.le_u
                  local.get 13
                  local.get 4
                  i64.eq
                  select
                  local.get 12
                  local.get 12
                  local.get 0
                  i32.const 16
                  i32.add
                  i64.load
                  local.tee 16
                  i64.add
                  local.tee 15
                  local.get 8
                  local.get 4
                  local.get 18
                  i64.lt_u
                  local.get 4
                  local.get 18
                  i64.eq
                  select
                  i64.extend_i32_u
                  i64.add
                  local.tee 13
                  i64.le_u
                  local.get 3
                  local.get 3
                  local.get 0
                  i32.const 24
                  i32.add
                  i64.load
                  i64.add
                  local.get 15
                  local.get 16
                  i64.lt_u
                  i64.extend_i32_u
                  i64.add
                  local.get 13
                  local.get 15
                  i64.lt_u
                  i64.extend_i32_u
                  i64.add
                  local.tee 18
                  i64.le_u
                  local.get 3
                  local.get 18
                  i64.eq
                  select
                  local.get 12
                  local.get 13
                  i64.xor
                  local.get 3
                  local.get 18
                  i64.xor
                  i64.or
                  i64.eqz
                  select
                  br_if 0 (;@7;)
                  local.get 7
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 7
                  global.set $__stack_pointer
                  local.get 0
                  i32.const 24
                  i32.add
                  i64.const 5640894258543067136
                  i64.store
                  local.get 0
                  i64.const 0
                  i64.store offset=16
                  local.get 0
                  i64.const 0
                  i64.store offset=8
                  local.get 0
                  i64.const 0
                  i64.store
                  i32.const 0
                  local.get 0
                  call $wrapper_mstore_u256
                  i32.const 4
                  i32.const 17
                  call $wrapper_mstore_u32
                  i32.const 0
                  i32.const 36
                  call $wrapper_revert
                end
                local.get 7
                i32.const -32
                i32.add
                local.tee 0
                local.tee 7
                global.set $__stack_pointer
                local.get 0
                i32.const 24
                i32.add
                i64.const 0
                i64.store
                local.get 0
                i64.const 0
                i64.store offset=16
                local.get 0
                i64.const 0
                i64.store offset=8
                local.get 0
                i64.const 2
                i64.store
                local.get 7
                i32.const -32
                i32.add
                local.tee 7
                local.tee 8
                global.set $__stack_pointer
                local.get 0
                local.get 7
                call $u256_to_big_endian_bytes
                local.get 8
                i32.const -32
                i32.add
                local.tee 0
                local.tee 8
                global.set $__stack_pointer
                local.get 0
                i32.const 24
                i32.add
                local.get 18
                i64.store
                local.get 0
                local.get 13
                i64.store offset=16
                local.get 0
                local.get 4
                i64.store offset=8
                local.get 0
                local.get 14
                i64.store
                local.get 7
                local.get 0
                call $wrapper_sstore_u256_using_little_endian_hostapi
                local.get 8
                i32.const -32
                i32.add
                local.tee 0
                local.tee 7
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
                local.get 10
                i64.store offset=8
                local.get 0
                local.get 11
                i64.store
                i32.const 0
                local.get 0
                call $wrapper_mstore_u256
                i32.const 32
                i32.const 0
                call $wrapper_mstore_u32
                local.get 7
                i32.const -32
                i32.add
                local.tee 7
                local.tee 0
                global.set $__stack_pointer
                i32.const 0
                i32.const 64
                local.get 7
                call $wrapper_keccak256
                local.get 0
                i32.const -32
                i32.add
                local.tee 0
                local.tee 8
                global.set $__stack_pointer
                local.get 7
                local.get 0
                call $wrapper_sload_u256_using_little_endian_hostapi
                local.get 0
                i32.const 24
                i32.add
                i64.load
                local.set 18
                local.get 0
                i32.const 16
                i32.add
                i64.load
                local.set 13
                local.get 0
                i64.load
                local.set 14
                local.get 0
                i32.const 8
                i32.add
                i64.load
                local.set 15
                local.get 8
                i32.const -32
                i32.add
                local.tee 0
                local.tee 8
                global.set $__stack_pointer
                local.get 2
                local.get 0
                call $u256_from_big_endian_bytes
                local.get 0
                i32.const 8
                i32.add
                i64.load
                local.set 3
                local.get 0
                i64.load
                local.set 4
                local.get 0
                i32.const 24
                i32.add
                i64.load
                local.set 16
                local.get 0
                i32.const 16
                i32.add
                i64.load
                local.set 12
                local.get 8
                i32.const -32
                i32.add
                local.tee 0
                local.tee 8
                global.set $__stack_pointer
                local.get 0
                local.get 3
                local.get 15
                i64.add
                local.get 4
                local.get 14
                i64.add
                local.tee 14
                local.get 4
                i64.lt_u
                local.tee 9
                i64.extend_i32_u
                i64.add
                local.tee 4
                i64.store offset=8
                local.get 0
                local.get 14
                i64.store
                local.get 0
                local.get 12
                local.get 13
                i64.add
                local.tee 13
                local.get 9
                local.get 4
                local.get 3
                i64.lt_u
                local.get 4
                local.get 3
                i64.eq
                select
                i64.extend_i32_u
                i64.add
                local.tee 3
                i64.store offset=16
                local.get 0
                i32.const 24
                i32.add
                local.get 16
                local.get 18
                i64.add
                local.get 13
                local.get 12
                i64.lt_u
                i64.extend_i32_u
                i64.add
                local.get 3
                local.get 13
                i64.lt_u
                i64.extend_i32_u
                i64.add
                i64.store
                local.get 7
                local.get 0
                call $wrapper_sstore_u256_using_little_endian_hostapi
                local.get 8
                i32.const -32
                i32.add
                local.tee 0
                local.tee 7
                global.set $__stack_pointer
                i32.const 64
                local.get 0
                call $wrapper_mload_bytes32
                local.get 0
                call $i32_from_big_endian_bytes32
                local.tee 8
                local.get 2
                call $wrapper_mstore_bytes32
                local.get 7
                i32.const -32
                i32.add
                local.tee 0
                local.tee 2
                global.set $__stack_pointer
                local.get 0
                i32.const 24
                i32.add
                i64.const 0
                i64.store
                local.get 0
                i64.const 0
                i64.store offset=16
                local.get 0
                i64.const 0
                i64.store offset=8
                local.get 0
                i64.const 0
                i64.store
                local.get 2
                i32.const -32
                i32.add
                local.tee 2
                local.tee 7
                global.set $__stack_pointer
                local.get 0
                local.get 2
                call $u256_to_big_endian_bytes
                local.get 7
                i32.const -32
                i32.add
                local.tee 0
                local.tee 7
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
                local.get 10
                i64.store offset=8
                local.get 0
                local.get 11
                i64.store
                local.get 7
                i32.const -32
                i32.add
                local.tee 7
                global.set $__stack_pointer
                local.get 0
                local.get 7
                call $u256_to_big_endian_bytes
                local.get 8
                i32.const 32
                i32.const 33056
                local.get 2
                local.get 7
                call $wrapper_log3
                i32.const 0
                i32.const 0
                call $wrapper_return
                br 5 (;@1;)
              end
              block  ;; label = @6
                call $wrapper_callvalue_not_zero
                i32.eqz
                br_if 0 (;@6;)
                i32.const 0
                i32.const 0
                call $wrapper_revert
              end
              block  ;; label = @6
                call $wrapper_calldata_size_minus_4
                i32.const 31
                i32.gt_u
                br_if 0 (;@6;)
                i32.const 0
                i32.const 0
                call $wrapper_revert
              end
              i32.const 4
              local.get 1
              call $wrapper_calldataload_bytes32
              local.get 1
              local.get 1
              i32.const 64
              i32.add
              call $u256_from_big_endian_bytes
              local.get 1
              i32.const 64
              i32.add
              i32.const 8
              i32.add
              i64.load
              local.set 3
              local.get 1
              i32.const 64
              i32.add
              i32.const 16
              i32.add
              i64.load32_u
              local.set 4
              local.get 1
              i64.load offset=64
              local.set 5
              local.get 0
              i32.const -32
              i32.add
              local.tee 0
              local.tee 2
              global.set $__stack_pointer
              local.get 0
              i32.const 24
              i32.add
              i64.const 0
              i64.store
              local.get 0
              local.get 4
              i64.store offset=16
              local.get 0
              local.get 3
              i64.store offset=8
              local.get 0
              local.get 5
              i64.store
              i32.const 0
              local.get 0
              call $wrapper_mstore_u256
              i32.const 32
              i32.const 0
              call $wrapper_mstore_u32
              local.get 2
              i32.const -32
              i32.add
              local.tee 2
              local.tee 0
              global.set $__stack_pointer
              i32.const 0
              i32.const 64
              local.get 2
              call $wrapper_keccak256
              local.get 0
              i32.const -32
              i32.add
              local.tee 0
              local.tee 7
              global.set $__stack_pointer
              local.get 2
              local.get 0
              call $wrapper_sload_u256_using_little_endian_hostapi
              local.get 0
              i64.load
              local.set 3
              local.get 0
              i32.const 8
              i32.add
              i64.load
              local.set 4
              local.get 0
              i32.const 16
              i32.add
              i64.load
              local.set 5
              local.get 0
              i32.const 24
              i32.add
              i64.load
              local.set 6
              local.get 7
              i32.const -32
              i32.add
              local.tee 0
              local.tee 7
              global.set $__stack_pointer
              i32.const 64
              local.get 0
              call $wrapper_mload_bytes32
              local.get 0
              call $i32_from_big_endian_bytes32
              local.set 2
              local.get 7
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
              local.get 3
              i64.store
              local.get 2
              local.get 0
              call $wrapper_mstore_u256
              local.get 2
              i32.const 32
              call $wrapper_return
              br 4 (;@1;)
            end
            block  ;; label = @5
              call $wrapper_callvalue_not_zero
              i32.eqz
              br_if 0 (;@5;)
              i32.const 0
              i32.const 0
              call $wrapper_revert
            end
            call $wrapper_calldata_size_minus_4
            drop
            local.get 0
            i32.const -32
            i32.add
            local.tee 8
            local.tee 0
            global.set $__stack_pointer
            i32.const 64
            local.get 8
            call $wrapper_mload_bytes32
            local.get 0
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            i64.const 0
            i64.store
            local.get 0
            i64.const 0
            i64.store offset=16
            local.get 0
            i64.const 0
            i64.store offset=8
            local.get 0
            i64.const 4
            i64.store
            local.get 2
            i32.const -32
            i32.add
            local.tee 2
            local.tee 7
            global.set $__stack_pointer
            local.get 0
            local.get 2
            call $u256_to_big_endian_bytes
            local.get 7
            i32.const -32
            i32.add
            local.tee 0
            local.tee 7
            global.set $__stack_pointer
            local.get 2
            local.get 0
            call $wrapper_sload_u256_using_little_endian_hostapi
            local.get 0
            i64.load
            local.set 3
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.set 6
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.set 10
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.set 11
            local.get 7
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
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
            local.get 6
            i64.store offset=8
            local.get 0
            local.get 3
            i64.store
            local.get 2
            i32.const -32
            i32.add
            local.tee 2
            local.tee 7
            global.set $__stack_pointer
            local.get 0
            i32.const 1
            local.get 2
            call $wrapper_u256_shr
            block  ;; label = @5
              local.get 3
              i32.wrap_i64
              i32.const 1
              i32.and
              local.get 2
              i64.load
              local.tee 5
              i64.const 127
              i64.and
              local.get 5
              local.get 3
              i64.const 1
              i64.and
              local.tee 4
              i64.eqz
              select
              local.tee 24
              i64.const 31
              i64.gt_u
              i64.const 0
              local.get 4
              i64.sub
              local.tee 5
              local.get 2
              i32.const 8
              i32.add
              i64.load
              i64.and
              local.tee 19
              i64.const 0
              i64.ne
              local.get 19
              i64.eqz
              select
              local.get 5
              local.get 2
              i32.const 16
              i32.add
              i64.load
              i64.and
              local.tee 20
              i64.const 0
              i64.ne
              local.get 5
              local.get 2
              i32.const 24
              i32.add
              i64.load
              i64.and
              local.tee 18
              i64.const 0
              i64.ne
              local.get 18
              i64.eqz
              select
              local.get 20
              local.get 18
              i64.or
              i64.eqz
              select
              i32.eq
              br_if 0 (;@5;)
              local.get 7
              i32.const -32
              i32.add
              local.tee 0
              local.tee 7
              global.set $__stack_pointer
              local.get 0
              i32.const 24
              i32.add
              i64.const 5640894258543067136
              i64.store
              local.get 0
              i64.const 0
              i64.store offset=16
              local.get 0
              i64.const 0
              i64.store offset=8
              local.get 0
              i64.const 0
              i64.store
              i32.const 0
              local.get 0
              call $wrapper_mstore_u256
              i32.const 4
              i32.const 34
              call $wrapper_mstore_u32
              i32.const 0
              i32.const 36
              call $wrapper_revert
            end
            local.get 8
            call $i32_from_big_endian_bytes32
            local.set 2
            local.get 7
            i32.const -32
            i32.add
            local.tee 0
            local.tee 7
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 18
            i64.store
            local.get 0
            local.get 20
            i64.store offset=16
            local.get 0
            local.get 19
            i64.store offset=8
            local.get 0
            local.get 24
            i64.store
            local.get 2
            local.get 0
            call $wrapper_mstore_u256
            local.get 7
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
            global.set $__stack_pointer
            block  ;; label = @5
              local.get 4
              i64.const 0
              i64.ne
              br_if 0 (;@5;)
              local.get 8
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 0
              i32.load
              local.set 7
              local.get 2
              i32.const -32
              i32.add
              local.tee 0
              local.tee 2
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
              local.get 6
              i64.store offset=8
              local.get 0
              local.get 3
              i64.const -256
              i64.and
              i64.store
              local.get 7
              i32.const 32
              i32.add
              local.get 0
              call $wrapper_mstore_u256
              local.get 2
              i32.const -32
              i32.add
              local.tee 0
              local.tee 2
              global.set $__stack_pointer
              local.get 0
              i32.const 24
              i32.add
              i64.const 0
              i64.store
              local.get 0
              i64.const 0
              i64.store offset=16
              local.get 0
              i64.const 0
              i64.store offset=8
              local.get 0
              local.get 24
              local.get 20
              i64.or
              local.get 19
              local.get 18
              i64.or
              i64.or
              i64.const 0
              i64.ne
              i64.extend_i32_u
              i64.store
              local.get 2
              i32.const -32
              i32.add
              local.tee 2
              local.tee 7
              global.set $__stack_pointer
              local.get 0
              i32.const 5
              local.get 2
              call $wrapper_u256_shl
              local.get 2
              i32.const 24
              i32.add
              i64.load
              local.set 3
              local.get 2
              i32.const 16
              i32.add
              i64.load
              local.set 4
              local.get 2
              i64.load
              local.set 6
              local.get 2
              i32.const 8
              i32.add
              i64.load
              local.set 10
              local.get 7
              i32.const -32
              i32.add
              local.tee 0
              local.tee 2
              global.set $__stack_pointer
              local.get 8
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 3
              local.get 0
              i32.const 24
              i32.add
              i64.load
              i64.add
              local.get 4
              local.get 0
              i32.const 16
              i32.add
              i64.load
              local.tee 3
              i64.add
              local.tee 5
              local.get 3
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.get 5
              local.get 6
              local.get 0
              i64.load
              local.tee 4
              i64.add
              local.tee 3
              local.get 4
              i64.lt_u
              local.tee 7
              local.get 10
              local.get 0
              i32.const 8
              i32.add
              i64.load
              local.tee 6
              i64.add
              local.get 7
              i64.extend_i32_u
              i64.add
              local.tee 4
              local.get 6
              i64.lt_u
              local.get 4
              local.get 6
              i64.eq
              select
              i64.extend_i32_u
              i64.add
              local.tee 12
              local.get 5
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.set 21
              br 2 (;@3;)
            end
            i64.const 0
            local.set 5
            local.get 0
            i64.const 0
            i64.store offset=16
            local.get 0
            i64.const 0
            i64.store offset=8
            local.get 0
            i64.const 4
            i64.store
            local.get 0
            i32.const 24
            i32.add
            i64.const 0
            i64.store
            i32.const 0
            local.get 0
            call $wrapper_mstore_u256
            block  ;; label = @5
              block  ;; label = @6
                local.get 24
                local.get 20
                i64.or
                local.get 19
                local.get 18
                i64.or
                i64.or
                i64.eqz
                i32.eqz
                br_if 0 (;@6;)
                i64.const 0
                local.set 10
                i64.const 0
                local.set 11
                i64.const 0
                local.set 6
                br 1 (;@5;)
              end
              i64.const -8487687725428770790
              local.set 14
              i64.const 4156397169740810738
              local.set 12
              i64.const -8176847297489115706
              local.set 13
              i64.const -5310871510323572325
              local.set 3
              i64.const 0
              local.set 4
              i64.const 0
              local.set 15
              i64.const 0
              local.set 16
              i64.const 0
              local.set 6
              loop  ;; label = @6
                local.get 2
                i32.const -32
                i32.add
                local.tee 0
                local.tee 2
                global.set $__stack_pointer
                local.get 8
                local.get 0
                call $u256_from_big_endian_bytes
                local.get 0
                i64.load
                local.set 5
                local.get 2
                i32.const -32
                i32.add
                local.tee 0
                local.tee 2
                global.set $__stack_pointer
                local.get 0
                i32.const 24
                i32.add
                local.get 14
                i64.store
                local.get 0
                local.get 12
                i64.store offset=16
                local.get 0
                local.get 13
                i64.store offset=8
                local.get 0
                local.get 3
                i64.store
                local.get 2
                i32.const -32
                i32.add
                local.tee 2
                local.tee 7
                global.set $__stack_pointer
                local.get 0
                local.get 2
                call $u256_to_big_endian_bytes
                local.get 7
                i32.const -32
                i32.add
                local.tee 0
                local.tee 7
                global.set $__stack_pointer
                local.get 2
                local.get 0
                call $wrapper_sload_u256_using_little_endian_hostapi
                local.get 0
                i64.load
                local.set 10
                local.get 0
                i32.const 8
                i32.add
                i64.load
                local.set 11
                local.get 0
                i32.const 16
                i32.add
                i64.load
                local.set 17
                local.get 0
                i32.const 24
                i32.add
                i64.load
                local.set 21
                local.get 7
                i32.const -32
                i32.add
                local.tee 0
                local.tee 2
                global.set $__stack_pointer
                local.get 0
                i32.const 24
                i32.add
                local.get 21
                i64.store
                local.get 0
                local.get 17
                i64.store offset=16
                local.get 0
                local.get 11
                i64.store offset=8
                local.get 0
                local.get 10
                i64.store
                local.get 5
                local.get 4
                i64.add
                i32.wrap_i64
                i32.const 32
                i32.add
                local.get 0
                call $wrapper_mstore_u256
                local.get 16
                local.get 4
                i64.const 32
                i64.add
                local.tee 5
                local.get 4
                i64.lt_u
                local.tee 0
                local.get 15
                local.get 0
                i64.extend_i32_u
                i64.add
                local.tee 10
                local.get 15
                i64.lt_u
                local.get 5
                local.get 4
                i64.ge_u
                select
                i64.extend_i32_u
                i64.add
                local.tee 11
                local.get 16
                i64.lt_u
                local.set 0
                local.get 14
                local.get 12
                local.get 3
                i64.const 1
                i64.add
                local.tee 17
                local.get 3
                i64.lt_u
                local.tee 7
                local.get 13
                local.get 7
                i64.extend_i32_u
                i64.add
                local.tee 21
                local.get 13
                i64.lt_u
                local.get 17
                local.get 3
                i64.ge_u
                select
                i64.extend_i32_u
                i64.add
                local.tee 23
                local.get 12
                i64.lt_u
                i64.extend_i32_u
                i64.add
                local.set 14
                local.get 5
                local.set 4
                local.get 10
                local.set 15
                local.get 11
                local.set 16
                local.get 17
                local.set 3
                local.get 21
                local.set 13
                local.get 23
                local.set 12
                local.get 5
                local.get 24
                i64.lt_u
                local.get 10
                local.get 19
                i64.lt_u
                local.get 10
                local.get 19
                i64.eq
                select
                local.get 11
                local.get 20
                i64.lt_u
                local.get 6
                local.get 0
                i64.extend_i32_u
                i64.add
                local.tee 6
                local.get 18
                i64.lt_u
                local.get 6
                local.get 18
                i64.eq
                select
                local.get 11
                local.get 20
                i64.xor
                local.get 6
                local.get 18
                i64.xor
                i64.or
                i64.eqz
                select
                br_if 0 (;@6;)
              end
            end
            local.get 2
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
            global.set $__stack_pointer
            local.get 8
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.get 6
            i64.add
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.tee 3
            local.get 11
            i64.add
            local.tee 6
            local.get 3
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.get 6
            local.get 0
            i64.load
            local.tee 4
            local.get 5
            i64.add
            local.tee 3
            local.get 4
            i64.lt_u
            local.tee 7
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.tee 5
            local.get 10
            i64.add
            local.get 7
            i64.extend_i32_u
            i64.add
            local.tee 4
            local.get 5
            i64.lt_u
            local.get 4
            local.get 5
            i64.eq
            select
            i64.extend_i32_u
            i64.add
            local.tee 12
            local.get 6
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.set 21
            br 1 (;@3;)
          end
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
            i32.const 63
            i32.gt_u
            br_if 0 (;@4;)
            i32.const 0
            i32.const 0
            call $wrapper_revert
          end
          i32.const 4
          local.get 1
          call $wrapper_calldataload_bytes32
          local.get 1
          local.get 1
          i32.const 64
          i32.add
          call $u256_from_big_endian_bytes
          local.get 1
          i32.const 64
          i32.add
          i32.const 8
          i32.add
          local.tee 2
          i64.load
          local.set 3
          local.get 1
          i32.const 64
          i32.add
          i32.const 16
          i32.add
          local.tee 7
          i64.load32_u
          local.set 4
          local.get 1
          i64.load offset=64
          local.set 5
          i32.const 36
          local.get 1
          call $wrapper_calldataload_bytes32
          local.get 1
          local.get 1
          i32.const 64
          i32.add
          call $u256_from_big_endian_bytes
          local.get 2
          i64.load
          local.set 6
          local.get 7
          i64.load32_u
          local.set 10
          local.get 1
          i64.load offset=64
          local.set 11
          local.get 0
          i32.const -32
          i32.add
          local.tee 0
          local.tee 2
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          i64.const 0
          i64.store
          local.get 0
          local.get 4
          i64.store offset=16
          local.get 0
          local.get 3
          i64.store offset=8
          local.get 0
          local.get 5
          i64.store
          i32.const 0
          local.get 0
          call $wrapper_mstore_u256
          i32.const 32
          i32.const 1
          call $wrapper_mstore_u32
          local.get 2
          i32.const -32
          i32.add
          local.tee 2
          local.tee 0
          global.set $__stack_pointer
          i32.const 0
          i32.const 64
          local.get 2
          call $wrapper_keccak256
          local.get 0
          i32.const -32
          i32.add
          local.tee 0
          local.tee 7
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          i64.const 0
          i64.store
          local.get 0
          local.get 10
          i64.store offset=16
          local.get 0
          local.get 6
          i64.store offset=8
          local.get 0
          local.get 11
          i64.store
          i32.const 0
          local.get 0
          call $wrapper_mstore_u256
          i32.const 32
          local.get 2
          call $wrapper_mstore_bytes32
          local.get 7
          i32.const -32
          i32.add
          local.tee 2
          local.tee 0
          global.set $__stack_pointer
          i32.const 0
          i32.const 64
          local.get 2
          call $wrapper_keccak256
          local.get 0
          i32.const -32
          i32.add
          local.tee 0
          local.tee 7
          global.set $__stack_pointer
          local.get 2
          local.get 0
          call $wrapper_sload_u256_using_little_endian_hostapi
          local.get 0
          i64.load
          local.set 3
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.set 4
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.set 5
          local.get 0
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 7
          i32.const -32
          i32.add
          local.tee 0
          local.tee 7
          global.set $__stack_pointer
          i32.const 64
          local.get 0
          call $wrapper_mload_bytes32
          local.get 0
          call $i32_from_big_endian_bytes32
          local.set 2
          local.get 7
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
          local.get 3
          i64.store
          local.get 2
          local.get 0
          call $wrapper_mstore_u256
          local.get 2
          i32.const 32
          call $wrapper_return
          br 2 (;@1;)
        end
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 8
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 23
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 13
        local.get 0
        i64.load
        local.set 18
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 6
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 8
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i64.load
        local.set 14
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 10
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 15
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 24
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        i32.const 33088
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i64.load
        local.set 25
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 16
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 17
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 11
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 8
        local.get 0
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          block  ;; label = @4
            local.get 14
            local.get 3
            local.get 18
            i64.sub
            local.tee 19
            i64.const 63
            i64.add
            local.tee 20
            i64.const -32
            i64.and
            i64.add
            local.tee 5
            local.get 25
            i64.gt_u
            local.get 10
            local.get 4
            local.get 6
            i64.sub
            local.get 3
            local.get 18
            i64.lt_u
            local.tee 7
            i64.extend_i32_u
            i64.sub
            local.tee 18
            local.get 20
            local.get 19
            i64.lt_u
            local.tee 9
            i64.extend_i32_u
            i64.add
            local.tee 25
            i64.add
            local.get 5
            local.get 14
            i64.lt_u
            local.tee 22
            i64.extend_i32_u
            i64.add
            local.tee 3
            local.get 16
            i64.gt_u
            local.get 3
            local.get 16
            i64.eq
            select
            local.get 15
            local.get 12
            local.get 13
            i64.sub
            local.tee 14
            local.get 7
            local.get 4
            local.get 6
            i64.lt_u
            local.get 4
            local.get 6
            i64.eq
            select
            i64.extend_i32_u
            local.tee 16
            i64.sub
            local.tee 26
            local.get 9
            local.get 25
            local.get 18
            i64.lt_u
            local.get 20
            local.get 19
            i64.ge_u
            select
            i64.extend_i32_u
            i64.add
            local.tee 18
            i64.add
            local.tee 4
            local.get 22
            local.get 3
            local.get 10
            i64.lt_u
            local.get 3
            local.get 10
            i64.eq
            select
            i64.extend_i32_u
            i64.add
            local.tee 6
            local.get 17
            i64.gt_u
            local.get 24
            local.get 21
            local.get 23
            i64.sub
            local.get 12
            local.get 13
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.get 14
            local.get 16
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.get 18
            local.get 26
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.add
            local.get 4
            local.get 15
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.get 6
            local.get 4
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.tee 4
            local.get 11
            i64.gt_u
            local.get 4
            local.get 11
            i64.eq
            select
            local.get 6
            local.get 17
            i64.xor
            local.get 4
            local.get 11
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
            local.get 5
            local.get 0
            i64.load
            i64.lt_u
            local.get 3
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.tee 10
            i64.lt_u
            local.get 3
            local.get 10
            i64.eq
            select
            local.get 6
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.tee 11
            i64.lt_u
            local.get 4
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.tee 10
            i64.lt_u
            local.get 4
            local.get 10
            i64.eq
            select
            local.get 6
            local.get 11
            i64.xor
            local.get 4
            local.get 10
            i64.xor
            i64.or
            i64.eqz
            select
            i32.eqz
            br_if 1 (;@3;)
          end
          local.get 2
          i32.const -32
          i32.add
          local.tee 0
          local.tee 2
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          i64.const 5640894258543067136
          i64.store
          local.get 0
          i64.const 0
          i64.store offset=16
          local.get 0
          i64.const 0
          i64.store offset=8
          local.get 0
          i64.const 0
          i64.store
          i32.const 0
          local.get 0
          call $wrapper_mstore_u256
          i32.const 4
          i32.const 65
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 4
        i64.store
        local.get 0
        local.get 6
        i64.store offset=16
        local.get 0
        local.get 3
        i64.store offset=8
        local.get 0
        local.get 5
        i64.store
        i32.const 64
        local.get 0
        call $wrapper_mstore_u256
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        global.set $__stack_pointer
        local.get 8
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.load
        local.set 2
        local.get 5
        i32.wrap_i64
        local.tee 0
        i32.const 32
        call $wrapper_mstore_u32
        local.get 2
        local.get 1
        call $wrapper_mload_bytes32
        local.get 0
        i32.const 32
        i32.add
        local.get 1
        call $wrapper_mstore_bytes32
        local.get 0
        i32.const 64
        i32.add
        local.get 2
        i32.const 32
        i32.add
        local.get 1
        call $i32_from_big_endian_bytes32
        call $wrapper_data_copy
        local.get 1
        local.get 1
        i32.const 64
        i32.add
        call $u256_from_big_endian_bytes
        local.get 1
        i64.load offset=64
        local.get 5
        i64.add
        i32.wrap_i64
        i32.const 64
        i32.add
        i32.const 0
        call $wrapper_mstore_u32
        local.get 1
        local.get 1
        i32.const 32
        i32.add
        call $u256_from_big_endian_bytes
        local.get 0
        local.get 1
        i32.load offset=32
        i32.const 31
        i32.add
        i32.const -32
        i32.and
        i32.const 64
        i32.add
        call $wrapper_return
        br 1 (;@1;)
      end
      local.get 7
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      i32.const 32896
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 6
      local.get 5
      i64.const -1
      i64.add
      local.tee 10
      local.get 5
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 10
      local.get 4
      i64.const -65
      i64.add
      local.tee 5
      local.get 4
      i64.lt_u
      local.tee 7
      local.get 3
      local.get 7
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.tee 4
      local.get 3
      i64.lt_u
      local.get 4
      local.get 3
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 6
      local.get 10
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.tee 13
      local.get 6
      local.get 5
      i64.const -32
      i64.and
      local.tee 10
      i64.const 96
      i64.add
      local.tee 3
      local.get 10
      i64.lt_u
      local.tee 7
      local.get 4
      local.get 7
      i64.extend_i32_u
      i64.add
      local.tee 11
      local.get 4
      i64.lt_u
      local.get 3
      local.get 10
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 12
      local.get 6
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.set 5
      block  ;; label = @2
        block  ;; label = @3
          local.get 10
          i64.const -97
          i64.gt_u
          i32.const 0
          local.get 4
          i64.const -1
          i64.eq
          select
          i32.const 0
          local.get 6
          local.get 13
          i64.and
          i64.const -1
          i64.eq
          select
          br_if 0 (;@3;)
          local.get 3
          local.get 0
          i64.load
          i64.gt_u
          local.get 11
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.tee 4
          i64.gt_u
          local.get 11
          local.get 4
          i64.eq
          select
          local.get 12
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.tee 6
          i64.gt_u
          local.get 5
          local.get 0
          i32.const 24
          i32.add
          i64.load
          local.tee 4
          i64.gt_u
          local.get 5
          local.get 4
          i64.eq
          select
          local.get 12
          local.get 6
          i64.xor
          local.get 5
          local.get 4
          i64.xor
          i64.or
          i64.eqz
          select
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        i64.const 5640894258543067136
        i64.store
        local.get 0
        i64.const 0
        i64.store offset=16
        local.get 0
        i64.const 0
        i64.store offset=8
        local.get 0
        i64.const 0
        i64.store
        i32.const 0
        local.get 0
        call $wrapper_mstore_u256
        i32.const 4
        i32.const 65
        call $wrapper_mstore_u32
        i32.const 0
        i32.const 36
        call $wrapper_revert
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 5
      i64.store
      local.get 0
      local.get 12
      i64.store offset=16
      local.get 0
      local.get 11
      i64.store offset=8
      local.get 0
      local.get 3
      i64.store
      i32.const 64
      local.get 0
      call $wrapper_mstore_u256
      local.get 3
      i32.wrap_i64
      local.tee 0
      i32.const 32
      call $wrapper_mstore_u32
      i32.const 96
      local.get 1
      call $wrapper_mload_bytes32
      local.get 0
      i32.const 32
      i32.add
      local.get 1
      call $wrapper_mstore_bytes32
      local.get 0
      i32.const 64
      i32.add
      i32.const 128
      local.get 1
      call $i32_from_big_endian_bytes32
      call $wrapper_data_copy
      local.get 1
      local.get 1
      i32.const 64
      i32.add
      call $u256_from_big_endian_bytes
      local.get 1
      i64.load offset=64
      local.get 3
      i64.add
      i32.wrap_i64
      i32.const 64
      i32.add
      i32.const 0
      call $wrapper_mstore_u32
      local.get 1
      local.get 1
      i32.const 32
      i32.add
      call $u256_from_big_endian_bytes
      local.get 0
      local.get 1
      i32.load offset=32
      i32.const 31
      i32.add
      i32.const -32
      i32.and
      i32.const 64
      i32.add
      call $wrapper_return
    end
    i32.const 0
    i32.const 0
    call $wrapper_revert
    local.get 1
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $call (type 5)
    call $GLDToken_48477_deployed.GLDToken_48477_deployed.init)
  (func $_start (type 5)
    call $__init_evm_heap)
  (func $GLDToken_48477.GLDToken_48477.init (type 5)
    (local i32 i32 i32 i64 i64 i64 i64 i64 i32 i64 i32 i32 i32 i32 i32 i64 i32 i64 i64 i64 i64 i64 i32 i64 i64)
    global.get $__stack_pointer
    local.tee 0
    local.set 1
    i32.const 128
    call $wrapper_memory_guard
    drop
    block  ;; label = @1
      call $wrapper_callvalue_not_zero
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      call $wrapper_revert
    end
    call $wrapper_current_contract_pure_contract_size
    local.set 2
    block  ;; label = @1
      call $wrapper_current_contract_code_size
      i64.extend_i32_u
      local.tee 3
      local.get 2
      i64.extend_i32_u
      local.tee 4
      i64.sub
      local.tee 5
      i64.const 31
      i64.add
      local.tee 6
      i64.const -32
      i64.and
      local.tee 7
      i64.const -96
      i64.lt_u
      i32.const 0
      local.get 6
      local.get 5
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      local.get 3
      local.get 4
      i64.lt_u
      i64.extend_i32_u
      local.tee 4
      i64.sub
      local.tee 9
      i64.eqz
      select
      i32.const 0
      local.get 8
      local.get 9
      i64.const 0
      local.get 4
      i64.sub
      local.tee 3
      i64.lt_u
      local.get 6
      local.get 5
      i64.ge_u
      select
      i64.extend_i32_u
      local.get 4
      i64.sub
      local.tee 6
      local.get 6
      local.get 3
      i64.lt_u
      i64.extend_i32_u
      local.get 4
      i64.sub
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      local.get 0
      i32.const -32
      i32.add
      local.tee 8
      local.tee 0
      global.set $__stack_pointer
      local.get 8
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 8
      i64.const 0
      i64.store offset=16
      local.get 8
      i64.const 0
      i64.store offset=8
      local.get 8
      i64.const 0
      i64.store
      i32.const 0
      local.get 8
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 7
    i32.wrap_i64
    i32.const 96
    i32.add
    call $wrapper_set_memptr_global
    i32.const 96
    local.get 2
    local.get 5
    i32.wrap_i64
    call $wrapper_codecopy
    block  ;; label = @1
      local.get 5
      i64.const 31
      i64.gt_u
      local.get 3
      i64.const 0
      i64.ne
      local.tee 2
      local.get 3
      i64.eqz
      local.tee 8
      select
      local.get 2
      local.get 3
      i64.const 0
      i64.gt_s
      local.get 8
      select
      local.get 3
      local.get 3
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      call $wrapper_revert
    end
    local.get 0
    i32.const -32
    i32.add
    local.tee 10
    local.tee 0
    global.set $__stack_pointer
    i32.const 96
    local.get 10
    call $wrapper_mload_bytes32
    call $wrapper_get_memptr_global
    local.tee 11
    i32.const 64
    i32.add
    call $wrapper_set_memptr_global
    local.get 0
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 4
    i64.store
    local.get 11
    local.get 0
    call $wrapper_mstore_u256
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 5147452075860295680
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 0
    i64.store
    local.get 11
    i32.const 32
    i32.add
    local.tee 12
    local.get 0
    call $wrapper_mstore_u256
    call $wrapper_get_memptr_global
    local.tee 13
    i32.const 64
    i32.add
    call $wrapper_set_memptr_global
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 3
    i64.store
    local.get 13
    local.get 0
    call $wrapper_mstore_u256
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 5137556041713582080
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 0
    i64.store
    local.get 13
    i32.const 32
    i32.add
    local.get 0
    call $wrapper_mstore_u256
    local.get 2
    i32.const -32
    i32.add
    local.tee 14
    local.tee 0
    global.set $__stack_pointer
    local.get 11
    local.get 14
    call $wrapper_mload_bytes32
    local.get 0
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 14
    local.get 0
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 0
      i32.const 8
      i32.add
      i64.load
      i64.eqz
      i32.const 0
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 0
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 3
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 2
    local.get 0
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 0
    i64.load
    local.set 3
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 5
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 4
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 6
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    local.get 6
    i64.store
    local.get 0
    local.get 4
    i64.store offset=16
    local.get 0
    local.get 5
    i64.store offset=8
    local.get 0
    local.get 3
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    i32.const 1
    local.get 2
    call $wrapper_u256_shr
    block  ;; label = @1
      local.get 3
      i32.wrap_i64
      i32.const 1
      i32.and
      local.get 2
      i64.load
      local.tee 5
      i64.const 127
      i64.and
      local.get 5
      local.get 3
      i64.const 1
      i64.and
      local.tee 3
      i64.eqz
      select
      local.tee 7
      i64.const 31
      i64.gt_u
      i64.const 0
      local.get 3
      i64.sub
      local.tee 3
      local.get 2
      i32.const 8
      i32.add
      i64.load
      i64.and
      local.tee 15
      i64.const 0
      i64.ne
      local.get 15
      i64.eqz
      local.tee 16
      select
      local.get 3
      local.get 2
      i32.const 16
      i32.add
      i64.load
      i64.and
      local.tee 17
      i64.const 0
      i64.ne
      local.get 3
      local.get 2
      i32.const 24
      i32.add
      i64.load
      i64.and
      local.tee 9
      i64.const 0
      i64.ne
      local.get 9
      i64.eqz
      select
      local.get 17
      local.get 9
      i64.or
      i64.eqz
      local.tee 2
      select
      i32.eq
      br_if 0 (;@1;)
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 0
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 34
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    block  ;; label = @1
      local.get 7
      i64.const 32
      i64.lt_u
      i32.const 0
      local.get 16
      select
      i32.const 0
      local.get 2
      select
      br_if 0 (;@1;)
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 3
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      local.get 2
      i32.const -32
      i32.add
      local.tee 16
      local.tee 0
      global.set $__stack_pointer
      i32.const 0
      i32.const 32
      local.get 16
      call $wrapper_keccak256
      local.get 0
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 14
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i64.load
      local.set 3
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 5
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 5
      local.get 3
      i64.const 31
      i64.add
      local.tee 6
      local.get 3
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      local.tee 19
      i64.store offset=8
      local.get 0
      local.get 6
      i64.store
      local.get 0
      local.get 4
      local.get 8
      local.get 19
      local.get 5
      i64.lt_u
      local.get 6
      local.get 3
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 3
      i64.store offset=16
      local.get 0
      i32.const 24
      i32.add
      local.get 18
      local.get 3
      local.get 4
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 6
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 18
      local.get 2
      i64.load
      local.set 19
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 20
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 16
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 21
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 5
      local.get 0
      i64.load
      local.set 4
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 3
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 14
      local.get 0
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i64.load
          i64.const 32
          i64.lt_u
          i32.const 0
          local.get 0
          i32.const 8
          i32.add
          i64.load
          i64.eqz
          select
          i32.const 0
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.get 0
          i32.const 24
          i32.add
          i64.load
          i64.or
          i64.eqz
          select
          br_if 0 (;@3;)
          local.get 21
          local.get 6
          i64.add
          local.get 5
          local.get 18
          i64.add
          local.tee 18
          local.get 5
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 18
          local.get 4
          local.get 19
          i64.add
          local.tee 5
          local.get 4
          i64.lt_u
          local.tee 0
          local.get 3
          local.get 20
          i64.add
          local.get 0
          i64.extend_i32_u
          i64.add
          local.tee 4
          local.get 3
          i64.lt_u
          local.get 4
          local.get 3
          i64.eq
          select
          i64.extend_i32_u
          i64.add
          local.tee 6
          local.get 18
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.set 3
          br 1 (;@2;)
        end
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 16
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 3
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
        local.set 5
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 15
      local.get 7
      i64.const 31
      i64.add
      local.tee 18
      local.get 7
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      local.tee 19
      i64.store offset=8
      local.get 0
      local.get 18
      i64.store
      local.get 0
      local.get 17
      local.get 8
      local.get 19
      local.get 15
      i64.lt_u
      local.get 18
      local.get 7
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 7
      i64.store offset=16
      local.get 0
      i32.const 24
      i32.add
      local.get 9
      local.get 7
      local.get 17
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 15
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 9
      local.get 2
      i64.load
      local.set 7
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 17
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 8
      global.set $__stack_pointer
      local.get 16
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 5
      local.get 7
      local.get 0
      i64.load
      local.tee 18
      i64.add
      local.tee 20
      i64.ge_u
      local.get 4
      local.get 17
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.tee 7
      i64.add
      local.get 20
      local.get 18
      i64.lt_u
      local.tee 2
      i64.extend_i32_u
      i64.add
      local.tee 18
      i64.ge_u
      local.get 4
      local.get 18
      i64.eq
      select
      local.get 6
      local.get 9
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.add
      local.tee 9
      local.get 2
      local.get 18
      local.get 7
      i64.lt_u
      local.get 18
      local.get 7
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 19
      i64.ge_u
      local.get 3
      local.get 15
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.add
      local.get 9
      local.get 17
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 19
      local.get 9
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 17
      i64.ge_u
      local.get 3
      local.get 17
      i64.eq
      select
      local.get 6
      local.get 19
      i64.xor
      local.get 3
      local.get 17
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 3
        i64.store
        local.get 0
        local.get 6
        i64.store offset=16
        local.get 0
        local.get 4
        i64.store offset=8
        local.get 0
        local.get 5
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        local.get 2
        call $u256_to_big_endian_bytes
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 0
        i64.const 0
        i64.store offset=16
        local.get 0
        i64.const 0
        i64.store offset=8
        local.get 0
        i64.const 0
        i64.store
        local.get 2
        local.get 0
        call $wrapper_sstore_u256_using_little_endian_hostapi
        local.get 6
        local.get 5
        i64.const 1
        i64.add
        local.tee 7
        local.get 5
        i64.lt_u
        local.tee 0
        local.get 4
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 9
        local.get 4
        i64.lt_u
        local.get 7
        local.get 5
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 15
        local.get 6
        i64.lt_u
        local.set 0
        local.get 7
        local.set 5
        local.get 9
        local.set 4
        local.get 15
        local.set 6
        local.get 7
        local.get 20
        i64.lt_u
        local.get 9
        local.get 18
        i64.lt_u
        local.get 9
        local.get 18
        i64.eq
        select
        local.get 15
        local.get 19
        i64.lt_u
        local.get 3
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 3
        local.get 17
        i64.lt_u
        local.get 3
        local.get 17
        i64.eq
        select
        local.get 15
        local.get 19
        i64.xor
        local.get 3
        local.get 17
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
      end
    end
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 14
    local.get 0
    call $u256_from_big_endian_bytes
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 3
    i64.const 0
    local.set 7
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 5
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 4
    local.get 0
    i64.load
    local.set 6
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        local.get 6
        i64.const 31
        i64.gt_u
        local.get 4
        i64.const 0
        i64.ne
        local.get 4
        i64.eqz
        select
        local.get 5
        i64.const 0
        i64.ne
        local.get 3
        i64.const 0
        i64.ne
        local.get 3
        i64.eqz
        select
        local.get 5
        local.get 3
        i64.or
        i64.eqz
        select
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i64.const -1
        i64.store offset=16
        local.get 0
        i64.const -1
        i64.store offset=8
        local.get 0
        i64.const -32
        i64.store
        local.get 0
        i32.const 24
        i32.add
        i64.const -1
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        local.get 2
        call $u256_to_big_endian_bytes
        local.get 8
        i32.const -32
        i32.add
        local.tee 22
        local.tee 0
        global.set $__stack_pointer
        local.get 14
        local.get 2
        local.get 22
        call $wrapper_bytes32_and
        local.get 0
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        i64.const 0
        local.set 5
        local.get 0
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 0
        i64.const 0
        i64.store offset=16
        local.get 0
        i64.const 0
        i64.store offset=8
        local.get 0
        i64.const 3
        i64.store
        i32.const 0
        local.get 0
        call $wrapper_mstore_u256
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 0
        global.set $__stack_pointer
        i32.const 32
        local.set 16
        i32.const 0
        i32.const 32
        local.get 2
        call $wrapper_keccak256
        local.get 0
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 22
        local.get 0
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 0
          i64.load
          local.get 0
          i32.const 16
          i32.add
          i64.load
          i64.or
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.get 0
          i32.const 24
          i32.add
          i64.load
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 17
          i64.const 0
          local.set 18
          i64.const 0
          local.set 4
          i64.const 32
          local.set 3
          i64.const 0
          local.set 19
          i64.const 0
          local.set 20
          i64.const 0
          local.set 21
          loop  ;; label = @4
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 11
            local.get 3
            i32.wrap_i64
            i32.add
            local.get 0
            call $wrapper_mload_u256
            local.get 0
            i64.load
            local.set 6
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.set 7
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.set 9
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.set 15
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 15
            i64.store
            local.get 0
            local.get 9
            i64.store offset=16
            local.get 0
            local.get 7
            i64.store offset=8
            local.get 0
            local.get 6
            i64.store
            local.get 2
            local.get 0
            call $wrapper_sstore_u256_using_little_endian_hostapi
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 2
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i64.load
            local.set 6
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.set 7
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.set 23
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.set 9
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
            global.set $__stack_pointer
            local.get 0
            local.get 7
            local.get 6
            i64.const 1
            i64.add
            local.tee 15
            local.get 6
            i64.lt_u
            local.tee 8
            i64.extend_i32_u
            i64.add
            local.tee 24
            i64.store offset=8
            local.get 0
            local.get 15
            i64.store
            local.get 0
            local.get 9
            local.get 8
            local.get 24
            local.get 7
            i64.lt_u
            local.get 15
            local.get 6
            i64.ge_u
            select
            i64.extend_i32_u
            i64.add
            local.tee 6
            i64.store offset=16
            local.get 0
            i32.const 24
            i32.add
            local.get 23
            local.get 6
            local.get 9
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.store
            local.get 2
            i32.const -32
            i32.add
            local.tee 2
            local.tee 8
            global.set $__stack_pointer
            local.get 0
            local.get 2
            call $u256_to_big_endian_bytes
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 22
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 18
            local.get 5
            i64.const 32
            i64.add
            local.tee 6
            local.get 5
            i64.lt_u
            local.tee 16
            local.get 17
            local.get 16
            i64.extend_i32_u
            i64.add
            local.tee 7
            local.get 17
            i64.lt_u
            local.get 6
            local.get 5
            i64.ge_u
            select
            i64.extend_i32_u
            i64.add
            local.tee 9
            local.get 18
            i64.lt_u
            local.set 16
            local.get 21
            local.get 20
            local.get 3
            i64.const 32
            i64.add
            local.tee 15
            local.get 3
            i64.lt_u
            local.tee 12
            local.get 19
            local.get 12
            i64.extend_i32_u
            i64.add
            local.tee 23
            local.get 19
            i64.lt_u
            local.get 15
            local.get 3
            i64.ge_u
            select
            i64.extend_i32_u
            i64.add
            local.tee 24
            local.get 20
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.set 21
            local.get 6
            local.set 5
            local.get 7
            local.set 17
            local.get 9
            local.set 18
            local.get 15
            local.set 3
            local.get 23
            local.set 19
            local.get 24
            local.set 20
            local.get 6
            local.get 0
            i64.load
            i64.lt_u
            local.get 7
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.tee 6
            i64.lt_u
            local.get 7
            local.get 6
            i64.eq
            select
            local.get 9
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.tee 7
            i64.lt_u
            local.get 4
            local.get 16
            i64.extend_i32_u
            i64.add
            local.tee 4
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.tee 6
            i64.lt_u
            local.get 4
            local.get 6
            i64.eq
            select
            local.get 9
            local.get 7
            i64.xor
            local.get 4
            local.get 6
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
          end
          local.get 15
          i32.wrap_i64
          local.set 16
        end
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 22
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i64.load
        local.set 6
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 5
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 4
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 3
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 14
        local.get 0
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 6
          local.get 0
          i64.load
          i64.ge_u
          local.get 5
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.tee 6
          i64.ge_u
          local.get 5
          local.get 6
          i64.eq
          select
          local.get 4
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.tee 6
          i64.ge_u
          local.get 3
          local.get 0
          i32.const 24
          i32.add
          i64.load
          local.tee 5
          i64.ge_u
          local.get 3
          local.get 5
          i64.eq
          select
          local.get 4
          local.get 6
          i64.xor
          local.get 3
          local.get 5
          i64.xor
          i64.or
          i64.eqz
          select
          br_if 0 (;@3;)
          local.get 8
          i32.const -32
          i32.add
          local.tee 12
          local.tee 0
          global.set $__stack_pointer
          local.get 16
          local.get 11
          i32.add
          local.get 12
          call $wrapper_mload_bytes32
          local.get 0
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 8
          i32.const 24
          i32.add
          local.get 14
          i32.const 24
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 8
          i32.const 16
          i32.add
          local.get 14
          i32.const 16
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 8
          i32.const 8
          i32.add
          local.get 14
          i32.const 8
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 8
          local.get 14
          i64.load align=1
          i64.store align=1
          local.get 8
          local.get 0
          call $u256_from_big_endian_bytes
          local.get 0
          i64.load
          local.set 3
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.set 5
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.set 4
          local.get 0
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 6
          i64.store
          local.get 0
          local.get 4
          i64.store offset=16
          local.get 0
          local.get 5
          i64.store offset=8
          local.get 0
          local.get 3
          i64.store
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 0
          i32.const 3
          local.get 8
          call $wrapper_u256_shl
          local.get 8
          i32.load
          local.set 11
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          i64.const -1
          i64.store
          local.get 0
          i64.const -1
          i64.store offset=16
          local.get 0
          i64.const -1
          i64.store offset=8
          local.get 0
          i64.const -1
          i64.store
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 0
          local.get 11
          i32.const 248
          i32.and
          local.get 8
          call $wrapper_u256_shr
          local.get 8
          i64.load
          local.set 3
          local.get 8
          i32.const 8
          i32.add
          i64.load
          local.set 5
          local.get 8
          i32.const 16
          i32.add
          i64.load
          local.set 4
          local.get 8
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 6
          i64.const -1
          i64.xor
          i64.store
          local.get 0
          local.get 4
          i64.const -1
          i64.xor
          i64.store offset=16
          local.get 0
          local.get 5
          i64.const -1
          i64.xor
          i64.store offset=8
          local.get 0
          local.get 3
          i64.const -1
          i64.xor
          i64.store
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 0
          local.get 8
          call $u256_to_big_endian_bytes
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 16
          global.set $__stack_pointer
          local.get 12
          local.get 8
          local.get 0
          call $wrapper_bytes32_and
          local.get 16
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 16
          i32.const -32
          i32.add
          local.tee 16
          local.tee 12
          global.set $__stack_pointer
          local.get 16
          i32.const 24
          i32.add
          local.get 0
          i32.const 24
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 16
          i32.const 16
          i32.add
          local.get 0
          i32.const 16
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 16
          i32.const 8
          i32.add
          local.get 0
          i32.const 8
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 16
          local.get 0
          i64.load align=1
          i64.store align=1
          local.get 16
          local.get 8
          call $u256_from_big_endian_bytes
          local.get 8
          i64.load
          local.set 3
          local.get 8
          i32.const 8
          i32.add
          i64.load
          local.set 5
          local.get 8
          i32.const 16
          i32.add
          i64.load
          local.set 4
          local.get 8
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 12
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 6
          i64.store
          local.get 0
          local.get 4
          i64.store offset=16
          local.get 0
          local.get 5
          i64.store offset=8
          local.get 0
          local.get 3
          i64.store
          local.get 2
          local.get 0
          call $wrapper_sstore_u256_using_little_endian_hostapi
        end
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 2
        i32.const 24
        i32.add
        local.get 14
        i32.const 24
        i32.add
        i64.load align=1
        i64.store align=1
        local.get 2
        i32.const 16
        i32.add
        local.get 14
        i32.const 16
        i32.add
        i64.load align=1
        i64.store align=1
        local.get 2
        i32.const 8
        i32.add
        local.get 14
        i32.const 8
        i32.add
        i64.load align=1
        i64.store align=1
        local.get 2
        local.get 14
        i64.load align=1
        i64.store align=1
        local.get 2
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i64.load
        local.set 3
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 5
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 4
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 6
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 6
        i64.store
        local.get 0
        local.get 4
        i64.store offset=16
        local.get 0
        local.get 5
        i64.store offset=8
        local.get 0
        local.get 3
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        i32.const 1
        local.get 2
        call $wrapper_u256_shl
        local.get 2
        i32.const 24
        i32.add
        i64.load
        local.set 7
        local.get 2
        i32.const 16
        i32.add
        i64.load
        local.set 5
        local.get 2
        i32.const 8
        i32.add
        i64.load
        local.set 4
        local.get 2
        i64.load
        local.set 3
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 0
        i64.const 0
        i64.store offset=16
        local.get 0
        i64.const 0
        i64.store offset=8
        local.get 0
        i64.const 3
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 8
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        local.get 8
        call $u256_to_big_endian_bytes
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 7
        local.get 5
        local.get 3
        i64.const 1
        i64.add
        local.tee 6
        local.get 3
        i64.lt_u
        local.tee 16
        local.get 4
        local.get 16
        i64.extend_i32_u
        i64.add
        local.tee 9
        local.get 4
        i64.lt_u
        local.get 6
        local.get 3
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 3
        local.get 5
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.store
        local.get 0
        local.get 3
        i64.store offset=16
        local.get 0
        local.get 9
        i64.store offset=8
        local.get 0
        local.get 6
        i64.store
        local.get 8
        local.get 0
        call $wrapper_sstore_u256_using_little_endian_hostapi
        br 1 (;@1;)
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 14
      i32.const 24
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 14
      i32.const 16
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 14
      i32.const 8
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 14
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i64.load
          local.get 0
          i32.const 16
          i32.add
          i64.load
          i64.or
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.get 0
          i32.const 24
          i32.add
          i64.load
          i64.or
          i64.or
          i64.eqz
          i32.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 3
          i64.const 0
          local.set 5
          i64.const 0
          local.set 4
          br 1 (;@2;)
        end
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 12
        local.get 0
        call $wrapper_mload_u256
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
        local.set 3
        local.get 0
        i64.load
        local.set 7
      end
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 14
      i32.const 24
      i32.add
      local.tee 16
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 14
      i32.const 16
      i32.add
      local.tee 12
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 14
      i32.const 8
      i32.add
      local.tee 11
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 14
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i64.load
      local.set 6
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 9
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 15
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 17
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 17
      i64.store
      local.get 0
      local.get 15
      i64.store offset=16
      local.get 0
      local.get 9
      i64.store offset=8
      local.get 0
      local.get 6
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 3
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i32.load
      local.set 22
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const -1
      i64.store
      local.get 0
      i64.const -1
      i64.store offset=16
      local.get 0
      i64.const -1
      i64.store offset=8
      local.get 0
      i64.const -1
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      local.get 22
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i64.load
      local.set 6
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 9
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 15
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 17
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 16
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 12
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 11
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 14
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i64.load
      local.set 18
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 19
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 20
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 21
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 21
      i64.store
      local.get 0
      local.get 20
      i64.store offset=16
      local.get 0
      local.get 19
      i64.store offset=8
      local.get 0
      local.get 18
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 1
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i64.load
      local.set 18
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 19
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 20
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 21
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 3
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 8
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 8
      call $u256_to_big_endian_bytes
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 21
      local.get 4
      local.get 17
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 0
      local.get 20
      local.get 5
      local.get 15
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=16
      local.get 0
      local.get 19
      local.get 3
      local.get 9
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=8
      local.get 0
      local.get 18
      local.get 7
      local.get 6
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 8
      local.get 0
      call $wrapper_sstore_u256_using_little_endian_hostapi
    end
    local.get 2
    i32.const -32
    i32.add
    local.tee 11
    local.tee 0
    global.set $__stack_pointer
    local.get 13
    local.get 11
    call $wrapper_mload_bytes32
    local.get 0
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 11
    local.get 0
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 0
      i32.const 8
      i32.add
      i64.load
      i64.const 0
      i64.ne
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.tee 5
      i64.const 0
      i64.ne
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.tee 3
      i64.const 0
      i64.ne
      local.get 3
      i64.eqz
      select
      local.get 5
      local.get 3
      i64.or
      i64.eqz
      select
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 0
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 4
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 2
    local.get 0
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 0
    i64.load
    local.set 3
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 5
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 4
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 6
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    local.get 6
    i64.store
    local.get 0
    local.get 4
    i64.store offset=16
    local.get 0
    local.get 5
    i64.store offset=8
    local.get 0
    local.get 3
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    i32.const 1
    local.get 2
    call $wrapper_u256_shr
    block  ;; label = @1
      local.get 2
      i64.load
      local.tee 5
      i64.const 127
      i64.and
      local.get 5
      local.get 3
      i64.const 1
      i64.and
      local.tee 4
      i64.eqz
      select
      local.tee 7
      i64.const 31
      i64.gt_u
      i64.const 0
      local.get 4
      i64.sub
      local.tee 5
      local.get 2
      i32.const 8
      i32.add
      i64.load
      i64.and
      local.tee 15
      i64.const 0
      i64.ne
      local.get 15
      i64.eqz
      local.tee 16
      select
      local.get 5
      local.get 2
      i32.const 16
      i32.add
      i64.load
      i64.and
      local.tee 17
      i64.const 0
      i64.ne
      local.get 5
      local.get 2
      i32.const 24
      i32.add
      i64.load
      i64.and
      local.tee 9
      i64.const 0
      i64.ne
      local.get 9
      i64.eqz
      select
      local.get 17
      local.get 9
      i64.or
      i64.eqz
      local.tee 2
      select
      local.get 3
      i32.wrap_i64
      i32.const 1
      i32.and
      i32.eq
      br_if 0 (;@1;)
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 0
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 34
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    block  ;; label = @1
      local.get 7
      i64.const 32
      i64.lt_u
      i32.const 0
      local.get 16
      select
      i32.const 0
      local.get 2
      select
      br_if 0 (;@1;)
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 4
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      local.get 2
      i32.const -32
      i32.add
      local.tee 16
      local.tee 0
      global.set $__stack_pointer
      i32.const 0
      i32.const 32
      local.get 16
      call $wrapper_keccak256
      local.get 0
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 11
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i64.load
      local.set 3
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 5
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 5
      local.get 3
      i64.const 31
      i64.add
      local.tee 6
      local.get 3
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      local.tee 19
      i64.store offset=8
      local.get 0
      local.get 6
      i64.store
      local.get 0
      local.get 4
      local.get 8
      local.get 19
      local.get 5
      i64.lt_u
      local.get 6
      local.get 3
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 3
      i64.store offset=16
      local.get 0
      i32.const 24
      i32.add
      local.get 18
      local.get 3
      local.get 4
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 6
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 18
      local.get 2
      i64.load
      local.set 19
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 20
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 16
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 21
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 5
      local.get 0
      i64.load
      local.set 4
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 3
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 11
      local.get 0
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i64.load
          i64.const 32
          i64.lt_u
          i32.const 0
          local.get 0
          i32.const 8
          i32.add
          i64.load
          i64.eqz
          select
          i32.const 0
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.get 0
          i32.const 24
          i32.add
          i64.load
          i64.or
          i64.eqz
          select
          br_if 0 (;@3;)
          local.get 21
          local.get 6
          i64.add
          local.get 5
          local.get 18
          i64.add
          local.tee 18
          local.get 5
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 18
          local.get 4
          local.get 19
          i64.add
          local.tee 5
          local.get 4
          i64.lt_u
          local.tee 0
          local.get 3
          local.get 20
          i64.add
          local.get 0
          i64.extend_i32_u
          i64.add
          local.tee 4
          local.get 3
          i64.lt_u
          local.get 4
          local.get 3
          i64.eq
          select
          i64.extend_i32_u
          i64.add
          local.tee 6
          local.get 18
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.set 3
          br 1 (;@2;)
        end
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 16
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 3
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
        local.set 5
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 15
      local.get 7
      i64.const 31
      i64.add
      local.tee 18
      local.get 7
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      local.tee 19
      i64.store offset=8
      local.get 0
      local.get 18
      i64.store
      local.get 0
      local.get 17
      local.get 8
      local.get 19
      local.get 15
      i64.lt_u
      local.get 18
      local.get 7
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 7
      i64.store offset=16
      local.get 0
      i32.const 24
      i32.add
      local.get 9
      local.get 7
      local.get 17
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 15
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 9
      local.get 2
      i64.load
      local.set 7
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 17
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 8
      global.set $__stack_pointer
      local.get 16
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 5
      local.get 7
      local.get 0
      i64.load
      local.tee 18
      i64.add
      local.tee 20
      i64.ge_u
      local.get 4
      local.get 17
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.tee 7
      i64.add
      local.get 20
      local.get 18
      i64.lt_u
      local.tee 2
      i64.extend_i32_u
      i64.add
      local.tee 18
      i64.ge_u
      local.get 4
      local.get 18
      i64.eq
      select
      local.get 6
      local.get 9
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.add
      local.tee 9
      local.get 2
      local.get 18
      local.get 7
      i64.lt_u
      local.get 18
      local.get 7
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 19
      i64.ge_u
      local.get 3
      local.get 15
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.add
      local.get 9
      local.get 17
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 19
      local.get 9
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 17
      i64.ge_u
      local.get 3
      local.get 17
      i64.eq
      select
      local.get 6
      local.get 19
      i64.xor
      local.get 3
      local.get 17
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 3
        i64.store
        local.get 0
        local.get 6
        i64.store offset=16
        local.get 0
        local.get 4
        i64.store offset=8
        local.get 0
        local.get 5
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        local.get 2
        call $u256_to_big_endian_bytes
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 0
        i64.const 0
        i64.store offset=16
        local.get 0
        i64.const 0
        i64.store offset=8
        local.get 0
        i64.const 0
        i64.store
        local.get 2
        local.get 0
        call $wrapper_sstore_u256_using_little_endian_hostapi
        local.get 6
        local.get 5
        i64.const 1
        i64.add
        local.tee 7
        local.get 5
        i64.lt_u
        local.tee 0
        local.get 4
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 9
        local.get 4
        i64.lt_u
        local.get 7
        local.get 5
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 15
        local.get 6
        i64.lt_u
        local.set 0
        local.get 7
        local.set 5
        local.get 9
        local.set 4
        local.get 15
        local.set 6
        local.get 7
        local.get 20
        i64.lt_u
        local.get 9
        local.get 18
        i64.lt_u
        local.get 9
        local.get 18
        i64.eq
        select
        local.get 15
        local.get 19
        i64.lt_u
        local.get 3
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 3
        local.get 17
        i64.lt_u
        local.get 3
        local.get 17
        i64.eq
        select
        local.get 15
        local.get 19
        i64.xor
        local.get 3
        local.get 17
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
      end
    end
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 11
    local.get 0
    call $u256_from_big_endian_bytes
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 3
    i64.const 0
    local.set 7
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 5
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 4
    local.get 0
    i64.load
    local.set 6
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        local.get 6
        i64.const 31
        i64.gt_u
        local.get 4
        i64.const 0
        i64.ne
        local.get 4
        i64.eqz
        select
        local.get 5
        i64.const 0
        i64.ne
        local.get 3
        i64.const 0
        i64.ne
        local.get 3
        i64.eqz
        select
        local.get 5
        local.get 3
        i64.or
        i64.eqz
        select
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i64.const -1
        i64.store offset=16
        local.get 0
        i64.const -1
        i64.store offset=8
        local.get 0
        i64.const -32
        i64.store
        local.get 0
        i32.const 24
        i32.add
        i64.const -1
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        local.get 2
        call $u256_to_big_endian_bytes
        local.get 8
        i32.const -32
        i32.add
        local.tee 14
        local.tee 0
        global.set $__stack_pointer
        local.get 11
        local.get 2
        local.get 14
        call $wrapper_bytes32_and
        local.get 0
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        i64.const 0
        local.set 5
        local.get 0
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 0
        i64.const 0
        i64.store offset=16
        local.get 0
        i64.const 0
        i64.store offset=8
        local.get 0
        i64.const 4
        i64.store
        i32.const 0
        local.get 0
        call $wrapper_mstore_u256
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 0
        global.set $__stack_pointer
        i32.const 32
        local.set 16
        i32.const 0
        i32.const 32
        local.get 2
        call $wrapper_keccak256
        local.get 0
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 14
        local.get 0
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 0
          i64.load
          local.get 0
          i32.const 16
          i32.add
          i64.load
          i64.or
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.get 0
          i32.const 24
          i32.add
          i64.load
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 17
          i64.const 0
          local.set 18
          i64.const 0
          local.set 4
          i64.const 32
          local.set 3
          i64.const 0
          local.set 19
          i64.const 0
          local.set 20
          i64.const 0
          local.set 21
          loop  ;; label = @4
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 13
            local.get 3
            i32.wrap_i64
            i32.add
            local.get 0
            call $wrapper_mload_u256
            local.get 0
            i64.load
            local.set 6
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.set 7
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.set 9
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.set 15
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 15
            i64.store
            local.get 0
            local.get 9
            i64.store offset=16
            local.get 0
            local.get 7
            i64.store offset=8
            local.get 0
            local.get 6
            i64.store
            local.get 2
            local.get 0
            call $wrapper_sstore_u256_using_little_endian_hostapi
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 2
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i64.load
            local.set 6
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.set 7
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.set 23
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.set 9
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
            global.set $__stack_pointer
            local.get 0
            local.get 7
            local.get 6
            i64.const 1
            i64.add
            local.tee 15
            local.get 6
            i64.lt_u
            local.tee 8
            i64.extend_i32_u
            i64.add
            local.tee 24
            i64.store offset=8
            local.get 0
            local.get 15
            i64.store
            local.get 0
            local.get 9
            local.get 8
            local.get 24
            local.get 7
            i64.lt_u
            local.get 15
            local.get 6
            i64.ge_u
            select
            i64.extend_i32_u
            i64.add
            local.tee 6
            i64.store offset=16
            local.get 0
            i32.const 24
            i32.add
            local.get 23
            local.get 6
            local.get 9
            i64.lt_u
            i64.extend_i32_u
            i64.add
            i64.store
            local.get 2
            i32.const -32
            i32.add
            local.tee 2
            local.tee 8
            global.set $__stack_pointer
            local.get 0
            local.get 2
            call $u256_to_big_endian_bytes
            local.get 8
            i32.const -32
            i32.add
            local.tee 0
            local.tee 8
            global.set $__stack_pointer
            local.get 14
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 18
            local.get 5
            i64.const 32
            i64.add
            local.tee 6
            local.get 5
            i64.lt_u
            local.tee 16
            local.get 17
            local.get 16
            i64.extend_i32_u
            i64.add
            local.tee 7
            local.get 17
            i64.lt_u
            local.get 6
            local.get 5
            i64.ge_u
            select
            i64.extend_i32_u
            i64.add
            local.tee 9
            local.get 18
            i64.lt_u
            local.set 16
            local.get 21
            local.get 20
            local.get 3
            i64.const 32
            i64.add
            local.tee 15
            local.get 3
            i64.lt_u
            local.tee 12
            local.get 19
            local.get 12
            i64.extend_i32_u
            i64.add
            local.tee 23
            local.get 19
            i64.lt_u
            local.get 15
            local.get 3
            i64.ge_u
            select
            i64.extend_i32_u
            i64.add
            local.tee 24
            local.get 20
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.set 21
            local.get 6
            local.set 5
            local.get 7
            local.set 17
            local.get 9
            local.set 18
            local.get 15
            local.set 3
            local.get 23
            local.set 19
            local.get 24
            local.set 20
            local.get 6
            local.get 0
            i64.load
            i64.lt_u
            local.get 7
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.tee 6
            i64.lt_u
            local.get 7
            local.get 6
            i64.eq
            select
            local.get 9
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.tee 7
            i64.lt_u
            local.get 4
            local.get 16
            i64.extend_i32_u
            i64.add
            local.tee 4
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.tee 6
            i64.lt_u
            local.get 4
            local.get 6
            i64.eq
            select
            local.get 9
            local.get 7
            i64.xor
            local.get 4
            local.get 6
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
          end
          local.get 15
          i32.wrap_i64
          local.set 16
        end
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 14
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i64.load
        local.set 6
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 5
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 4
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 3
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 11
        local.get 0
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 6
          local.get 0
          i64.load
          i64.ge_u
          local.get 5
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.tee 6
          i64.ge_u
          local.get 5
          local.get 6
          i64.eq
          select
          local.get 4
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.tee 6
          i64.ge_u
          local.get 3
          local.get 0
          i32.const 24
          i32.add
          i64.load
          local.tee 5
          i64.ge_u
          local.get 3
          local.get 5
          i64.eq
          select
          local.get 4
          local.get 6
          i64.xor
          local.get 3
          local.get 5
          i64.xor
          i64.or
          i64.eqz
          select
          br_if 0 (;@3;)
          local.get 8
          i32.const -32
          i32.add
          local.tee 12
          local.tee 0
          global.set $__stack_pointer
          local.get 16
          local.get 13
          i32.add
          local.get 12
          call $wrapper_mload_bytes32
          local.get 0
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 8
          i32.const 24
          i32.add
          local.get 11
          i32.const 24
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 8
          i32.const 16
          i32.add
          local.get 11
          i32.const 16
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 8
          i32.const 8
          i32.add
          local.get 11
          i32.const 8
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 8
          local.get 11
          i64.load align=1
          i64.store align=1
          local.get 8
          local.get 0
          call $u256_from_big_endian_bytes
          local.get 0
          i64.load
          local.set 3
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.set 5
          local.get 0
          i32.const 16
          i32.add
          i64.load
          local.set 4
          local.get 0
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 6
          i64.store
          local.get 0
          local.get 4
          i64.store offset=16
          local.get 0
          local.get 5
          i64.store offset=8
          local.get 0
          local.get 3
          i64.store
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 0
          i32.const 3
          local.get 8
          call $wrapper_u256_shl
          local.get 8
          i32.load
          local.set 13
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          i64.const -1
          i64.store
          local.get 0
          i64.const -1
          i64.store offset=16
          local.get 0
          i64.const -1
          i64.store offset=8
          local.get 0
          i64.const -1
          i64.store
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 0
          local.get 13
          i32.const 248
          i32.and
          local.get 8
          call $wrapper_u256_shr
          local.get 8
          i64.load
          local.set 3
          local.get 8
          i32.const 8
          i32.add
          i64.load
          local.set 5
          local.get 8
          i32.const 16
          i32.add
          i64.load
          local.set 4
          local.get 8
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 6
          i64.const -1
          i64.xor
          i64.store
          local.get 0
          local.get 4
          i64.const -1
          i64.xor
          i64.store offset=16
          local.get 0
          local.get 5
          i64.const -1
          i64.xor
          i64.store offset=8
          local.get 0
          local.get 3
          i64.const -1
          i64.xor
          i64.store
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 0
          local.get 8
          call $u256_to_big_endian_bytes
          local.get 16
          i32.const -32
          i32.add
          local.tee 0
          local.tee 16
          global.set $__stack_pointer
          local.get 12
          local.get 8
          local.get 0
          call $wrapper_bytes32_and
          local.get 16
          i32.const -32
          i32.add
          local.tee 8
          local.tee 16
          global.set $__stack_pointer
          local.get 16
          i32.const -32
          i32.add
          local.tee 16
          local.tee 12
          global.set $__stack_pointer
          local.get 16
          i32.const 24
          i32.add
          local.get 0
          i32.const 24
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 16
          i32.const 16
          i32.add
          local.get 0
          i32.const 16
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 16
          i32.const 8
          i32.add
          local.get 0
          i32.const 8
          i32.add
          i64.load align=1
          i64.store align=1
          local.get 16
          local.get 0
          i64.load align=1
          i64.store align=1
          local.get 16
          local.get 8
          call $u256_from_big_endian_bytes
          local.get 8
          i64.load
          local.set 3
          local.get 8
          i32.const 8
          i32.add
          i64.load
          local.set 5
          local.get 8
          i32.const 16
          i32.add
          i64.load
          local.set 4
          local.get 8
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 12
          i32.const -32
          i32.add
          local.tee 0
          local.tee 8
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 6
          i64.store
          local.get 0
          local.get 4
          i64.store offset=16
          local.get 0
          local.get 5
          i64.store offset=8
          local.get 0
          local.get 3
          i64.store
          local.get 2
          local.get 0
          call $wrapper_sstore_u256_using_little_endian_hostapi
        end
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 2
        i32.const 24
        i32.add
        local.get 11
        i32.const 24
        i32.add
        i64.load align=1
        i64.store align=1
        local.get 2
        i32.const 16
        i32.add
        local.get 11
        i32.const 16
        i32.add
        i64.load align=1
        i64.store align=1
        local.get 2
        i32.const 8
        i32.add
        local.get 11
        i32.const 8
        i32.add
        i64.load align=1
        i64.store align=1
        local.get 2
        local.get 11
        i64.load align=1
        i64.store align=1
        local.get 2
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i64.load
        local.set 3
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 5
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 4
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 6
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 6
        i64.store
        local.get 0
        local.get 4
        i64.store offset=16
        local.get 0
        local.get 5
        i64.store offset=8
        local.get 0
        local.get 3
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 8
        global.set $__stack_pointer
        local.get 0
        i32.const 1
        local.get 2
        call $wrapper_u256_shl
        local.get 2
        i32.const 24
        i32.add
        i64.load
        local.set 7
        local.get 2
        i32.const 16
        i32.add
        i64.load
        local.set 5
        local.get 2
        i32.const 8
        i32.add
        i64.load
        local.set 4
        local.get 2
        i64.load
        local.set 3
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 0
        i64.const 0
        i64.store offset=16
        local.get 0
        i64.const 0
        i64.store offset=8
        local.get 0
        i64.const 4
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 8
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        local.get 8
        call $u256_to_big_endian_bytes
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 7
        local.get 5
        local.get 3
        i64.const 1
        i64.add
        local.tee 6
        local.get 3
        i64.lt_u
        local.tee 16
        local.get 4
        local.get 16
        i64.extend_i32_u
        i64.add
        local.tee 9
        local.get 4
        i64.lt_u
        local.get 6
        local.get 3
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 3
        local.get 5
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.store
        local.get 0
        local.get 3
        i64.store offset=16
        local.get 0
        local.get 9
        i64.store offset=8
        local.get 0
        local.get 6
        i64.store
        local.get 8
        local.get 0
        call $wrapper_sstore_u256_using_little_endian_hostapi
        br 1 (;@1;)
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 11
      i32.const 24
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 11
      i32.const 16
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 11
      i32.const 8
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 11
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i64.load
          local.get 0
          i32.const 16
          i32.add
          i64.load
          i64.or
          local.get 0
          i32.const 8
          i32.add
          i64.load
          local.get 0
          i32.const 24
          i32.add
          i64.load
          i64.or
          i64.or
          i64.eqz
          i32.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 3
          i64.const 0
          local.set 5
          i64.const 0
          local.set 4
          br 1 (;@2;)
        end
        local.get 8
        i32.const -32
        i32.add
        local.tee 0
        local.tee 8
        global.set $__stack_pointer
        local.get 13
        i32.const 32
        i32.add
        local.get 0
        call $wrapper_mload_u256
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
        local.set 3
        local.get 0
        i64.load
        local.set 7
      end
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 11
      i32.const 24
      i32.add
      local.tee 16
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 11
      i32.const 16
      i32.add
      local.tee 12
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 11
      i32.const 8
      i32.add
      local.tee 13
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 11
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i64.load
      local.set 6
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 9
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 15
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 17
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 17
      i64.store
      local.get 0
      local.get 15
      i64.store offset=16
      local.get 0
      local.get 9
      i64.store offset=8
      local.get 0
      local.get 6
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 3
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i32.load
      local.set 14
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const -1
      i64.store
      local.get 0
      i64.const -1
      i64.store offset=16
      local.get 0
      i64.const -1
      i64.store offset=8
      local.get 0
      i64.const -1
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      local.get 14
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i64.load
      local.set 6
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 9
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 15
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 17
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 16
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 12
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 13
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 11
      i64.load align=1
      i64.store align=1
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i64.load
      local.set 18
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 19
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 20
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 21
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 21
      i64.store
      local.get 0
      local.get 20
      i64.store offset=16
      local.get 0
      local.get 19
      i64.store offset=8
      local.get 0
      local.get 18
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 8
      global.set $__stack_pointer
      local.get 0
      i32.const 1
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i64.load
      local.set 18
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 19
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 20
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 21
      local.get 8
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 4
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 8
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 8
      call $u256_to_big_endian_bytes
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 21
      local.get 4
      local.get 17
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 0
      local.get 20
      local.get 5
      local.get 15
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=16
      local.get 0
      local.get 19
      local.get 3
      local.get 9
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=8
      local.get 0
      local.get 18
      local.get 7
      local.get 6
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 8
      local.get 0
      call $wrapper_sstore_u256_using_little_endian_hostapi
    end
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    call $wrapper_caller
    block  ;; label = @1
      local.get 0
      call $wrapper_bytes32_iszero
      i32.eqz
      br_if 0 (;@1;)
      call $wrapper_get_memptr_global
      local.set 8
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 16
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      i32.const 33120
      i32.const 24
      i32.add
      i64.load
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      i32.const 33120
      i32.const 16
      i32.add
      i64.load
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      i32.const 33120
      i32.const 8
      i32.add
      i64.load
      i64.store align=1
      local.get 2
      i32.const 0
      i64.load offset=33120
      i64.store align=1
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i64.load
      local.set 3
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 5
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 6
      local.get 16
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 6
      i64.store
      local.get 0
      local.get 4
      i64.store offset=16
      local.get 0
      local.get 5
      i64.store offset=8
      local.get 0
      local.get 3
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 16
      global.set $__stack_pointer
      local.get 0
      i32.const 224
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i64.load
      local.set 3
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 5
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 6
      local.get 16
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 6
      i64.store
      local.get 0
      local.get 4
      i64.store offset=16
      local.get 0
      local.get 5
      i64.store offset=8
      local.get 0
      local.get 3
      i64.store
      local.get 8
      local.get 0
      call $wrapper_mstore_u256
      local.get 8
      i32.const 4
      i32.add
      i32.const 0
      call $wrapper_mstore_u32
      local.get 8
      i32.const 36
      call $wrapper_revert
    end
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 2
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 2
    local.get 0
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 3
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 4
    local.get 0
    i64.load
    local.set 5
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 6
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 10
    local.get 0
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 5
      local.get 5
      local.get 0
      i64.load
      local.tee 15
      i64.add
      local.tee 9
      i64.le_u
      local.get 6
      local.get 6
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.tee 7
      i64.add
      local.get 9
      local.get 15
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      local.tee 5
      i64.le_u
      local.get 6
      local.get 5
      i64.eq
      select
      local.get 4
      local.get 4
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.add
      local.tee 15
      local.get 8
      local.get 5
      local.get 7
      i64.lt_u
      local.get 5
      local.get 7
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 6
      i64.le_u
      local.get 3
      local.get 3
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.add
      local.get 15
      local.get 17
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 6
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 7
      i64.le_u
      local.get 3
      local.get 7
      i64.eq
      select
      local.get 4
      local.get 6
      i64.xor
      local.get 3
      local.get 7
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 0
      i64.const 0
      i64.store offset=16
      local.get 0
      i64.const 0
      i64.store offset=8
      local.get 0
      i64.const 0
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 17
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 2
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    local.get 7
    i64.store
    local.get 0
    local.get 6
    i64.store offset=16
    local.get 0
    local.get 5
    i64.store offset=8
    local.get 0
    local.get 9
    i64.store
    local.get 2
    local.get 0
    call $wrapper_sstore_u256_using_little_endian_hostapi
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    call $wrapper_caller
    i32.const 0
    local.get 0
    call $wrapper_mstore_bytes32
    i32.const 32
    i32.const 0
    call $wrapper_mstore_u32
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 0
    global.set $__stack_pointer
    i32.const 0
    i32.const 64
    local.get 2
    call $wrapper_keccak256
    local.get 0
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 2
    local.get 0
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 7
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 6
    local.get 0
    i64.load
    local.set 9
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 15
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 10
    local.get 0
    call $u256_from_big_endian_bytes
    local.get 0
    i32.const 8
    i32.add
    i64.load
    local.set 3
    local.get 0
    i64.load
    local.set 5
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 17
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 4
    local.get 8
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    local.get 3
    local.get 15
    i64.add
    local.get 5
    local.get 9
    i64.add
    local.tee 9
    local.get 5
    i64.lt_u
    local.tee 16
    i64.extend_i32_u
    i64.add
    local.tee 5
    i64.store offset=8
    local.get 0
    local.get 9
    i64.store
    local.get 0
    local.get 4
    local.get 6
    i64.add
    local.tee 6
    local.get 16
    local.get 5
    local.get 3
    i64.lt_u
    local.get 5
    local.get 3
    i64.eq
    select
    i64.extend_i32_u
    i64.add
    local.tee 3
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 17
    local.get 7
    i64.add
    local.get 6
    local.get 4
    i64.lt_u
    i64.extend_i32_u
    i64.add
    local.get 3
    local.get 6
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.store
    local.get 2
    local.get 0
    call $wrapper_sstore_u256_using_little_endian_hostapi
    call $wrapper_get_memptr_global
    local.tee 16
    local.get 10
    call $wrapper_mstore_bytes32
    local.get 8
    i32.const -32
    i32.add
    local.tee 2
    local.tee 0
    global.set $__stack_pointer
    local.get 2
    call $wrapper_caller
    local.get 0
    i32.const -32
    i32.add
    local.tee 0
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    i64.const 0
    i64.store
    local.get 8
    i32.const -32
    i32.add
    local.tee 8
    global.set $__stack_pointer
    local.get 0
    local.get 8
    call $u256_to_big_endian_bytes
    local.get 16
    i32.const 32
    i32.const 33152
    local.get 8
    local.get 2
    call $wrapper_log3
    call $wrapper_get_memptr_global
    local.tee 0
    i32.const 49712
    i32.const 0
    call $evm_get_memory_addr
    i32.sub
    i32.const 4
    call $wrapper_codecopy
    local.get 0
    i32.const 4
    call $wrapper_return
    local.get 1
    global.set $__stack_pointer)
  (func $deploy (type 5)
    call $set_is_deploying_tx
    call $GLDToken_48477.GLDToken_48477.init)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 1)
  (global $__stack_pointer (mut i32) (i32.const 65536))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "call" (func $call))
  (export "deploy" (func $deploy))
  (data $.rodata (i32.const 32768) "\dd\f2R\ad\1b\e2\c8\9bi\c2\b0h\fc7\8d\aa\95+\a7\f1c\c4\a1\16(\f5ZM\f5#\b3\ef\96\c6\fd\1e")
  (data $.data (i32.const 32848) "\ecD/\05")
  (data (;2;) (i32.const 32884) "\ff\ff\ff\ff")
  (data (;3;) (i32.const 32920) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;4;) (i32.const 32956) "\e6\02\df\05\8c[\e1\e5\eb\ec}[\d1OqB}\1e\84\f3\dd\03\14\c0\f7\b2)\1e[ \0a\c8\c7\c3\b9%")
  (data (;5;) (i32.const 33020) "\e6\02\df\05")
  (data (;6;) (i32.const 33052) "\ecD/\05\dd\f2R\ad\1b\e2\c8\9bi\c2\b0h\fc7\8d\aa\95+\a7\f1c\c4\a1\16(\f5ZM\f5#\b3\ef")
  (data (;7;) (i32.const 33112) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;8;) (i32.const 33148) "\ecD/\05\dd\f2R\ad\1b\e2\c8\9bi\c2\b0h\fc7\8d\aa\95+\a7\f1c\c4\a1\16(\f5ZM\f5#\b3\ef")
  (data (;9;) (i32.const 33304) "\01\00\00\000\82\00\000\c2")
  (data (;10;) (i32.const 33321) "@")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "producers" "\02\08language\01\03C99\00\0cprocessed-by\02\05clangV11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\0eHomebrew clang\0616.0.6")
  (@custom "name" "\01\a4\095\00\0fgetCallDataSize\01\0ccallDataCopy\02\09getCaller\03\0cgetCallValue\04\06revert\05\06finish\06\0bgetCodeSize\07\08codeCopy\08\18storageStoreLittleEndian\09\17storageLoadLittleEndian\0a\09keccak256\0b\0cemitLogEvent\0c\11__wasm_call_ctors\0d\1au256_from_big_endian_bytes\0e\18u256_to_big_endian_bytes\0f\1bi32_from_big_endian_bytes32\10\1cwrapper_calldataload_bytes32\11\1ewrapper_calldata_load_selector\12\15wrapper_calldata_size\13\0ewrapper_caller\14\1awrapper_callvalue_not_zero\15\0ewrapper_revert\16\13evm_get_memory_addr\17\10wrapper_codecopy\18\14wrapper_memory_guard\19\16wrapper_mstore_bytes32\1a\13wrapper_mstore_u256\1b\12wrapper_mstore_u32\1c\12wrapper_mload_u256\1d\15wrapper_mload_bytes32\1e/wrapper_sstore_u256_using_little_endian_hostapi\1f.wrapper_sload_u256_using_little_endian_hostapi \11wrapper_keccak256!\0ewrapper_return\22\0cwrapper_log3#\13set_is_deploying_tx$\22wrapper_current_contract_code_size%+wrapper_current_contract_pure_contract_size&\11wrapper_data_copy'\1dwrapper_calldata_size_minus_4(\19wrapper_set_memptr_global)\19wrapper_get_memptr_global*$wrapper_optimized_erc20_fun_transfer+\0f__init_evm_heap,\16wrapper_bytes32_iszero-\13wrapper_bytes32_and.\10wrapper_u256_shl/\10wrapper_u256_shr04GLDToken_48477_deployed.GLDToken_48477_deployed.init1\04call2\06_start3\22GLDToken_48477.GLDToken_48477.init4\06deploy\07\12\01\00\0f__stack_pointer\09\11\02\00\07.rodata\01\05.data")
  (@custom ".debug_str" "y\00x\00low\00wasisdk://v12.0/build/compiler-rt\00du_int\00ti_int\00di_int\00long long int\00long long unsigned int\00uint64_t\00twords\00r\00all\00lower_mask\00high\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins/multi3.c\00b\00a\00__int128\00__multi3\00__mulddi3\00bits_in_dword_2\00clang version 11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\00")
  (@custom ".debug_line" "M\01\00\00\04\00\c2\00\00\00\01\01\01\fb\0e\0d\00\01\01\01\01\00\00\00\01\00\00\01wasisdk://v12.0/build/install/opt/wasi-sdk/share/wasi-sysroot/include/bits\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins\00\00alltypes.h\00\01\00\00int_types.h\00\02\00\00multi3.c\00\02\00\00\00\04\03\00\05\02\ff\ff\ff\ff\03'\01\05\03\0aD\05,-\05\18\06X\05\0c\06\03rX\05\0b\1eo\05&`\05\0c\06<\05#\06\03u \05\10\06\ac\05\1e\90\03i<\05\16\06\03\18J\05\1f\22\05\05\06X\03f \05\10\06\03\1cJ\05\22\03\13 \05\0f\03n \05\1f\92\05\05\06X\03a \05\11\06\03!J\05\0c\03\0e \05\03!\05\1f\03pX\05\0b\03yX\97\05\03\03\10 \02\04\00\01\01")
  (@custom ".debug_abbrev" "\01\11\01%\0e\13\05\03\0e\10\17\1b\0e\11\01\12\06\00\00\02$\00\03\0e>\0b\0b\0b\00\00\03\16\00I\13\03\0e:\0b;\0b\00\00\04.\01\03\0e:\0b;\0b'\19I\13 \0b\00\00\05\05\00\03\0e:\0b;\0bI\13\00\00\064\00\03\0e:\0b;\0bI\13\00\00\07\17\01\0b\0b:\0b;\0b\00\00\08\0d\00\03\0eI\13:\0b;\0b8\0b\00\00\09\13\01\0b\0b:\0b;\0b\00\00\0a&\00I\13\00\00\0b.\01\11\01\12\06@\18\97B\19\03\0e:\0b;\0b'\19I\13?\19\00\00\0c\05\00\02\17\03\0e:\0b;\0bI\13\00\00\0d4\00\02\17\03\0e:\0b;\0bI\13\00\00\0e\1d\011\13U\17X\0bY\0bW\0b\00\00\0f\05\001\13\00\00\104\00\02\171\13\00\00\114\00\1c\0d1\13\00\00\124\00\1c\0f1\13\00\00\00")
  (@custom ".debug_ranges" "\0f\00\00\00G\00\00\00H\00\00\00\5c\00\00\00b\00\00\00q\00\00\00\00\00\00\00\00\00\00\00")
  (@custom ".debug_loc" "\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\007\00\00\009\00\00\00\06\00\ed\02\02\9f\93\089\00\00\00G\00\00\00\06\00\ed\00\05\9f\93\08G\00\00\00H\00\00\00\0c\00\ed\00\05\9f\93\08\ed\02\02\9f\93\08H\00\00\00p\00\00\00\06\00\ed\00\05\9f\93\08p\00\00\00q\00\00\00\06\00\ed\02\02\9f\93\08q\00\00\00t\00\00\00\06\00\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00]\00\00\00`\00\00\00\08\00\93\08\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00<\00\00\00B\00\00\00\04\00\ed\02\02\9fQ\00\00\00Y\00\00\00\04\00\ed\02\02\9fY\00\00\00u\00\00\00\04\00\ed\00\03\9f\00\00\00\00\00\00\00\00")
  (@custom ".debug_info" "\b4\01\00\00\04\00\00\00\00\00\04\01\fd\00\00\00\0c\00\8a\00\00\00\00\00\00\00\08\00\00\00\ff\ff\ff\ffu\00\00\00\02`\00\00\00\05\04\038\00\00\00*\00\00\00\02&\03C\00\00\00d\00\00\00\01\aa\02M\00\00\00\07\08\04\e3\00\00\00\03\13\99\00\00\00\01\05\cf\00\00\00\03\13-\00\00\00\05\cd\00\00\00\03\13-\00\00\00\06t\00\00\00\03\14\ab\00\00\00\06\ed\00\00\00\03\15\0d\01\00\00\06z\00\00\00\03\16\12\01\00\00\06k\00\00\00\03\18-\00\00\00\00\03\a4\00\00\001\00\00\00\02O\02\d1\00\00\00\05\10\03\b6\00\00\00m\00\00\00\02]\07\10\02R\08v\00\00\00\99\00\00\00\02S\00\08r\00\00\00\d2\00\00\00\02\5c\00\09\10\02T\08\04\00\00\00-\00\00\00\02V\00\08\85\00\00\00\f0\00\00\00\02W\08\00\00\03\fb\00\00\008\00\00\00\02%\03\06\01\00\00e\00\00\00\01\91\02?\00\00\00\05\08\0a&\00\00\00\0a-\00\00\00\0b\ff\ff\ff\ffu\00\00\00\07\ed\03\00\00\00\00\9f\da\00\00\00\03(\99\00\00\00\0c\00\00\00\00\cf\00\00\00\03(\99\00\00\00\0c\14\00\00\00\cd\00\00\00\03(\99\00\00\00\0d(\00\00\00\00\00\00\00\03+\ab\00\00\00\0d\aa\00\00\00\02\00\00\00\03)\ab\00\00\00\0d\be\00\00\00t\00\00\00\03-\ab\00\00\00\0eJ\00\00\00\00\00\00\00\03.\0b\0fV\00\00\00\0fa\00\00\00\10<\00\00\00l\00\00\00\11 w\00\00\00\12\ff\ff\ff\ff\0f\82\00\00\00\10\d8\00\00\00\8d\00\00\00\00\00\00"))
