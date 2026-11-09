(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32 i32)))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func (param i64 i32 i32 i32) (result i32)))
  (type (;5;) (func (result i64)))
  (type (;6;) (func (param i32 i32 i32 i32)))
  (type (;7;) (func))
  (type (;8;) (func (param i32 i64 i64 i64 i64)))
  (type (;9;) (func (param i32) (result i32)))
  (type (;10;) (func (param i32 i32 i32) (result i32)))
  (type (;11;) (func (param i64 i32 i32 i32 i32 i32) (result i32)))
  (type (;12;) (func (param i32 i32) (result i32)))
  (type (;13;) (func (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)))
  (type (;14;) (func (param i32 i64 i64 i64 i64 i64 i64 i64 i64)))
  (type (;15;) (func (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)))
  (type (;16;) (func (param i64 i64 i64 i64 i64 i64 i64 i64)))
  (type (;17;) (func (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)))
  (import "env" "getCallDataSize" (func $getCallDataSize (type 0)))
  (import "env" "callDataCopy" (func $callDataCopy (type 1)))
  (import "env" "getCallValue" (func $getCallValue (type 2)))
  (import "env" "revert" (func $revert (type 3)))
  (import "env" "finish" (func $finish (type 3)))
  (import "env" "getCodeSize" (func $getCodeSize (type 0)))
  (import "env" "codeCopy" (func $codeCopy (type 1)))
  (import "env" "getReturnDataSize" (func $getReturnDataSize (type 0)))
  (import "env" "returnDataCopy" (func $returnDataCopy (type 1)))
  (import "env" "callStatic" (func $callStatic (type 4)))
  (import "env" "getGasLeft" (func $getGasLeft (type 5)))
  (import "env" "addmod" (func $addmod (type 6)))
  (import "env" "mulmod" (func $mulmod (type 6)))
  (func $__wasm_call_ctors (type 7))
  (func $__multi3 (type 8) (param i32 i64 i64 i64 i64)
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
  (func $i32_from_big_endian_bytes32 (type 9) (param i32) (result i32)
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
      i32.load offset=65616
      local.tee 2
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 2
      i32.store offset=65616
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
              i32.store offset=65616
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
              i32.load8_u offset=67252
              br_if 0 (;@5;)
              i32.const 67152
              i32.const 0
              local.get 3
              call $callDataCopy
              i32.const 0
              i32.const 1
              i32.store8 offset=67252
            end
            local.get 4
            i32.eqz
            br_if 2 (;@2;)
            local.get 0
            i32.const 67152
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
            i32.store offset=65616
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
            i32.load8_u offset=67252
            br_if 0 (;@4;)
            i32.const 67152
            i32.const 0
            local.get 2
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=67252
          end
          local.get 1
          local.get 0
          i32.const 67152
          i32.add
          i32.load8_u
          i32.store8
          local.get 1
          local.get 0
          i32.const 67153
          i32.add
          i32.load8_u
          i32.store8 offset=1
          local.get 1
          local.get 0
          i32.const 67154
          i32.add
          i32.load8_u
          i32.store8 offset=2
          local.get 1
          local.get 0
          i32.const 67155
          i32.add
          i32.load8_u
          i32.store8 offset=3
          local.get 1
          local.get 0
          i32.const 67156
          i32.add
          i32.load8_u
          i32.store8 offset=4
          local.get 1
          local.get 0
          i32.const 67157
          i32.add
          i32.load8_u
          i32.store8 offset=5
          local.get 1
          local.get 0
          i32.const 67158
          i32.add
          i32.load8_u
          i32.store8 offset=6
          local.get 1
          local.get 0
          i32.const 67159
          i32.add
          i32.load8_u
          i32.store8 offset=7
          local.get 1
          local.get 0
          i32.const 67160
          i32.add
          i32.load8_u
          i32.store8 offset=8
          local.get 1
          local.get 0
          i32.const 67161
          i32.add
          i32.load8_u
          i32.store8 offset=9
          local.get 1
          local.get 0
          i32.const 67162
          i32.add
          i32.load8_u
          i32.store8 offset=10
          local.get 1
          local.get 0
          i32.const 67163
          i32.add
          i32.load8_u
          i32.store8 offset=11
          local.get 1
          local.get 0
          i32.const 67164
          i32.add
          i32.load8_u
          i32.store8 offset=12
          local.get 1
          local.get 0
          i32.const 67165
          i32.add
          i32.load8_u
          i32.store8 offset=13
          local.get 1
          local.get 0
          i32.const 67166
          i32.add
          i32.load8_u
          i32.store8 offset=14
          local.get 1
          local.get 0
          i32.const 67167
          i32.add
          i32.load8_u
          i32.store8 offset=15
          local.get 1
          local.get 0
          i32.const 67168
          i32.add
          i32.load8_u
          i32.store8 offset=16
          local.get 1
          local.get 0
          i32.const 67169
          i32.add
          i32.load8_u
          i32.store8 offset=17
          local.get 1
          local.get 0
          i32.const 67170
          i32.add
          i32.load8_u
          i32.store8 offset=18
          local.get 1
          local.get 0
          i32.const 67171
          i32.add
          i32.load8_u
          i32.store8 offset=19
          local.get 1
          local.get 0
          i32.const 67172
          i32.add
          i32.load8_u
          i32.store8 offset=20
          local.get 1
          local.get 0
          i32.const 67173
          i32.add
          i32.load8_u
          i32.store8 offset=21
          local.get 1
          local.get 0
          i32.const 67174
          i32.add
          i32.load8_u
          i32.store8 offset=22
          local.get 1
          local.get 0
          i32.const 67175
          i32.add
          i32.load8_u
          i32.store8 offset=23
          local.get 1
          local.get 0
          i32.const 67176
          i32.add
          i32.load8_u
          i32.store8 offset=24
          local.get 1
          local.get 0
          i32.const 67177
          i32.add
          i32.load8_u
          i32.store8 offset=25
          local.get 1
          local.get 0
          i32.const 67178
          i32.add
          i32.load8_u
          i32.store8 offset=26
          local.get 1
          local.get 0
          i32.const 67179
          i32.add
          i32.load8_u
          i32.store8 offset=27
          local.get 1
          local.get 0
          i32.const 67180
          i32.add
          i32.load8_u
          i32.store8 offset=28
          local.get 1
          local.get 0
          i32.const 67181
          i32.add
          i32.load8_u
          i32.store8 offset=29
          local.get 1
          local.get 0
          i32.const 67182
          i32.add
          i32.load8_u
          i32.store8 offset=30
          local.get 1
          local.get 0
          i32.const 67183
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
      i32.load offset=65616
      local.tee 0
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 0
      i32.store offset=65616
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
    i32.load offset=67260
    local.get 0
    i32.add
    local.get 1
    call $revert)
  (func $evm_get_memory_addr (type 9) (param i32) (result i32)
    i32.const 0
    i32.load offset=67260
    local.get 0
    i32.add)
  (func $wrapper_codecopy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=67272
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
        i32.store offset=67268
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=67272
        i32.const 0
        i32.const 0
        i32.load offset=67264
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=67264
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=67268
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=67268
    end
    i32.const 0
    i32.load offset=67260
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
          i32.load offset=65616
          local.tee 1
          i32.const -1
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 0
          call $getCallDataSize
          local.tee 1
          i32.store offset=65616
          local.get 1
          i32.const -1
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 0
          call $getCallDataSize
          local.tee 1
          i32.store offset=65616
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
          i32.load8_u offset=67252
          br_if 0 (;@3;)
          i32.const 67152
          i32.const 0
          local.get 1
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=67252
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.const 67152
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
  (func $wrapper_memory_guard (type 9) (param i32) (result i32)
    (local i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=67272
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
      i32.store offset=67268
      i32.const 0
      local.get 2
      i32.const -65536
      i32.and
      i32.store offset=67272
      i32.const 0
      i32.const 0
      i32.load offset=67264
      local.get 1
      i32.const 16
      i32.shl
      i32.add
      i32.store offset=67264
      i32.const 96
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=67268
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 0
      i32.store offset=67268
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
          i32.load offset=67272
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
          i32.store offset=67268
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=67272
          i32.const 0
          i32.const 0
          i32.load offset=67264
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67264
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67268
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=67268
      end
      i32.const 0
      i32.load offset=67260
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
          i32.load offset=67272
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
          i32.store offset=67268
          i32.const 0
          local.get 7
          i32.const -65536
          i32.and
          i32.store offset=67272
          i32.const 0
          i32.const 0
          i32.load offset=67264
          local.get 1
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67264
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67268
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=67268
      end
      i32.const 0
      i32.load offset=67260
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
          i32.load offset=67272
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
          i32.store offset=67268
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=67272
          i32.const 0
          i32.const 0
          i32.load offset=67264
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67264
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67268
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=67268
      end
      i32.const 0
      i32.load offset=67260
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
    i32.load offset=67260
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
    i32.load offset=67260
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
    i32.load offset=67260
    local.get 0
    i32.add
    local.get 1
    call $finish)
  (func $write_call_data (type 10) (param i32 i32 i32) (result i32)
    (local i32 i32 i32)
    block  ;; label = @1
      local.get 0
      i32.const 2
      i32.ne
      br_if 0 (;@1;)
      i32.const 65561
      i32.const 20
      call $revert
      i32.const 0
      return
    end
    block  ;; label = @1
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        call $getReturnDataSize
        local.tee 3
        local.get 2
        i32.ge_s
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 0
          br_if 0 (;@3;)
          block  ;; label = @4
            block  ;; label = @5
              i32.const 0
              i32.load offset=67272
              local.tee 2
              local.get 3
              local.get 1
              i32.add
              local.tee 0
              i32.ge_u
              br_if 0 (;@5;)
              local.get 0
              i32.const 65535
              i32.add
              local.tee 4
              i32.const 16
              i32.shr_u
              local.get 2
              i32.const 16
              i32.shr_u
              i32.sub
              local.tee 2
              memory.grow
              drop
              i32.const 0
              local.get 0
              i32.store offset=67268
              i32.const 0
              local.get 4
              i32.const -65536
              i32.and
              i32.store offset=67272
              i32.const 0
              i32.const 0
              i32.load offset=67264
              local.get 2
              i32.const 16
              i32.shl
              i32.add
              i32.store offset=67264
              br 1 (;@4;)
            end
            i32.const 0
            i32.load offset=67268
            local.get 0
            i32.ge_u
            br_if 0 (;@4;)
            i32.const 0
            local.get 0
            i32.store offset=67268
          end
          i32.const 0
          i32.load offset=67260
          local.get 1
          i32.add
          i32.const 0
          local.get 3
          call $returnDataCopy
          i32.const 1
          return
        end
        block  ;; label = @3
          local.get 3
          br_if 0 (;@3;)
          i32.const 65582
          i32.const 31
          call $revert
          local.get 0
          i32.eqz
          return
        end
        block  ;; label = @3
          local.get 3
          i32.const 1024
          i32.gt_s
          br_if 0 (;@3;)
          i32.const 66112
          i32.const 0
          local.get 3
          call $returnDataCopy
          i32.const 66112
          local.get 3
          call $revert
          local.get 0
          i32.eqz
          return
        end
        i32.const 65536
        i32.const 24
        call $revert
        local.get 0
        i32.eqz
        return
      end
      block  ;; label = @2
        block  ;; label = @3
          i32.const 0
          i32.load offset=67272
          local.tee 4
          local.get 2
          local.get 1
          i32.add
          local.tee 3
          i32.ge_u
          br_if 0 (;@3;)
          local.get 3
          i32.const 65535
          i32.add
          local.tee 5
          i32.const 16
          i32.shr_u
          local.get 4
          i32.const 16
          i32.shr_u
          i32.sub
          local.tee 4
          memory.grow
          drop
          i32.const 0
          local.get 3
          i32.store offset=67268
          i32.const 0
          local.get 5
          i32.const -65536
          i32.and
          i32.store offset=67272
          i32.const 0
          i32.const 0
          i32.load offset=67264
          local.get 4
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67264
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67268
        local.get 3
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 3
        i32.store offset=67268
      end
      i32.const 0
      i32.load offset=67260
      local.get 1
      i32.add
      i32.const 0
      local.get 2
      call $returnDataCopy
    end
    local.get 0
    i32.eqz)
  (func $wrapper_staticcall (type 11) (param i64 i32 i32 i32 i32 i32) (result i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        local.get 1
        i32.const 12
        i32.add
        i32.const 0
        i32.load offset=67260
        local.get 2
        i32.add
        local.get 3
        call $callStatic
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i64.load
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        local.get 1
        i64.load offset=8
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        local.get 1
        i64.load offset=16
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        local.get 1
        i32.load8_u offset=24
        br_if 0 (;@2;)
        local.get 1
        i32.load8_u offset=25
        br_if 0 (;@2;)
        local.get 1
        i32.load8_u offset=26
        br_if 0 (;@2;)
        local.get 1
        i32.load8_u offset=27
        br_if 0 (;@2;)
        local.get 1
        i32.load8_u offset=28
        br_if 0 (;@2;)
        local.get 1
        i32.load8_u offset=29
        br_if 0 (;@2;)
        local.get 1
        i32.load8_u offset=30
        br_if 0 (;@2;)
        i32.const 0
        local.set 2
        local.get 1
        i32.load8_u offset=31
        i32.const -11
        i32.add
        i32.const 255
        i32.and
        i32.const 245
        i32.gt_u
        br_if 1 (;@1;)
      end
      local.get 3
      local.get 4
      local.get 5
      call $write_call_data
      local.set 2
    end
    local.get 2)
  (func $wrapper_gas (type 5) (result i64)
    call $getGasLeft)
  (func $set_is_deploying_tx (type 7)
    i32.const 0
    i32.const 1
    i32.store8 offset=67136)
  (func $wrapper_addmod (type 6) (param i32 i32 i32 i32)
    local.get 0
    local.get 1
    local.get 2
    local.get 3
    call $addmod)
  (func $wrapper_mulmod (type 6) (param i32 i32 i32 i32)
    local.get 0
    local.get 1
    local.get 2
    local.get 3
    call $mulmod)
  (func $__init_evm_heap (type 2) (param i32)
    (local i32)
    block  ;; label = @1
      i32.const 0
      i32.load8_u offset=67256
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
          i32.store offset=67260
          i32.const 1
          memory.grow
          drop
          memory.size
          i32.const 16
          i32.shl
          local.tee 0
          i32.const 0
          i32.load offset=67260
          i32.sub
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 67280
        i32.store offset=67260
        i32.const 83664
        local.set 0
        i32.const 16384
        local.set 1
      end
      i32.const 0
      local.get 0
      i32.store offset=67264
      i32.const 0
      local.get 1
      i32.store offset=67272
      i32.const 0
      i32.const 1
      i32.store8 offset=67256
      i32.const 0
      i32.const 0
      i32.store offset=67268
    end)
  (func $wrapper_bytes32_eq (type 12) (param i32 i32) (result i32)
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
  (func $wrapper_bytes32_iszero (type 9) (param i32) (result i32)
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
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_test_ecdsa_verify_p256_51 (type 2) (param i32)
    (local i32 i32 i64 i32 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    i32.const 65664
    local.get 1
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    local.get 1
    i32.const 64
    i32.add
    i32.const 0
    local.get 1
    i32.const 32
    i32.add
    call $wrapper_u256_shl
    local.get 1
    i32.const 32
    i32.add
    i32.const 24
    i32.add
    local.tee 2
    i64.load
    local.set 3
    local.get 1
    i32.const 32
    i32.add
    i32.const 16
    i32.add
    local.tee 4
    i64.load
    local.set 5
    local.get 1
    i32.const 32
    i32.add
    i32.const 8
    i32.add
    local.tee 6
    i64.load
    local.set 7
    local.get 1
    i64.load offset=32
    local.set 8
    i32.const 65696
    local.get 1
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    local.get 1
    i32.const 64
    i32.add
    i32.const 0
    local.get 1
    i32.const 32
    i32.add
    call $wrapper_u256_shl
    local.get 2
    i64.load
    local.set 9
    local.get 4
    i64.load
    local.set 10
    local.get 6
    i64.load
    local.set 11
    local.get 1
    i64.load offset=32
    local.set 12
    i32.const 65728
    local.get 1
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    local.get 1
    i32.const 64
    i32.add
    i32.const 0
    local.get 1
    i32.const 32
    i32.add
    call $wrapper_u256_shl
    local.get 2
    i64.load
    local.set 13
    local.get 4
    i64.load
    local.set 14
    local.get 6
    i64.load
    local.set 15
    local.get 1
    i64.load offset=32
    local.set 16
    i32.const 65760
    local.get 1
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    local.get 1
    i32.const 64
    i32.add
    i32.const 0
    local.get 1
    i32.const 32
    i32.add
    call $wrapper_u256_shl
    local.get 2
    i64.load
    local.set 17
    local.get 4
    i64.load
    local.set 18
    local.get 6
    i64.load
    local.set 19
    local.get 1
    i64.load offset=32
    local.set 20
    i32.const 65792
    local.get 1
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    local.get 1
    i32.const 64
    i32.add
    i32.const 0
    local.get 1
    i32.const 32
    i32.add
    call $wrapper_u256_shl
    local.get 1
    local.get 8
    local.get 7
    local.get 5
    local.get 3
    local.get 12
    local.get 11
    local.get 10
    local.get 9
    local.get 16
    local.get 15
    local.get 14
    local.get 13
    local.get 20
    local.get 19
    local.get 18
    local.get 17
    local.get 1
    i64.load offset=32
    local.get 6
    i64.load
    local.get 4
    i64.load
    local.get 2
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_verifySolidity_2002
    block  ;; label = @1
      local.get 1
      i64.load
      local.tee 3
      local.get 1
      i32.const 16
      i32.add
      i64.load
      local.tee 5
      i64.or
      local.get 1
      i32.const 8
      i32.add
      i64.load
      local.tee 7
      local.get 1
      i32.const 24
      i32.add
      i64.load
      local.tee 8
      i64.or
      i64.or
      i64.const 0
      i64.ne
      br_if 0 (;@1;)
      i32.const 64
      local.get 1
      i32.const 64
      i32.add
      call $wrapper_mload_u256
      local.get 1
      i32.load offset=64
      local.tee 4
      i32.const 65632
      call $wrapper_mstore_bytes32
      local.get 2
      i64.const 0
      i64.store
      local.get 1
      i64.const 0
      i64.store offset=48
      local.get 1
      i64.const 0
      i64.store offset=40
      local.get 1
      i64.const 32
      i64.store offset=32
      local.get 4
      i32.const 4
      i32.add
      local.get 1
      i32.const 32
      i32.add
      call $wrapper_mstore_u256
      local.get 1
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      local.tee 2
      i64.const 0
      i64.store
      local.get 1
      i64.const 0
      i64.store offset=80
      local.get 1
      i64.const 0
      i64.store offset=72
      local.get 1
      i64.const 29
      i64.store offset=64
      local.get 4
      i32.const 36
      i32.add
      local.get 1
      i32.const 64
      i32.add
      call $wrapper_mstore_u256
      local.get 2
      i64.const 6010448901481723250
      i64.store
      local.get 1
      i64.const 7286954375168747113
      i64.store offset=80
      local.get 1
      i64.const 7161132878685675622
      i64.store offset=72
      local.get 1
      i64.const 7019260676958846976
      i64.store offset=64
      local.get 4
      i32.const 68
      i32.add
      local.get 1
      i32.const 64
      i32.add
      call $wrapper_mstore_u256
      local.get 4
      i32.const 100
      call $wrapper_revert
    end
    local.get 0
    local.get 3
    i64.store
    local.get 0
    local.get 7
    i64.store offset=8
    local.get 0
    local.get 5
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 1
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_verifySolidity_2002 (type 13) (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i32 i32 i32 i64 i64 i64 i64 i32 i32 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 480
    i32.sub
    local.tee 21
    global.set $__stack_pointer
    local.get 21
    local.tee 22
    i32.const 448
    i32.add
    i32.const 24
    i32.add
    local.tee 23
    local.get 8
    i64.store
    local.get 22
    local.get 7
    i64.store offset=464
    local.get 22
    local.get 6
    i64.store offset=456
    local.get 22
    local.get 5
    i64.store offset=448
    local.get 22
    i32.const 448
    i32.add
    i32.const 0
    local.get 22
    i32.const 416
    i32.add
    call $wrapper_u256_shr
    block  ;; label = @1
      block  ;; label = @2
        local.get 22
        i64.load offset=416
        local.get 22
        i32.const 416
        i32.add
        i32.const 16
        i32.add
        local.tee 24
        i64.load
        i64.or
        local.get 22
        i32.const 416
        i32.add
        i32.const 8
        i32.add
        local.tee 25
        i64.load
        local.get 22
        i32.const 416
        i32.add
        i32.const 24
        i32.add
        local.tee 26
        i64.load
        i64.or
        i64.or
        i64.eqz
        br_if 0 (;@2;)
        local.get 23
        local.get 8
        i64.store
        local.get 22
        local.get 5
        i64.store offset=448
        local.get 22
        local.get 6
        i64.store offset=456
        local.get 22
        local.get 7
        i64.store offset=464
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 25
        i64.load
        local.set 27
        local.get 24
        i64.load
        local.set 28
        local.get 26
        i64.load
        local.set 29
        local.get 22
        i64.load offset=416
        local.set 30
        i32.const 65824
        local.get 22
        i32.const 448
        i32.add
        call $u256_from_big_endian_bytes
        local.get 30
        local.get 22
        i64.load offset=448
        i64.ge_u
        local.get 27
        local.get 22
        i32.const 448
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 30
        i64.ge_u
        local.get 27
        local.get 30
        i64.eq
        select
        local.get 28
        local.get 22
        i32.const 448
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.tee 30
        i64.ge_u
        local.get 29
        local.get 23
        i64.load
        local.tee 27
        i64.ge_u
        local.get 29
        local.get 27
        i64.eq
        select
        local.get 28
        local.get 30
        i64.xor
        local.get 29
        local.get 27
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        local.get 22
        i32.const 448
        i32.add
        i32.const 24
        i32.add
        local.tee 23
        local.get 12
        i64.store
        local.get 22
        local.get 9
        i64.store offset=448
        local.get 22
        local.get 10
        i64.store offset=456
        local.get 22
        local.get 11
        i64.store offset=464
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 22
        i64.load offset=416
        local.get 22
        i32.const 416
        i32.add
        i32.const 16
        i32.add
        local.tee 24
        i64.load
        i64.or
        local.get 22
        i32.const 416
        i32.add
        i32.const 8
        i32.add
        local.tee 25
        i64.load
        local.get 22
        i32.const 416
        i32.add
        i32.const 24
        i32.add
        local.tee 26
        i64.load
        i64.or
        i64.or
        i64.eqz
        br_if 0 (;@2;)
        local.get 23
        local.get 12
        i64.store
        local.get 22
        local.get 9
        i64.store offset=448
        local.get 22
        local.get 10
        i64.store offset=456
        local.get 22
        local.get 11
        i64.store offset=464
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 25
        i64.load
        local.set 27
        local.get 24
        i64.load
        local.set 28
        local.get 26
        i64.load
        local.set 29
        local.get 22
        i64.load offset=416
        local.set 30
        i32.const 65888
        local.get 22
        i32.const 448
        i32.add
        call $u256_from_big_endian_bytes
        local.get 30
        local.get 22
        i64.load offset=448
        i64.le_u
        local.get 27
        local.get 22
        i32.const 448
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 30
        i64.le_u
        local.get 27
        local.get 30
        i64.eq
        select
        local.get 28
        local.get 22
        i32.const 448
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.tee 30
        i64.le_u
        local.get 29
        local.get 23
        i64.load
        local.tee 27
        i64.le_u
        local.get 29
        local.get 27
        i64.eq
        select
        local.get 28
        local.get 30
        i64.xor
        local.get 29
        local.get 27
        i64.xor
        i64.or
        i64.eqz
        select
        i32.eqz
        br_if 0 (;@2;)
        local.get 22
        i32.const 384
        i32.add
        local.get 13
        local.get 14
        local.get 15
        local.get 16
        local.get 17
        local.get 18
        local.get 19
        local.get 20
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_isValidPublicKey_2179
        local.get 22
        i64.load offset=384
        local.get 22
        i32.const 384
        i32.add
        i32.const 16
        i32.add
        i64.load
        i64.or
        local.get 22
        i32.const 384
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 22
        i32.const 384
        i32.add
        i32.const 24
        i32.add
        i64.load
        i64.or
        i64.or
        i64.eqz
        br_if 0 (;@2;)
        local.get 22
        i32.const 448
        i32.add
        i32.const 24
        i32.add
        local.tee 23
        local.get 16
        i64.store
        local.get 22
        local.get 13
        i64.store offset=448
        local.get 22
        local.get 14
        i64.store offset=456
        local.get 22
        local.get 15
        i64.store offset=464
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 22
        i32.const 416
        i32.add
        i32.const 24
        i32.add
        local.tee 24
        i64.load
        local.set 29
        local.get 22
        i32.const 416
        i32.add
        i32.const 16
        i32.add
        local.tee 25
        i64.load
        local.set 27
        local.get 22
        i32.const 416
        i32.add
        i32.const 8
        i32.add
        local.tee 26
        i64.load
        local.set 28
        local.get 22
        i64.load offset=416
        local.set 30
        local.get 23
        local.get 20
        i64.store
        local.get 22
        local.get 19
        i64.store offset=464
        local.get 22
        local.get 18
        i64.store offset=456
        local.get 22
        local.get 17
        i64.store offset=448
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 22
        i32.const 352
        i32.add
        local.get 30
        local.get 28
        local.get 27
        local.get 29
        local.get 22
        i64.load offset=416
        local.get 26
        i64.load
        local.get 25
        i64.load
        local.get 24
        i64.load
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__preComputeJacobianPoints_2649
        local.get 22
        i32.const 352
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.set 30
        local.get 22
        i32.const 352
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.set 20
        local.get 22
        i32.const 352
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.set 19
        local.get 22
        i64.load offset=352
        local.set 18
        local.get 23
        local.get 12
        i64.store
        local.get 22
        local.get 11
        i64.store offset=464
        local.get 22
        local.get 10
        i64.store offset=456
        local.get 22
        local.get 9
        i64.store offset=448
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 24
        i64.load
        local.set 10
        local.get 25
        i64.load
        local.set 9
        local.get 26
        i64.load
        local.set 17
        local.get 22
        i64.load offset=416
        local.set 16
        i32.const 65824
        local.get 22
        i32.const 448
        i32.add
        call $u256_from_big_endian_bytes
        local.get 22
        i32.const 288
        i32.add
        local.get 16
        local.get 17
        local.get 9
        local.get 10
        local.get 22
        i64.load offset=448
        local.tee 27
        i64.const -2
        i64.add
        local.tee 28
        local.get 22
        i32.const 448
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.tee 29
        local.get 28
        local.get 27
        i64.lt_u
        local.tee 24
        i64.extend_i32_u
        i64.add
        i64.const -1
        i64.add
        local.tee 28
        local.get 22
        i32.const 448
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.tee 12
        i64.const -1
        i64.add
        local.tee 11
        local.get 24
        local.get 28
        local.get 29
        i64.lt_u
        local.get 28
        local.get 29
        i64.eq
        select
        i64.extend_i32_u
        i64.add
        local.tee 28
        local.get 23
        i64.load
        local.tee 15
        local.get 11
        local.get 12
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 28
        local.get 11
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.const -1
        i64.add
        local.get 27
        local.get 29
        local.get 12
        local.get 15
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_tryModExp_905
        local.get 22
        i32.const 344
        i32.add
        i64.load
        local.set 29
        local.get 22
        i32.const 336
        i32.add
        i64.load
        local.set 27
        local.get 22
        i32.const 328
        i32.add
        i64.load
        local.set 28
        local.get 22
        i64.load offset=320
        local.set 12
        block  ;; label = @3
          local.get 22
          i64.load offset=288
          local.get 22
          i32.const 288
          i32.add
          i32.const 16
          i32.add
          i64.load
          i64.or
          local.get 22
          i32.const 288
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.get 22
          i32.const 288
          i32.add
          i32.const 24
          i32.add
          i64.load
          i64.or
          i64.or
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
          i32.const 0
          i32.const 1313373041
          call $wrapper_mstore_u32
          local.get 22
          i32.const 472
          i32.add
          i64.const 0
          i64.store
          local.get 22
          i64.const 0
          i64.store offset=464
          local.get 22
          i64.const 0
          i64.store offset=456
          local.get 22
          i64.const 18
          i64.store offset=448
          i32.const 32
          local.get 22
          i32.const 448
          i32.add
          call $wrapper_mstore_u256
          i32.const 28
          i32.const 36
          call $wrapper_revert
        end
        local.get 22
        i32.const 448
        i32.add
        i32.const 24
        i32.add
        local.tee 24
        local.get 4
        i64.store
        local.get 22
        local.get 1
        i64.store offset=448
        local.get 22
        local.get 2
        i64.store offset=456
        local.get 22
        local.get 3
        i64.store offset=464
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 22
        i32.const 416
        i32.add
        i32.const 24
        i32.add
        local.tee 31
        i64.load
        local.set 11
        local.get 22
        i32.const 416
        i32.add
        i32.const 16
        i32.add
        local.tee 32
        i64.load
        local.set 10
        local.get 22
        i32.const 416
        i32.add
        i32.const 8
        i32.add
        local.tee 33
        i64.load
        local.set 9
        local.get 22
        i64.load offset=416
        local.set 17
        i32.const 65824
        local.get 22
        i32.const 448
        i32.add
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 22
          i64.load offset=448
          local.tee 16
          local.get 22
          i32.const 448
          i32.add
          i32.const 16
          i32.add
          local.tee 34
          i64.load
          local.tee 15
          i64.or
          local.get 22
          i32.const 448
          i32.add
          i32.const 8
          i32.add
          local.tee 35
          i64.load
          local.tee 14
          local.get 24
          i64.load
          local.tee 13
          i64.or
          i64.or
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65856
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 18
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        local.get 21
        i32.const -32
        i32.add
        local.tee 23
        local.tee 21
        global.set $__stack_pointer
        local.get 23
        i32.const 24
        i32.add
        local.get 11
        i64.store
        local.get 23
        local.get 10
        i64.store offset=16
        local.get 23
        local.get 9
        i64.store offset=8
        local.get 23
        local.get 17
        i64.store
        local.get 21
        i32.const -32
        i32.add
        local.tee 21
        local.tee 25
        global.set $__stack_pointer
        local.get 23
        local.get 21
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 23
        local.tee 25
        global.set $__stack_pointer
        local.get 23
        i32.const 24
        i32.add
        local.get 29
        i64.store
        local.get 23
        local.get 27
        i64.store offset=16
        local.get 23
        local.get 28
        i64.store offset=8
        local.get 23
        local.get 12
        i64.store
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 26
        global.set $__stack_pointer
        local.get 23
        local.get 25
        call $u256_to_big_endian_bytes
        local.get 26
        i32.const -32
        i32.add
        local.tee 23
        local.tee 26
        global.set $__stack_pointer
        local.get 23
        i32.const 24
        i32.add
        local.get 13
        i64.store
        local.get 23
        local.get 15
        i64.store offset=16
        local.get 23
        local.get 14
        i64.store offset=8
        local.get 23
        local.get 16
        i64.store
        local.get 26
        i32.const -32
        i32.add
        local.tee 26
        local.tee 36
        global.set $__stack_pointer
        local.get 23
        local.get 26
        call $u256_to_big_endian_bytes
        local.get 36
        i32.const -32
        i32.add
        local.tee 36
        local.tee 23
        global.set $__stack_pointer
        local.get 21
        local.get 25
        local.get 26
        local.get 36
        call $wrapper_mulmod
        local.get 24
        local.get 8
        i64.store
        local.get 22
        local.get 7
        i64.store offset=464
        local.get 22
        local.get 6
        i64.store offset=456
        local.get 22
        local.get 5
        i64.store offset=448
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 31
        i64.load
        local.set 11
        local.get 32
        i64.load
        local.set 10
        local.get 33
        i64.load
        local.set 9
        local.get 22
        i64.load offset=416
        local.set 17
        i32.const 65824
        local.get 22
        i32.const 448
        i32.add
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 22
          i64.load offset=448
          local.tee 16
          local.get 34
          i64.load
          local.tee 15
          i64.or
          local.get 35
          i64.load
          local.tee 14
          local.get 24
          i64.load
          local.tee 13
          i64.or
          i64.or
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65856
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 18
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 21
        global.set $__stack_pointer
        local.get 23
        i32.const 24
        i32.add
        local.get 11
        i64.store
        local.get 23
        local.get 10
        i64.store offset=16
        local.get 23
        local.get 9
        i64.store offset=8
        local.get 23
        local.get 17
        i64.store
        local.get 21
        i32.const -32
        i32.add
        local.tee 21
        local.tee 24
        global.set $__stack_pointer
        local.get 23
        local.get 21
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 23
        local.tee 24
        global.set $__stack_pointer
        local.get 23
        i32.const 24
        i32.add
        local.get 29
        i64.store
        local.get 23
        local.get 27
        i64.store offset=16
        local.get 23
        local.get 28
        i64.store offset=8
        local.get 23
        local.get 12
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 25
        global.set $__stack_pointer
        local.get 23
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 23
        local.tee 25
        global.set $__stack_pointer
        local.get 23
        i32.const 24
        i32.add
        local.get 13
        i64.store
        local.get 23
        local.get 15
        i64.store offset=16
        local.get 23
        local.get 14
        i64.store offset=8
        local.get 23
        local.get 16
        i64.store
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 26
        global.set $__stack_pointer
        local.get 23
        local.get 25
        call $u256_to_big_endian_bytes
        local.get 26
        i32.const -32
        i32.add
        local.tee 26
        local.tee 23
        global.set $__stack_pointer
        local.get 21
        local.get 24
        local.get 25
        local.get 26
        call $wrapper_mulmod
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 21
        global.set $__stack_pointer
        local.get 36
        local.get 23
        call $u256_from_big_endian_bytes
        local.get 23
        i32.const 24
        i32.add
        i64.load
        local.set 29
        local.get 23
        i32.const 16
        i32.add
        i64.load
        local.set 27
        local.get 23
        i32.const 8
        i32.add
        i64.load
        local.set 28
        local.get 23
        i64.load
        local.set 12
        local.get 21
        i32.const -32
        i32.add
        local.tee 23
        global.set $__stack_pointer
        local.get 26
        local.get 23
        call $u256_from_big_endian_bytes
        local.get 22
        i32.const 224
        i32.add
        local.get 18
        local.get 19
        local.get 20
        local.get 30
        local.get 12
        local.get 28
        local.get 27
        local.get 29
        local.get 23
        i64.load
        local.get 23
        i32.const 8
        i32.add
        i64.load
        local.get 23
        i32.const 16
        i32.add
        i64.load
        local.get 23
        i32.const 24
        i32.add
        i64.load
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jMultShamir_2442
        local.get 22
        i32.const 224
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.set 37
        local.get 22
        i32.const 224
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.set 38
        local.get 22
        i32.const 224
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.set 39
        local.get 22
        i64.load offset=224
        local.set 40
        i32.const 65824
        local.get 22
        i32.const 448
        i32.add
        call $u256_from_big_endian_bytes
        block  ;; label = @3
          local.get 22
          i64.load offset=448
          local.tee 41
          local.get 22
          i32.const 448
          i32.add
          i32.const 16
          i32.add
          i64.load
          local.tee 42
          i64.or
          local.get 22
          i32.const 448
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.tee 43
          local.get 22
          i32.const 448
          i32.add
          i32.const 24
          i32.add
          i64.load
          local.tee 44
          i64.or
          i64.or
          local.tee 27
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
          i32.const 0
          i32.const 65856
          call $wrapper_mstore_bytes32
          i32.const 4
          i32.const 18
          call $wrapper_mstore_u32
          i32.const 0
          i32.const 36
          call $wrapper_revert
        end
        i64.const 0
        local.set 29
        i64.const 0
        local.get 37
        local.get 27
        i64.eqz
        local.get 40
        local.get 38
        i64.or
        local.get 39
        local.get 37
        i64.or
        i64.or
        i64.eqz
        i32.or
        i64.const 0
        local.get 44
        i64.clz
        local.get 42
        i64.clz
        i64.const 64
        i64.add
        local.get 44
        i64.const 0
        i64.ne
        select
        local.get 43
        i64.clz
        local.get 41
        i64.clz
        i64.const 64
        i64.add
        local.get 43
        i64.const 0
        i64.ne
        select
        local.tee 27
        i64.const 128
        i64.add
        local.tee 28
        local.get 42
        local.get 44
        i64.or
        i64.const 0
        i64.ne
        local.tee 23
        select
        local.tee 12
        local.get 37
        i64.clz
        local.get 38
        i64.clz
        i64.const 64
        i64.add
        local.get 37
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
        local.tee 11
        i64.const 128
        i64.add
        local.tee 10
        local.get 38
        local.get 37
        i64.or
        i64.const 0
        i64.ne
        local.tee 21
        select
        local.tee 9
        i64.lt_u
        local.tee 24
        i64.const 0
        local.get 28
        local.get 27
        i64.lt_u
        i64.extend_i32_u
        local.get 23
        select
        local.tee 27
        i64.const 0
        local.get 10
        local.get 11
        i64.lt_u
        i64.extend_i32_u
        local.get 21
        select
        local.tee 28
        i64.lt_u
        local.get 27
        local.get 28
        i64.eq
        select
        local.tee 23
        i64.extend_i32_u
        i64.sub
        local.tee 16
        i64.const 0
        i64.ne
        i64.const 0
        local.get 23
        i32.const 0
        i32.ne
        i64.extend_i32_u
        i64.sub
        local.tee 17
        i64.const 0
        i64.ne
        local.get 17
        i64.eqz
        select
        local.get 12
        local.get 9
        i64.sub
        local.tee 18
        i64.const 255
        i64.gt_u
        local.get 27
        local.get 28
        i64.sub
        local.get 24
        i64.extend_i32_u
        i64.sub
        local.tee 11
        i64.const 0
        i64.ne
        local.get 11
        i64.eqz
        select
        local.get 23
        select
        i32.or
        local.tee 23
        select
        local.set 12
        i64.const 0
        local.get 38
        local.get 23
        select
        local.set 10
        i64.const 0
        local.get 39
        local.get 23
        select
        local.set 27
        i64.const 0
        local.get 40
        local.get 23
        select
        local.set 28
        block  ;; label = @3
          local.get 23
          br_if 0 (;@3;)
          local.get 18
          i64.const 255
          i64.xor
          local.get 16
          i64.or
          local.get 11
          local.get 17
          i64.or
          i64.or
          i64.eqz
          br_if 0 (;@3;)
          local.get 22
          i32.const 160
          i32.add
          i32.const 40
          i32.add
          local.get 39
          i64.store align=1
          local.get 22
          i32.const 192
          i32.add
          local.tee 23
          local.get 40
          i64.store align=1
          i64.const 0
          local.set 45
          local.get 22
          i32.const 160
          i32.add
          i32.const 24
          i32.add
          i64.const 0
          i64.store align=1
          local.get 22
          i32.const 160
          i32.add
          i32.const 48
          i32.add
          local.get 38
          i64.store align=1
          local.get 22
          i32.const 160
          i32.add
          i32.const 56
          i32.add
          local.get 37
          i64.store align=1
          local.get 22
          i64.const 0
          i64.store offset=176 align=1
          local.get 22
          i64.const 0
          i64.store offset=168 align=1
          local.get 22
          i64.const 0
          i64.store offset=160 align=1
          local.get 23
          i32.const 255
          local.get 18
          i32.wrap_i64
          i32.sub
          local.tee 21
          i32.const 3
          i32.shr_u
          i32.const 31
          i32.and
          i32.sub
          local.tee 23
          i32.const 8
          i32.add
          i64.load align=1
          local.tee 28
          local.get 21
          i32.const 7
          i32.and
          local.tee 21
          i64.extend_i32_u
          local.tee 27
          i64.shl
          local.get 23
          i64.load align=1
          local.tee 12
          i64.const 1
          i64.shr_u
          local.get 21
          i32.const 63
          i32.xor
          i64.extend_i32_u
          local.tee 10
          i64.shr_u
          i64.or
          local.set 9
          local.get 23
          i32.const 24
          i32.add
          i64.load align=1
          local.get 27
          i64.shl
          local.get 23
          i32.const 16
          i32.add
          i64.load align=1
          local.tee 30
          i64.const 1
          i64.shr_u
          local.get 10
          i64.shr_u
          i64.or
          local.set 19
          local.get 30
          local.get 27
          i64.shl
          local.get 28
          i64.const 1
          i64.shr_u
          local.get 21
          i32.const -1
          i32.xor
          i32.const 63
          i32.and
          i64.extend_i32_u
          i64.shr_u
          i64.or
          local.set 30
          local.get 12
          local.get 27
          i64.shl
          local.set 20
          block  ;; label = @4
            block  ;; label = @5
              local.get 18
              i64.const 1
              i64.add
              local.tee 10
              local.get 16
              local.get 10
              local.get 18
              i64.lt_u
              local.tee 23
              local.get 11
              local.get 23
              i64.extend_i32_u
              i64.add
              local.tee 12
              local.get 11
              i64.lt_u
              local.get 10
              local.get 18
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 18
              i64.or
              local.get 12
              local.get 17
              local.get 18
              local.get 16
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.tee 4
              i64.or
              i64.or
              i64.eqz
              br_if 0 (;@5;)
              i64.const 0
              local.set 46
              local.get 22
              i32.const 96
              i32.add
              i32.const 56
              i32.add
              i64.const 0
              i64.store align=1
              local.get 22
              i32.const 96
              i32.add
              i32.const 48
              i32.add
              i64.const 0
              i64.store align=1
              local.get 22
              i32.const 96
              i32.add
              i32.const 40
              i32.add
              i64.const 0
              i64.store align=1
              local.get 22
              i32.const 96
              i32.add
              i32.const 24
              i32.add
              local.get 37
              i64.store align=1
              local.get 22
              i64.const 0
              i64.store offset=128 align=1
              local.get 22
              local.get 40
              i64.store offset=96 align=1
              local.get 22
              local.get 39
              i64.store offset=104 align=1
              local.get 22
              local.get 38
              i64.store offset=112 align=1
              local.get 22
              i32.const 96
              i32.add
              local.get 10
              i32.wrap_i64
              local.tee 21
              i32.const 3
              i32.shr_u
              i32.const 31
              i32.and
              i32.add
              local.tee 23
              i32.const 16
              i32.add
              i64.load align=1
              local.tee 28
              local.get 10
              i64.const 7
              i64.and
              local.tee 27
              i64.shr_u
              local.get 23
              i32.const 24
              i32.add
              i64.load align=1
              local.tee 11
              i64.const 1
              i64.shl
              local.get 21
              i32.const 7
              i32.and
              local.tee 21
              i32.const 63
              i32.xor
              i64.extend_i32_u
              local.tee 15
              i64.shl
              i64.or
              local.set 17
              local.get 23
              i32.const 8
              i32.add
              i64.load align=1
              local.tee 14
              local.get 27
              i64.shr_u
              local.get 28
              i64.const 1
              i64.shl
              local.get 21
              i32.const -1
              i32.xor
              i32.const 63
              i32.and
              i64.extend_i32_u
              i64.shl
              i64.or
              local.set 16
              local.get 23
              i64.load align=1
              local.get 27
              i64.shr_u
              local.get 14
              i64.const 1
              i64.shl
              local.get 15
              i64.shl
              i64.or
              local.set 15
              local.get 44
              local.get 42
              i64.const -1
              i64.add
              local.tee 28
              local.get 42
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.get 28
              local.get 41
              i64.const -1
              i64.add
              local.tee 47
              local.get 41
              i64.lt_u
              local.tee 23
              local.get 43
              local.get 23
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.tee 13
              local.get 43
              i64.lt_u
              local.get 13
              local.get 43
              i64.eq
              select
              i64.extend_i32_u
              i64.add
              local.tee 3
              local.get 28
              i64.lt_u
              i64.extend_i32_u
              i64.add
              i64.const -1
              i64.add
              local.set 48
              local.get 11
              local.get 27
              i64.shr_u
              local.set 2
              i64.const 0
              local.set 1
              loop  ;; label = @6
                local.get 17
                i64.const 1
                i64.shl
                local.get 16
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 11
                local.get 48
                local.get 2
                i64.const 1
                i64.shl
                local.get 17
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 2
                i64.sub
                local.get 3
                local.get 11
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.get 3
                local.get 11
                i64.sub
                local.get 47
                local.get 15
                i64.const 1
                i64.shl
                local.get 19
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 14
                i64.lt_u
                local.get 13
                local.get 16
                i64.const 1
                i64.shl
                local.get 15
                i64.const 63
                i64.shr_u
                i64.or
                local.tee 27
                i64.lt_u
                local.get 13
                local.get 27
                i64.eq
                select
                i64.extend_i32_u
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                i64.const 63
                i64.shr_s
                local.tee 28
                local.get 42
                i64.and
                local.tee 15
                i64.sub
                local.tee 49
                local.get 14
                local.get 28
                local.get 41
                i64.and
                local.tee 50
                i64.lt_u
                local.tee 23
                local.get 27
                local.get 28
                local.get 43
                i64.and
                local.tee 16
                i64.lt_u
                local.get 27
                local.get 16
                i64.eq
                select
                i64.extend_i32_u
                local.tee 45
                i64.sub
                local.set 17
                local.get 2
                local.get 28
                local.get 44
                i64.and
                i64.sub
                local.get 11
                local.get 15
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.get 49
                local.get 45
                i64.lt_u
                i64.extend_i32_u
                i64.sub
                local.set 2
                local.get 27
                local.get 16
                i64.sub
                local.get 23
                i64.extend_i32_u
                i64.sub
                local.set 16
                local.get 14
                local.get 50
                i64.sub
                local.set 15
                local.get 12
                local.get 10
                i64.const -1
                i64.add
                local.tee 11
                local.get 10
                i64.lt_u
                local.tee 23
                i64.extend_i32_u
                i64.add
                i64.const -1
                i64.add
                local.tee 27
                local.get 12
                i64.eq
                local.set 21
                local.get 27
                local.get 12
                i64.lt_u
                local.set 24
                local.get 18
                i64.const -1
                i64.add
                local.tee 14
                local.get 18
                i64.lt_u
                local.set 25
                local.get 20
                i64.const 63
                i64.shr_u
                local.set 49
                local.get 9
                i64.const 63
                i64.shr_u
                local.set 50
                i64.const 0
                local.get 19
                i64.const 1
                i64.shl
                local.get 30
                i64.const 63
                i64.shr_u
                i64.or
                i64.or
                local.set 19
                local.get 1
                local.get 20
                i64.const 1
                i64.shl
                i64.or
                local.set 20
                local.get 28
                i64.const 1
                i64.and
                local.tee 45
                local.set 1
                local.get 11
                local.set 10
                local.get 27
                local.set 12
                local.get 14
                local.get 23
                local.get 24
                local.get 21
                select
                i64.extend_i32_u
                i64.add
                local.tee 28
                local.set 18
                i64.const 0
                local.get 49
                local.get 9
                i64.const 1
                i64.shl
                i64.or
                i64.or
                local.tee 49
                local.set 9
                i64.const 0
                local.get 50
                local.get 30
                i64.const 1
                i64.shl
                i64.or
                i64.or
                local.tee 50
                local.set 30
                local.get 11
                local.get 28
                i64.or
                local.get 27
                local.get 4
                local.get 25
                i64.extend_i32_u
                i64.add
                local.get 28
                local.get 14
                i64.lt_u
                i64.extend_i32_u
                i64.add
                i64.const -1
                i64.add
                local.tee 4
                i64.or
                i64.or
                i64.eqz
                i32.eqz
                br_if 0 (;@6;)
              end
              i64.const 0
              local.set 28
              i64.const 0
              local.set 12
              local.get 49
              local.set 9
              local.get 50
              local.set 30
              br 1 (;@4;)
            end
            i64.const 0
            local.set 46
            i64.const 0
            local.set 28
            i64.const 0
            local.set 12
          end
          local.get 46
          local.get 9
          i64.const 1
          i64.shl
          local.get 20
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 27
          local.get 28
          local.get 30
          i64.const 1
          i64.shl
          local.get 9
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 10
          local.get 12
          local.get 19
          i64.const 1
          i64.shl
          local.get 30
          i64.const 63
          i64.shr_u
          i64.or
          i64.or
          local.set 12
          local.get 45
          local.get 20
          i64.const 1
          i64.shl
          i64.or
          local.set 28
        end
        local.get 22
        i32.const 80
        i32.add
        local.get 28
        local.get 27
        local.get 42
        local.get 44
        call $__multi3
        local.get 22
        i32.const 64
        i32.add
        local.get 10
        local.get 12
        local.get 41
        local.get 43
        call $__multi3
        local.get 22
        i32.const 16
        i32.add
        local.get 41
        i64.const 0
        local.get 28
        i64.const 0
        call $__multi3
        local.get 22
        local.get 43
        i64.const 0
        local.get 28
        i64.const 0
        call $__multi3
        local.get 22
        i32.const 32
        i32.add
        local.get 41
        i64.const 0
        local.get 27
        i64.const 0
        call $__multi3
        local.get 22
        i32.const 48
        i32.add
        local.get 43
        i64.const 0
        local.get 27
        i64.const 0
        call $__multi3
        local.get 22
        i32.const 448
        i32.add
        i32.const 24
        i32.add
        local.get 8
        i64.store
        local.get 22
        local.get 5
        i64.store offset=448
        local.get 22
        local.get 6
        i64.store offset=456
        local.get 22
        local.get 7
        i64.store offset=464
        local.get 22
        i32.const 448
        i32.add
        i32.const 0
        local.get 22
        i32.const 416
        i32.add
        call $wrapper_u256_shr
        local.get 40
        local.get 22
        i64.load offset=16
        local.tee 7
        i64.sub
        local.get 22
        i64.load offset=416
        i64.xor
        local.get 38
        local.get 22
        i64.load offset=48
        local.tee 6
        local.get 22
        i32.const 8
        i32.add
        i64.load
        local.get 22
        i64.load
        local.tee 27
        local.get 22
        i32.const 16
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.tee 28
        local.get 27
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 5
        local.get 22
        i32.const 32
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 22
        i64.load offset=32
        local.tee 8
        local.get 28
        i64.add
        local.tee 27
        local.get 8
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.tee 12
        i64.add
        local.tee 28
        local.get 22
        i64.load offset=64
        local.tee 11
        local.get 22
        i64.load offset=80
        i64.add
        local.tee 10
        i64.add
        local.tee 8
        i64.sub
        local.tee 9
        local.get 40
        local.get 7
        i64.lt_u
        local.tee 23
        local.get 39
        local.get 27
        i64.lt_u
        local.get 39
        local.get 27
        i64.eq
        select
        i64.extend_i32_u
        local.tee 7
        i64.sub
        local.get 22
        i32.const 432
        i32.add
        i64.load
        i64.xor
        i64.or
        local.get 39
        local.get 27
        i64.sub
        local.get 23
        i64.extend_i32_u
        i64.sub
        local.get 22
        i32.const 416
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.xor
        local.get 37
        local.get 22
        i32.const 48
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 12
        local.get 5
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 28
        local.get 6
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 22
        i32.const 64
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 22
        i32.const 80
        i32.add
        i32.const 8
        i32.add
        i64.load
        i64.add
        local.get 10
        local.get 11
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.add
        local.get 8
        local.get 28
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.sub
        local.get 38
        local.get 8
        i64.lt_u
        i64.extend_i32_u
        i64.sub
        local.get 9
        local.get 7
        i64.lt_u
        i64.extend_i32_u
        i64.sub
        local.get 22
        i32.const 416
        i32.add
        i32.const 24
        i32.add
        i64.load
        i64.xor
        i64.or
        i64.or
        i64.eqz
        i64.extend_i32_u
        local.set 27
        br 1 (;@1;)
      end
      i64.const 0
      local.set 27
      i64.const 0
      local.set 29
    end
    local.get 0
    local.get 27
    i64.store
    local.get 0
    local.get 29
    i64.store offset=8
    local.get 0
    local.get 29
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 29
    i64.store
    local.get 22
    i32.const 480
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_isValidPublicKey_2179 (type 14) (param i32 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 928
    i32.sub
    local.tee 9
    global.set $__stack_pointer
    local.get 9
    i32.const 896
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 9
    local.get 7
    i64.store offset=912
    local.get 9
    local.get 6
    i64.store offset=904
    local.get 9
    local.get 5
    i64.store offset=896
    local.get 9
    i32.const 896
    i32.add
    local.get 9
    i32.const 864
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 832
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 9
    local.get 7
    i64.store offset=848
    local.get 9
    local.get 6
    i64.store offset=840
    local.get 9
    local.get 5
    i64.store offset=832
    local.get 9
    i32.const 832
    i32.add
    local.get 9
    i32.const 800
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 768
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 9
    i64.const 0
    i64.store offset=784
    local.get 9
    i64.const 4294967295
    i64.store offset=776
    local.get 9
    i64.const -1
    i64.store offset=768
    local.get 9
    i32.const 768
    i32.add
    local.get 9
    i32.const 736
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 864
    i32.add
    local.get 9
    i32.const 800
    i32.add
    local.get 9
    i32.const 736
    i32.add
    local.get 9
    i32.const 704
    i32.add
    call $wrapper_mulmod
    local.get 9
    i32.const 672
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 9
    local.get 3
    i64.store offset=688
    local.get 9
    local.get 2
    i64.store offset=680
    local.get 9
    local.get 1
    i64.store offset=672
    local.get 9
    i32.const 672
    i32.add
    local.get 9
    i32.const 640
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 608
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 9
    local.get 3
    i64.store offset=624
    local.get 9
    local.get 2
    i64.store offset=616
    local.get 9
    local.get 1
    i64.store offset=608
    local.get 9
    i32.const 608
    i32.add
    local.get 9
    i32.const 576
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 544
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 9
    i64.const 0
    i64.store offset=560
    local.get 9
    i64.const 4294967295
    i64.store offset=552
    local.get 9
    i64.const -1
    i64.store offset=544
    local.get 9
    i32.const 544
    i32.add
    local.get 9
    i32.const 512
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 640
    i32.add
    local.get 9
    i32.const 576
    i32.add
    local.get 9
    i32.const 512
    i32.add
    local.get 9
    i32.const 480
    i32.add
    call $wrapper_mulmod
    local.get 9
    i32.const 448
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 9
    i64.const 0
    i64.store offset=464
    local.get 9
    i64.const 4294967295
    i64.store offset=456
    local.get 9
    i64.const -4
    i64.store offset=448
    local.get 9
    i32.const 448
    i32.add
    local.get 9
    i32.const 416
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 384
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 9
    i64.const 0
    i64.store offset=400
    local.get 9
    i64.const 4294967295
    i64.store offset=392
    local.get 9
    i64.const -1
    i64.store offset=384
    local.get 9
    i32.const 384
    i32.add
    local.get 9
    i32.const 352
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 480
    i32.add
    local.get 9
    i32.const 416
    i32.add
    local.get 9
    i32.const 352
    i32.add
    local.get 9
    i32.const 320
    i32.add
    call $wrapper_addmod
    local.get 9
    i32.const 288
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 9
    local.get 3
    i64.store offset=304
    local.get 9
    local.get 2
    i64.store offset=296
    local.get 9
    local.get 1
    i64.store offset=288
    local.get 9
    i32.const 288
    i32.add
    local.get 9
    i32.const 256
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 224
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 9
    i64.const 0
    i64.store offset=240
    local.get 9
    i64.const 4294967295
    i64.store offset=232
    local.get 9
    i64.const -1
    i64.store offset=224
    local.get 9
    i32.const 224
    i32.add
    local.get 9
    i32.const 192
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 320
    i32.add
    local.get 9
    i32.const 256
    i32.add
    local.get 9
    i32.const 192
    i32.add
    local.get 9
    i32.const 160
    i32.add
    call $wrapper_mulmod
    local.get 9
    i32.const 128
    i32.add
    i32.const 24
    i32.add
    i64.const 6540974713487397863
    i64.store
    local.get 9
    i64.const -5482079946633869636
    i64.store offset=144
    local.get 9
    i64.const 7285987128567378166
    i64.store offset=136
    local.get 9
    i64.const 4309448131093880907
    i64.store offset=128
    local.get 9
    i32.const 128
    i32.add
    local.get 9
    i32.const 96
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 9
    i64.const 0
    i64.store offset=80
    local.get 9
    i64.const 4294967295
    i64.store offset=72
    local.get 9
    i64.const -1
    i64.store offset=64
    local.get 9
    i32.const 64
    i32.add
    local.get 9
    i32.const 32
    i32.add
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const 160
    i32.add
    local.get 9
    i32.const 96
    i32.add
    local.get 9
    i32.const 32
    i32.add
    local.get 9
    call $wrapper_addmod
    local.get 9
    i32.const 704
    i32.add
    local.get 9
    call $wrapper_bytes32_eq
    local.set 10
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
    local.get 10
    local.get 1
    i64.const -1
    i64.ne
    local.get 2
    i64.const 4294967295
    i64.lt_u
    local.get 2
    i64.const 4294967295
    i64.eq
    select
    local.get 4
    i64.const -4294967295
    i64.lt_u
    local.get 3
    local.get 4
    i64.const -4294967295
    i64.xor
    i64.or
    i64.eqz
    select
    local.get 5
    i64.const -1
    i64.ne
    local.get 6
    i64.const 4294967295
    i64.lt_u
    local.get 6
    i64.const 4294967295
    i64.eq
    select
    local.get 8
    i64.const -4294967295
    i64.lt_u
    local.get 7
    local.get 8
    i64.const -4294967295
    i64.xor
    i64.or
    i64.eqz
    select
    i32.and
    i32.and
    i64.extend_i32_u
    i64.store
    local.get 9
    i32.const 928
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__preComputeJacobianPoints_2649 (type 14) (param i32 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i64 i32 i64 i32 i64 i64 i64 i64 i64 i64 i32 i32 i32 i32 i32 i32 i32 i64 i64 i64 i64 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 1344
    i32.sub
    local.tee 9
    global.set $__stack_pointer
    i32.const 65984
    local.get 9
    local.tee 10
    i32.const 1312
    i32.add
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 10
      i64.load offset=1312
      i64.const 15
      i64.gt_u
      local.get 10
      i32.const 1320
      i32.add
      local.tee 11
      i64.load
      local.tee 12
      i64.const 0
      i64.ne
      local.get 12
      i64.eqz
      select
      local.get 10
      i32.const 1328
      i32.add
      local.tee 13
      i64.load
      local.tee 14
      i64.const 0
      i64.ne
      local.get 10
      i32.const 1336
      i32.add
      local.tee 15
      i64.load
      local.tee 12
      i64.const 0
      i64.ne
      local.get 12
      i64.eqz
      select
      local.get 14
      local.get 12
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      i32.const 0
      i32.const 65920
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 12
    local.get 11
    i64.load
    local.tee 14
    local.get 13
    i64.load
    local.tee 16
    local.get 15
    i64.load
    local.tee 17
    i64.const 512
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    i32.const 65984
    local.get 10
    i32.const 1312
    i32.add
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 10
      i64.load offset=1312
      i64.const 15
      i64.gt_u
      local.get 11
      i64.load
      local.tee 18
      i64.const 0
      i64.ne
      local.get 18
      i64.eqz
      select
      local.get 13
      i64.load
      local.tee 19
      i64.const 0
      i64.ne
      local.get 15
      i64.load
      local.tee 18
      i64.const 0
      i64.ne
      local.get 18
      i64.eqz
      select
      local.get 19
      local.get 18
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      i32.const 0
      i32.const 65920
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 12
    local.get 14
    local.get 16
    local.get 17
    i64.const 512
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.zero_complex_memory_array_t_array$_t_struct$_JPoint_$1709_memory_ptr_$16_memory_ptr
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 10
    i32.const 1312
    i32.add
    i32.const 8
    i32.add
    local.tee 13
    i64.load
    local.tee 19
    local.get 10
    i32.const 1312
    i32.add
    i32.const 16
    i32.add
    local.tee 15
    i64.load
    local.tee 20
    local.get 10
    i32.const 1312
    i32.add
    i32.const 24
    i32.add
    local.tee 11
    i64.load
    local.tee 21
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 22
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 22
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 22
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 9
    i32.const -32
    i32.add
    local.tee 22
    local.tee 23
    global.set $__stack_pointer
    local.get 22
    i32.const 24
    i32.add
    local.get 21
    i64.store
    local.get 22
    local.get 20
    i64.store offset=16
    local.get 22
    local.get 19
    i64.store offset=8
    local.get 22
    local.get 18
    i64.store
    local.get 12
    i32.wrap_i64
    local.tee 9
    local.get 22
    call $wrapper_mstore_u256
    local.get 23
    i32.const -32
    i32.add
    local.tee 22
    local.tee 23
    global.set $__stack_pointer
    local.get 9
    local.get 22
    call $wrapper_mload_bytes32
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 19
    local.get 15
    i64.load
    local.tee 20
    local.get 11
    i64.load
    local.tee 21
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 4
    i64.store
    local.get 10
    local.get 3
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 1
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 22
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 8
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 6
    i64.store offset=1320
    local.get 10
    local.get 5
    i64.store offset=1312
    local.get 22
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 1
    i64.store offset=1312
    local.get 22
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i32.const -32
    i32.add
    local.tee 22
    local.tee 23
    global.set $__stack_pointer
    local.get 22
    i32.const 24
    i32.add
    local.get 21
    i64.store
    local.get 22
    local.get 20
    i64.store offset=16
    local.get 22
    local.get 19
    i64.store offset=8
    local.get 22
    local.get 18
    i64.store
    local.get 9
    i32.const 32
    i32.add
    local.tee 24
    local.get 22
    call $wrapper_mstore_u256
    local.get 23
    i32.const -32
    i32.add
    local.tee 22
    local.tee 25
    global.set $__stack_pointer
    local.get 24
    local.get 22
    call $wrapper_mload_bytes32
    i32.const 66016
    local.get 10
    i32.const 1280
    i32.add
    call $u256_from_big_endian_bytes
    i32.const 66048
    local.get 10
    i32.const 1312
    i32.add
    call $u256_from_big_endian_bytes
    i32.const 64
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1248
    local.tee 18
    local.get 10
    i32.const 1248
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.tee 8
    local.get 10
    i32.const 1248
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.tee 7
    local.get 10
    i32.const 1248
    i32.add
    i32.const 24
    i32.add
    local.tee 22
    i64.load
    local.tee 6
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 18
    i32.wrap_i64
    local.tee 23
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 1
    i64.store offset=1312
    local.get 23
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 25
    i32.const -32
    i32.add
    local.tee 23
    local.tee 26
    global.set $__stack_pointer
    local.get 23
    i32.const 24
    i32.add
    local.get 6
    i64.store
    local.get 23
    local.get 7
    i64.store offset=16
    local.get 23
    local.get 8
    i64.store offset=8
    local.get 23
    local.get 18
    i64.store
    local.get 9
    i32.const 128
    i32.add
    local.tee 25
    local.get 23
    call $wrapper_mstore_u256
    local.get 26
    i32.const -32
    i32.add
    local.tee 23
    local.tee 26
    global.set $__stack_pointer
    local.get 25
    local.get 23
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 23
    local.tee 26
    global.set $__stack_pointer
    local.get 24
    local.get 23
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 27
    global.set $__stack_pointer
    local.get 23
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 28
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 10
    i32.const 1280
    i32.add
    i32.const 24
    i32.add
    local.tee 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 28
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 28
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 18
    local.get 15
    i64.load
    local.set 8
    local.get 13
    i64.load
    local.set 7
    local.get 10
    i64.load offset=1312
    local.set 6
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 1152
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jDouble_2293
    local.get 10
    i32.const 1152
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 1152
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 1152
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 1152
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 1152
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 1152
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 1152
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 1152
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 1152
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=1216
    local.set 20
    local.get 10
    i64.load offset=1184
    local.set 21
    local.get 10
    i64.load offset=1152
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 27
    i32.const -32
    i32.add
    local.tee 26
    local.tee 27
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 64
    i32.add
    local.tee 28
    local.get 26
    call $wrapper_mstore_u256
    local.get 27
    i32.const -32
    i32.add
    local.tee 26
    local.tee 27
    global.set $__stack_pointer
    local.get 28
    local.get 26
    call $wrapper_mload_bytes32
    local.get 27
    i32.const -32
    i32.add
    local.tee 26
    local.tee 27
    global.set $__stack_pointer
    local.get 25
    local.get 26
    call $wrapper_mload_bytes32
    local.get 27
    i32.const -32
    i32.add
    local.tee 27
    local.tee 33
    global.set $__stack_pointer
    local.get 26
    local.get 27
    call $u256_from_big_endian_bytes
    local.get 27
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 27
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 27
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 27
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 18
    local.get 15
    i64.load
    local.set 8
    local.get 13
    i64.load
    local.set 7
    local.get 10
    i64.load offset=1312
    local.set 6
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 1056
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jDouble_2293
    local.get 10
    i32.const 1056
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 1056
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 1056
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 1056
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 1056
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 1056
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 1056
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 1056
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 1056
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=1120
    local.set 20
    local.get 10
    i64.load offset=1088
    local.set 21
    local.get 10
    i64.load offset=1056
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 33
    i32.const -32
    i32.add
    local.tee 26
    local.tee 33
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 256
    i32.add
    local.tee 27
    local.get 26
    call $wrapper_mstore_u256
    local.get 33
    i32.const -32
    i32.add
    local.tee 26
    local.tee 33
    global.set $__stack_pointer
    local.get 27
    local.get 26
    call $wrapper_mload_bytes32
    local.get 33
    i32.const -32
    i32.add
    local.tee 33
    local.tee 26
    global.set $__stack_pointer
    local.get 24
    local.get 33
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 34
    local.tee 26
    global.set $__stack_pointer
    local.get 28
    local.get 34
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 35
    global.set $__stack_pointer
    local.get 33
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 26
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 26
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 26
    i64.load
    local.set 6
    local.get 35
    i32.const -32
    i32.add
    local.tee 26
    local.tee 35
    global.set $__stack_pointer
    local.get 34
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 33
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 33
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 33
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 960
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 960
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 960
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 960
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 960
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 960
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 960
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 960
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 960
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 960
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=1024
    local.set 20
    local.get 10
    i64.load offset=992
    local.set 21
    local.get 10
    i64.load offset=960
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 35
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 96
    i32.add
    local.tee 33
    local.get 26
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 33
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 34
    local.tee 26
    global.set $__stack_pointer
    local.get 24
    local.get 34
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 35
    local.tee 26
    global.set $__stack_pointer
    local.get 25
    local.get 35
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 34
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 26
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 26
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 26
    i64.load
    local.set 6
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 34
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 34
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 34
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 864
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 864
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 864
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 864
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 864
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 864
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 864
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 864
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 864
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 864
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=928
    local.set 20
    local.get 10
    i64.load offset=896
    local.set 21
    local.get 10
    i64.load offset=864
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 160
    i32.add
    local.tee 35
    local.get 26
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 34
    local.tee 26
    global.set $__stack_pointer
    local.get 28
    local.get 34
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 35
    local.tee 26
    global.set $__stack_pointer
    local.get 25
    local.get 35
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 34
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 26
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 26
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 26
    i64.load
    local.set 6
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 34
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 34
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 34
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 768
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 768
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 768
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 768
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 768
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 768
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 768
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 768
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 768
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 768
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=832
    local.set 20
    local.get 10
    i64.load offset=800
    local.set 21
    local.get 10
    i64.load offset=768
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 192
    i32.add
    local.tee 35
    local.get 26
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 34
    local.tee 26
    global.set $__stack_pointer
    local.get 33
    local.get 34
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 35
    local.tee 26
    global.set $__stack_pointer
    local.get 25
    local.get 35
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 34
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 26
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 26
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 26
    i64.load
    local.set 6
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 34
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 34
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 34
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 672
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 672
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 672
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 672
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 672
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 672
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 672
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 672
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 672
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 672
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=736
    local.set 20
    local.get 10
    i64.load offset=704
    local.set 21
    local.get 10
    i64.load offset=672
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 224
    i32.add
    local.tee 35
    local.get 26
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 34
    local.tee 26
    global.set $__stack_pointer
    local.get 24
    local.get 34
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 35
    local.tee 26
    global.set $__stack_pointer
    local.get 27
    local.get 35
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 34
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 26
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 26
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 26
    i64.load
    local.set 6
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 34
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 34
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 34
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 576
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 576
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 576
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 576
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 576
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 576
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 576
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 576
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 576
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 576
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=640
    local.set 20
    local.get 10
    i64.load offset=608
    local.set 21
    local.get 10
    i64.load offset=576
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 288
    i32.add
    local.tee 35
    local.get 26
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 34
    local.tee 26
    global.set $__stack_pointer
    local.get 28
    local.get 34
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 35
    local.tee 26
    global.set $__stack_pointer
    local.get 27
    local.get 35
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 34
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 26
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 26
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 26
    i64.load
    local.set 6
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 34
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 34
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 34
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 480
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 480
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 480
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 480
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 480
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 480
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 480
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 480
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 480
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 480
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=544
    local.set 20
    local.get 10
    i64.load offset=512
    local.set 21
    local.get 10
    i64.load offset=480
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 320
    i32.add
    local.tee 35
    local.get 26
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 34
    local.tee 26
    global.set $__stack_pointer
    local.get 33
    local.get 34
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 35
    local.tee 26
    global.set $__stack_pointer
    local.get 27
    local.get 35
    call $wrapper_mload_bytes32
    local.get 26
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 34
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 26
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 26
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 26
    i64.load
    local.set 6
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 36
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $u256_from_big_endian_bytes
    local.get 26
    i32.load
    local.set 26
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 34
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 34
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 34
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 384
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 384
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 384
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 384
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 384
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 384
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 384
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 384
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 384
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 384
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=448
    local.set 20
    local.get 10
    i64.load offset=416
    local.set 21
    local.get 10
    i64.load offset=384
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 36
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 26
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 26
    local.get 31
    i64.store offset=16
    local.get 26
    local.get 30
    i64.store offset=8
    local.get 26
    local.get 18
    i64.store
    local.get 9
    i32.const 352
    i32.add
    local.tee 35
    local.get 26
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 35
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 26
    local.tee 34
    global.set $__stack_pointer
    local.get 25
    local.get 26
    call $wrapper_mload_bytes32
    local.get 34
    i32.const -32
    i32.add
    local.tee 34
    local.tee 25
    global.set $__stack_pointer
    local.get 27
    local.get 34
    call $wrapper_mload_bytes32
    local.get 25
    i32.const -32
    i32.add
    local.tee 25
    local.tee 27
    global.set $__stack_pointer
    local.get 26
    local.get 25
    call $u256_from_big_endian_bytes
    local.get 25
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 25
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 25
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 25
    i64.load
    local.set 6
    local.get 27
    i32.const -32
    i32.add
    local.tee 25
    local.tee 27
    global.set $__stack_pointer
    local.get 34
    local.get 25
    call $u256_from_big_endian_bytes
    local.get 25
    i32.load
    local.set 25
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 26
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 26
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 26
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 25
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 25
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 25
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 288
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 288
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 288
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 288
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 288
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 288
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 288
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 288
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 288
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 288
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=352
    local.set 20
    local.get 10
    i64.load offset=320
    local.set 21
    local.get 10
    i64.load offset=288
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 25
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 25
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 25
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 27
    i32.const -32
    i32.add
    local.tee 25
    local.tee 27
    global.set $__stack_pointer
    local.get 25
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 25
    local.get 31
    i64.store offset=16
    local.get 25
    local.get 30
    i64.store offset=8
    local.get 25
    local.get 18
    i64.store
    local.get 9
    i32.const 384
    i32.add
    local.tee 26
    local.get 25
    call $wrapper_mstore_u256
    local.get 27
    i32.const -32
    i32.add
    local.tee 25
    local.tee 27
    global.set $__stack_pointer
    local.get 26
    local.get 25
    call $wrapper_mload_bytes32
    local.get 27
    i32.const -32
    i32.add
    local.tee 25
    local.tee 27
    global.set $__stack_pointer
    local.get 24
    local.get 25
    call $wrapper_mload_bytes32
    local.get 27
    i32.const -32
    i32.add
    local.tee 27
    local.tee 24
    global.set $__stack_pointer
    local.get 26
    local.get 27
    call $wrapper_mload_bytes32
    local.get 24
    i32.const -32
    i32.add
    local.tee 24
    local.tee 34
    global.set $__stack_pointer
    local.get 25
    local.get 24
    call $u256_from_big_endian_bytes
    local.get 24
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 24
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 24
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 24
    i64.load
    local.set 6
    local.get 34
    i32.const -32
    i32.add
    local.tee 24
    local.tee 34
    global.set $__stack_pointer
    local.get 27
    local.get 24
    call $u256_from_big_endian_bytes
    local.get 24
    i32.load
    local.set 24
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 25
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 25
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 25
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 24
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 24
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 24
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 192
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 192
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 192
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 192
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 192
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 192
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 192
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 192
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 192
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 192
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=256
    local.set 20
    local.get 10
    i64.load offset=224
    local.set 21
    local.get 10
    i64.load offset=192
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 24
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 24
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 24
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 34
    i32.const -32
    i32.add
    local.tee 24
    local.tee 25
    global.set $__stack_pointer
    local.get 24
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 24
    local.get 31
    i64.store offset=16
    local.get 24
    local.get 30
    i64.store offset=8
    local.get 24
    local.get 18
    i64.store
    local.get 9
    i32.const 416
    i32.add
    local.tee 27
    local.get 24
    call $wrapper_mstore_u256
    local.get 25
    i32.const -32
    i32.add
    local.tee 24
    local.tee 25
    global.set $__stack_pointer
    local.get 27
    local.get 24
    call $wrapper_mload_bytes32
    local.get 25
    i32.const -32
    i32.add
    local.tee 25
    local.tee 24
    global.set $__stack_pointer
    local.get 28
    local.get 25
    call $wrapper_mload_bytes32
    local.get 24
    i32.const -32
    i32.add
    local.tee 28
    local.tee 24
    global.set $__stack_pointer
    local.get 26
    local.get 28
    call $wrapper_mload_bytes32
    local.get 24
    i32.const -32
    i32.add
    local.tee 24
    local.tee 27
    global.set $__stack_pointer
    local.get 25
    local.get 24
    call $u256_from_big_endian_bytes
    local.get 24
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 24
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 24
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 24
    i64.load
    local.set 6
    local.get 27
    i32.const -32
    i32.add
    local.tee 24
    local.tee 27
    global.set $__stack_pointer
    local.get 28
    local.get 24
    call $u256_from_big_endian_bytes
    local.get 24
    i32.load
    local.set 24
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 25
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 25
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 25
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 24
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 24
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 24
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i32.const 96
    i32.add
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 96
    i32.add
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 96
    i32.add
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 96
    i32.add
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 96
    i32.add
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 96
    i32.add
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 96
    i32.add
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 96
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 96
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 96
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=160
    local.set 20
    local.get 10
    i64.load offset=128
    local.set 21
    local.get 10
    i64.load offset=96
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 24
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 24
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 24
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 27
    i32.const -32
    i32.add
    local.tee 24
    local.tee 25
    global.set $__stack_pointer
    local.get 24
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 24
    local.get 31
    i64.store offset=16
    local.get 24
    local.get 30
    i64.store offset=8
    local.get 24
    local.get 18
    i64.store
    local.get 9
    i32.const 448
    i32.add
    local.tee 28
    local.get 24
    call $wrapper_mstore_u256
    local.get 25
    i32.const -32
    i32.add
    local.tee 24
    local.tee 25
    global.set $__stack_pointer
    local.get 28
    local.get 24
    call $wrapper_mload_bytes32
    local.get 25
    i32.const -32
    i32.add
    local.tee 25
    local.tee 24
    global.set $__stack_pointer
    local.get 33
    local.get 25
    call $wrapper_mload_bytes32
    local.get 24
    i32.const -32
    i32.add
    local.tee 28
    local.tee 24
    global.set $__stack_pointer
    local.get 26
    local.get 28
    call $wrapper_mload_bytes32
    local.get 24
    i32.const -32
    i32.add
    local.tee 24
    local.tee 26
    global.set $__stack_pointer
    local.get 25
    local.get 24
    call $u256_from_big_endian_bytes
    local.get 24
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 24
    i32.const 16
    i32.add
    i64.load
    local.set 8
    local.get 24
    i32.const 8
    i32.add
    i64.load
    local.set 7
    local.get 24
    i64.load
    local.set 6
    local.get 26
    i32.const -32
    i32.add
    local.tee 24
    local.tee 26
    global.set $__stack_pointer
    local.get 28
    local.get 24
    call $u256_from_big_endian_bytes
    local.get 24
    i32.load
    local.set 24
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 5
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1328
    local.get 10
    i64.const 0
    i64.store offset=1320
    local.get 10
    i64.const 0
    i64.store offset=1312
    local.get 5
    i32.wrap_i64
    local.tee 25
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 23
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1296
    local.get 10
    i64.const 0
    i64.store offset=1288
    local.get 10
    i64.const 0
    i64.store offset=1280
    local.get 25
    i32.const 32
    i32.add
    local.get 10
    i32.const 1280
    i32.add
    call $wrapper_mstore_u256
    local.get 22
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=1264
    local.get 10
    i64.const 0
    i64.store offset=1256
    local.get 10
    i64.const 0
    i64.store offset=1248
    local.get 25
    i32.const 64
    i32.add
    local.get 10
    i32.const 1248
    i32.add
    call $wrapper_mstore_u256
    local.get 24
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 5
    local.get 15
    i64.load
    local.set 4
    local.get 13
    i64.load
    local.set 3
    local.get 10
    i64.load offset=1312
    local.set 2
    local.get 24
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 11
    i64.load
    local.set 1
    local.get 15
    i64.load
    local.set 19
    local.get 13
    i64.load
    local.set 20
    local.get 10
    i64.load offset=1312
    local.set 21
    local.get 24
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    local.get 6
    local.get 7
    local.get 8
    local.get 18
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 21
    local.get 20
    local.get 19
    local.get 1
    local.get 10
    i64.load offset=1312
    local.get 13
    i64.load
    local.get 15
    i64.load
    local.get 11
    i64.load
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
    local.get 10
    i32.const 72
    i32.add
    i64.load
    local.set 8
    local.get 10
    i32.const 80
    i32.add
    i64.load
    local.set 7
    local.get 10
    i32.const 88
    i32.add
    i64.load
    local.set 6
    local.get 10
    i32.const 40
    i32.add
    i64.load
    local.set 5
    local.get 10
    i32.const 48
    i32.add
    i64.load
    local.set 4
    local.get 10
    i32.const 56
    i32.add
    i64.load
    local.set 3
    local.get 10
    i32.const 8
    i32.add
    i64.load
    local.set 2
    local.get 10
    i32.const 16
    i32.add
    i64.load
    local.set 1
    local.get 10
    i32.const 24
    i32.add
    i64.load
    local.set 19
    local.get 10
    i64.load offset=64
    local.set 20
    local.get 10
    i64.load offset=32
    local.set 21
    local.get 10
    i64.load
    local.set 29
    i32.const 64
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mload_u256
    local.get 10
    i64.load offset=1312
    local.tee 18
    local.get 13
    i64.load
    local.tee 30
    local.get 15
    i64.load
    local.tee 31
    local.get 11
    i64.load
    local.tee 32
    i64.const 96
    i64.const 0
    i64.const 0
    i64.const 0
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
    local.get 11
    local.get 19
    i64.store
    local.get 10
    local.get 1
    i64.store offset=1328
    local.get 10
    local.get 2
    i64.store offset=1320
    local.get 10
    local.get 29
    i64.store offset=1312
    local.get 18
    i32.wrap_i64
    local.tee 13
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 3
    i64.store
    local.get 10
    local.get 4
    i64.store offset=1328
    local.get 10
    local.get 5
    i64.store offset=1320
    local.get 10
    local.get 21
    i64.store offset=1312
    local.get 13
    i32.const 32
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 11
    local.get 6
    i64.store
    local.get 10
    local.get 7
    i64.store offset=1328
    local.get 10
    local.get 8
    i64.store offset=1320
    local.get 10
    local.get 20
    i64.store offset=1312
    local.get 13
    i32.const 64
    i32.add
    local.get 10
    i32.const 1312
    i32.add
    call $wrapper_mstore_u256
    local.get 26
    i32.const -32
    i32.add
    local.tee 11
    local.tee 13
    global.set $__stack_pointer
    local.get 11
    i32.const 24
    i32.add
    local.get 32
    i64.store
    local.get 11
    local.get 31
    i64.store offset=16
    local.get 11
    local.get 30
    i64.store offset=8
    local.get 11
    local.get 18
    i64.store
    local.get 9
    i32.const 480
    i32.add
    local.tee 15
    local.get 11
    call $wrapper_mstore_u256
    local.get 13
    i32.const -32
    i32.add
    local.tee 11
    global.set $__stack_pointer
    local.get 15
    local.get 11
    call $wrapper_mload_bytes32
    local.get 0
    local.get 16
    i64.store offset=16
    local.get 0
    local.get 14
    i64.store offset=8
    local.get 0
    local.get 12
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 17
    i64.store
    local.get 10
    i32.const 1344
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_tryModExp_905 (type 15) (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i64 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 13
    local.set 14
    local.get 13
    global.set $__stack_pointer
    i64.const 0
    local.set 15
    block  ;; label = @1
      block  ;; label = @2
        local.get 9
        local.get 11
        i64.or
        local.get 10
        local.get 12
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i64.const 0
        local.set 12
        i64.const 0
        local.set 10
        i64.const 0
        local.set 11
        i64.const 0
        local.set 9
        i64.const 0
        local.set 8
        br 1 (;@1;)
      end
      local.get 13
      i32.const -32
      i32.add
      local.tee 13
      local.tee 16
      global.set $__stack_pointer
      i32.const 64
      local.get 13
      call $wrapper_mload_bytes32
      local.get 13
      call $i32_from_big_endian_bytes32
      local.tee 17
      i32.const 32
      call $wrapper_mstore_u32
      local.get 16
      i32.const -32
      i32.add
      local.tee 16
      local.tee 18
      global.set $__stack_pointer
      local.get 13
      local.get 16
      call $u256_from_big_endian_bytes
      local.get 16
      i32.load
      i32.const 32
      i32.add
      i32.const 32
      call $wrapper_mstore_u32
      local.get 18
      i32.const -32
      i32.add
      local.tee 16
      local.tee 18
      global.set $__stack_pointer
      local.get 13
      local.get 16
      call $u256_from_big_endian_bytes
      local.get 16
      i32.load
      i32.const 64
      i32.add
      i32.const 32
      call $wrapper_mstore_u32
      local.get 18
      i32.const -32
      i32.add
      local.tee 16
      local.tee 18
      global.set $__stack_pointer
      local.get 13
      local.get 16
      call $u256_from_big_endian_bytes
      local.get 16
      i32.load
      local.set 19
      local.get 18
      i32.const -32
      i32.add
      local.tee 16
      local.tee 18
      global.set $__stack_pointer
      local.get 16
      i32.const 24
      i32.add
      local.get 4
      i64.store
      local.get 16
      local.get 3
      i64.store offset=16
      local.get 16
      local.get 2
      i64.store offset=8
      local.get 16
      local.get 1
      i64.store
      local.get 19
      i32.const 96
      i32.add
      local.get 16
      call $wrapper_mstore_u256
      local.get 18
      i32.const -32
      i32.add
      local.tee 16
      local.tee 18
      global.set $__stack_pointer
      local.get 13
      local.get 16
      call $u256_from_big_endian_bytes
      local.get 16
      i32.load
      local.set 19
      local.get 18
      i32.const -32
      i32.add
      local.tee 16
      local.tee 18
      global.set $__stack_pointer
      local.get 16
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 16
      local.get 7
      i64.store offset=16
      local.get 16
      local.get 6
      i64.store offset=8
      local.get 16
      local.get 5
      i64.store
      local.get 19
      i32.const 128
      i32.add
      local.get 16
      call $wrapper_mstore_u256
      local.get 18
      i32.const -32
      i32.add
      local.tee 16
      local.tee 18
      global.set $__stack_pointer
      local.get 13
      local.get 16
      call $u256_from_big_endian_bytes
      local.get 16
      i32.load
      local.set 16
      local.get 18
      i32.const -32
      i32.add
      local.tee 13
      local.tee 18
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 12
      i64.store
      local.get 13
      local.get 11
      i64.store offset=16
      local.get 13
      local.get 10
      i64.store offset=8
      local.get 13
      local.get 9
      i64.store
      local.get 16
      i32.const 160
      i32.add
      local.get 13
      call $wrapper_mstore_u256
      call $wrapper_gas
      local.set 12
      local.get 18
      i32.const -32
      i32.add
      local.tee 13
      local.tee 16
      global.set $__stack_pointer
      i64.const 0
      local.set 8
      local.get 13
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 13
      i64.const 0
      i64.store offset=16
      local.get 13
      i64.const 0
      i64.store offset=8
      local.get 13
      i64.const 5
      i64.store
      local.get 16
      i32.const -32
      i32.add
      local.tee 16
      global.set $__stack_pointer
      local.get 13
      local.get 16
      call $u256_to_big_endian_bytes
      local.get 12
      local.get 16
      local.get 17
      i32.const 192
      i32.const 0
      i32.const 32
      call $wrapper_staticcall
      local.set 13
      i32.const 0
      local.get 14
      call $wrapper_mload_u256
      local.get 13
      i64.extend_i32_u
      local.set 9
      local.get 14
      i32.const 24
      i32.add
      i64.load
      local.set 11
      local.get 14
      i32.const 16
      i32.add
      i64.load
      local.set 10
      local.get 14
      i32.const 8
      i32.add
      i64.load
      local.set 12
      local.get 14
      i64.load
      local.set 15
    end
    local.get 0
    local.get 15
    i64.store offset=32
    local.get 0
    local.get 9
    i64.store
    local.get 0
    i32.const 40
    i32.add
    local.get 12
    i64.store
    local.get 0
    local.get 8
    i64.store offset=8
    local.get 0
    i32.const 48
    i32.add
    local.get 10
    i64.store
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i32.const 56
    i32.add
    local.get 11
    i64.store
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 14
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jMultShamir_2442 (type 15) (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i32 i32 i32 i32 i64 i32)
    global.get $__stack_pointer
    i32.const 416
    i32.sub
    local.tee 13
    global.set $__stack_pointer
    local.get 13
    local.tee 14
    i32.const 384
    i32.add
    i32.const 8
    i32.add
    local.set 15
    local.get 14
    i32.const 384
    i32.add
    i32.const 16
    i32.add
    local.set 16
    local.get 14
    i32.const 64
    i32.add
    i32.const 88
    i32.add
    local.set 17
    local.get 14
    i32.const 64
    i32.add
    i32.const 80
    i32.add
    local.set 18
    local.get 14
    i32.const 64
    i32.add
    i32.const 72
    i32.add
    local.set 19
    local.get 14
    i32.const 64
    i32.add
    i32.const 56
    i32.add
    local.set 20
    local.get 14
    i32.const 64
    i32.add
    i32.const 48
    i32.add
    local.set 21
    local.get 14
    i32.const 64
    i32.add
    i32.const 40
    i32.add
    local.set 22
    i64.const 0
    local.set 23
    i64.const 0
    local.set 24
    i64.const 0
    local.set 25
    i64.const 0
    local.set 26
    i64.const 0
    local.set 27
    i64.const 0
    local.set 28
    i64.const 0
    local.set 29
    i64.const 0
    local.set 30
    i64.const 0
    local.set 31
    i64.const 0
    local.set 32
    i64.const 0
    local.set 33
    i64.const 0
    local.set 34
    i64.const 0
    local.set 35
    i64.const 0
    local.set 36
    i64.const 0
    local.set 37
    i64.const 0
    local.set 38
    loop  ;; label = @1
      local.get 37
      local.set 39
      local.get 36
      local.set 40
      local.get 35
      local.set 41
      block  ;; label = @2
        block  ;; label = @3
          local.get 31
          local.get 33
          i64.or
          local.get 32
          local.get 34
          i64.or
          i64.or
          i64.eqz
          i32.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 31
          i64.const 0
          local.set 32
          i64.const 0
          local.set 33
          i64.const 0
          local.set 34
          br 1 (;@2;)
        end
        local.get 14
        i32.const 256
        i32.add
        local.get 23
        local.get 24
        local.get 25
        local.get 26
        local.get 27
        local.get 28
        local.get 29
        local.get 30
        local.get 31
        local.get 32
        local.get 33
        local.get 34
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jDouble_2293
        local.get 14
        i32.const 160
        i32.add
        local.get 14
        i64.load offset=256
        local.get 14
        i32.const 256
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 14
        i32.const 256
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.get 14
        i32.const 256
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.get 14
        i64.load offset=288
        local.get 14
        i32.const 256
        i32.add
        i32.const 40
        i32.add
        i64.load
        local.get 14
        i32.const 256
        i32.add
        i32.const 48
        i32.add
        i64.load
        local.get 14
        i32.const 256
        i32.add
        i32.const 56
        i32.add
        i64.load
        local.get 14
        i64.load offset=320
        local.get 14
        i32.const 256
        i32.add
        i32.const 72
        i32.add
        i64.load
        local.get 14
        i32.const 256
        i32.add
        i32.const 80
        i32.add
        i64.load
        local.get 14
        i32.const 256
        i32.add
        i32.const 88
        i32.add
        i64.load
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jDouble_2293
        local.get 14
        i32.const 160
        i32.add
        i32.const 88
        i32.add
        i64.load
        local.set 34
        local.get 14
        i32.const 160
        i32.add
        i32.const 80
        i32.add
        i64.load
        local.set 33
        local.get 14
        i32.const 160
        i32.add
        i32.const 72
        i32.add
        i64.load
        local.set 32
        local.get 14
        i32.const 160
        i32.add
        i32.const 56
        i32.add
        i64.load
        local.set 30
        local.get 14
        i32.const 160
        i32.add
        i32.const 48
        i32.add
        i64.load
        local.set 29
        local.get 14
        i32.const 160
        i32.add
        i32.const 40
        i32.add
        i64.load
        local.set 28
        local.get 14
        i32.const 160
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.set 26
        local.get 14
        i32.const 160
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.set 25
        local.get 14
        i32.const 160
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.set 24
        local.get 14
        i64.load offset=224
        local.set 31
        local.get 14
        i64.load offset=192
        local.set 27
        local.get 14
        i64.load offset=160
        local.set 23
      end
      local.get 14
      i32.const 384
      i32.add
      i32.const 24
      i32.add
      local.tee 42
      local.get 8
      i64.store
      local.get 14
      local.get 5
      i64.store offset=384
      local.get 14
      local.get 6
      i64.store offset=392
      local.get 14
      local.get 7
      i64.store offset=400
      local.get 14
      i32.const 384
      i32.add
      i32.const 252
      local.get 14
      i32.const 352
      i32.add
      call $wrapper_u256_shr
      local.get 14
      i64.load offset=352
      local.set 35
      local.get 42
      local.get 12
      i64.store
      local.get 14
      local.get 11
      i64.store offset=400
      local.get 14
      local.get 10
      i64.store offset=392
      local.get 14
      local.get 9
      i64.store offset=384
      local.get 14
      i32.const 384
      i32.add
      i32.const 254
      local.get 14
      i32.const 352
      i32.add
      call $wrapper_u256_shr
      local.get 14
      i64.load offset=352
      local.set 36
      local.get 13
      i32.const -32
      i32.add
      local.tee 43
      local.tee 13
      global.set $__stack_pointer
      local.get 36
      i64.const 3
      i64.and
      local.get 35
      i64.const 12
      i64.and
      i64.or
      i64.const 5
      i64.shl
      local.get 1
      i64.add
      i32.wrap_i64
      local.tee 44
      local.get 43
      call $wrapper_mload_bytes32
      local.get 13
      i32.const -32
      i32.add
      local.tee 45
      local.tee 13
      global.set $__stack_pointer
      local.get 43
      local.get 45
      call $u256_from_big_endian_bytes
      local.get 45
      i32.load
      i32.const 64
      i32.add
      local.get 14
      i32.const 384
      i32.add
      call $wrapper_mload_u256
      block  ;; label = @2
        local.get 14
        i64.load offset=384
        local.get 16
        i64.load
        i64.or
        local.get 15
        i64.load
        local.get 42
        i64.load
        i64.or
        i64.or
        i64.eqz
        br_if 0 (;@2;)
        local.get 13
        i32.const -32
        i32.add
        local.tee 45
        local.tee 13
        global.set $__stack_pointer
        local.get 44
        local.get 45
        call $wrapper_mload_bytes32
        local.get 13
        i32.const -32
        i32.add
        local.tee 43
        local.tee 13
        global.set $__stack_pointer
        local.get 45
        local.get 43
        call $u256_from_big_endian_bytes
        local.get 43
        i64.load
        local.set 35
        block  ;; label = @3
          local.get 31
          local.get 33
          i64.or
          local.get 32
          local.get 34
          i64.or
          i64.or
          i64.eqz
          i32.eqz
          br_if 0 (;@3;)
          local.get 35
          i32.wrap_i64
          local.get 14
          i32.const 384
          i32.add
          call $wrapper_mload_u256
          local.get 42
          i64.load
          local.set 26
          local.get 16
          i64.load
          local.set 25
          local.get 15
          i64.load
          local.set 24
          local.get 14
          i64.load offset=384
          local.set 23
          local.get 13
          i32.const -32
          i32.add
          local.tee 13
          local.tee 43
          global.set $__stack_pointer
          local.get 44
          local.get 13
          call $wrapper_mload_bytes32
          local.get 43
          i32.const -32
          i32.add
          local.tee 43
          local.tee 45
          global.set $__stack_pointer
          local.get 13
          local.get 43
          call $u256_from_big_endian_bytes
          local.get 43
          i32.load
          i32.const 32
          i32.add
          local.get 14
          i32.const 384
          i32.add
          call $wrapper_mload_u256
          local.get 42
          i64.load
          local.set 30
          local.get 16
          i64.load
          local.set 29
          local.get 15
          i64.load
          local.set 28
          local.get 14
          i64.load offset=384
          local.set 27
          local.get 45
          i32.const -32
          i32.add
          local.tee 43
          local.tee 13
          global.set $__stack_pointer
          local.get 44
          local.get 43
          call $wrapper_mload_bytes32
          local.get 13
          i32.const -32
          i32.add
          local.tee 45
          local.tee 13
          global.set $__stack_pointer
          local.get 43
          local.get 45
          call $u256_from_big_endian_bytes
          local.get 45
          i32.load
          i32.const 64
          i32.add
          local.get 14
          i32.const 384
          i32.add
          call $wrapper_mload_u256
          local.get 42
          i64.load
          local.set 34
          local.get 16
          i64.load
          local.set 33
          local.get 15
          i64.load
          local.set 32
          local.get 14
          i64.load offset=384
          local.set 31
          br 1 (;@2;)
        end
        local.get 14
        i32.const 64
        i32.add
        local.get 35
        local.get 43
        i32.const 8
        i32.add
        i64.load
        local.get 43
        i32.const 16
        i32.add
        i64.load
        local.get 43
        i32.const 24
        i32.add
        i64.load
        local.get 23
        local.get 24
        local.get 25
        local.get 26
        local.get 27
        local.get 28
        local.get 29
        local.get 30
        local.get 31
        local.get 32
        local.get 33
        local.get 34
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275
        local.get 17
        i64.load
        local.set 34
        local.get 18
        i64.load
        local.set 33
        local.get 19
        i64.load
        local.set 32
        local.get 20
        i64.load
        local.set 30
        local.get 21
        i64.load
        local.set 29
        local.get 22
        i64.load
        local.set 28
        local.get 14
        i32.const 64
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.set 26
        local.get 14
        i32.const 64
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.set 25
        local.get 14
        i32.const 64
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.set 24
        local.get 14
        i64.load offset=128
        local.set 31
        local.get 14
        i64.load offset=96
        local.set 27
        local.get 14
        i64.load offset=64
        local.set 23
      end
      local.get 42
      local.get 8
      i64.store
      local.get 14
      local.get 5
      i64.store offset=384
      local.get 14
      local.get 6
      i64.store offset=392
      local.get 14
      local.get 7
      i64.store offset=400
      local.get 14
      i32.const 384
      i32.add
      i32.const 2
      local.get 14
      i32.const 352
      i32.add
      call $wrapper_u256_shl
      local.get 14
      i32.const 352
      i32.add
      i32.const 24
      i32.add
      local.tee 43
      i64.load
      local.set 8
      local.get 14
      i32.const 352
      i32.add
      i32.const 16
      i32.add
      local.tee 45
      i64.load
      local.set 7
      local.get 14
      i32.const 352
      i32.add
      i32.const 8
      i32.add
      local.tee 44
      i64.load
      local.set 6
      local.get 14
      i64.load offset=352
      local.set 5
      local.get 42
      local.get 12
      i64.store
      local.get 14
      local.get 11
      i64.store offset=400
      local.get 14
      local.get 10
      i64.store offset=392
      local.get 14
      local.get 9
      i64.store offset=384
      local.get 14
      i32.const 384
      i32.add
      i32.const 2
      local.get 14
      i32.const 352
      i32.add
      call $wrapper_u256_shl
      local.get 38
      i64.const 0
      i64.ne
      local.set 42
      local.get 38
      i64.eqz
      local.set 46
      local.get 39
      local.get 38
      i64.or
      local.set 47
      local.get 38
      local.get 39
      local.get 41
      i64.const 1
      i64.add
      local.tee 35
      local.get 41
      i64.lt_u
      local.tee 48
      local.get 40
      local.get 48
      i64.extend_i32_u
      i64.add
      local.tee 36
      local.get 40
      i64.lt_u
      local.get 35
      local.get 41
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 37
      local.get 39
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.set 38
      local.get 43
      i64.load
      local.set 12
      local.get 45
      i64.load
      local.set 11
      local.get 44
      i64.load
      local.set 10
      local.get 14
      i64.load offset=352
      local.set 9
      local.get 41
      i64.const 126
      i64.gt_u
      local.get 40
      i64.const 0
      i64.ne
      local.get 40
      i64.eqz
      select
      local.get 39
      i64.const 0
      i64.ne
      local.get 42
      local.get 46
      select
      local.get 47
      i64.eqz
      select
      i32.eqz
      br_if 0 (;@1;)
    end
    local.get 14
    local.get 23
    local.get 24
    local.get 25
    local.get 26
    local.get 27
    local.get 28
    local.get 29
    local.get 30
    local.get 31
    local.get 32
    local.get 33
    local.get 34
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__affineFromJacobian_2254
    local.get 14
    i32.const 24
    i32.add
    i64.load
    local.set 38
    local.get 14
    i32.const 40
    i32.add
    i64.load
    local.set 41
    local.get 14
    i32.const 56
    i32.add
    i64.load
    local.set 40
    local.get 14
    i32.const 48
    i32.add
    i64.load
    local.set 39
    local.get 14
    i32.const 8
    i32.add
    i64.load
    local.set 31
    local.get 14
    i32.const 16
    i32.add
    i64.load
    local.set 32
    local.get 14
    i64.load
    local.set 33
    local.get 0
    local.get 14
    i64.load offset=32
    i64.store offset=32
    local.get 0
    local.get 32
    i64.store offset=16
    local.get 0
    local.get 33
    i64.store
    local.get 0
    local.get 31
    i64.store offset=8
    local.get 0
    i32.const 48
    i32.add
    local.get 39
    i64.store
    local.get 0
    i32.const 56
    i32.add
    local.get 40
    i64.store
    local.get 0
    i32.const 40
    i32.add
    local.get 41
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 38
    i64.store
    local.get 14
    i32.const 416
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation (type 16) (param i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i64 i64 i64 i32 i64 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 8
    global.set $__stack_pointer
    i32.const 65952
    local.get 8
    local.tee 9
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i64.const 31
        i64.add
        local.tee 10
        i64.const -32
        i64.and
        local.tee 11
        local.get 0
        i64.add
        local.tee 12
        local.get 0
        i64.lt_u
        local.get 5
        local.get 10
        local.get 4
        i64.lt_u
        local.tee 13
        i64.extend_i32_u
        i64.add
        local.tee 14
        local.get 1
        i64.add
        local.get 12
        local.get 11
        i64.lt_u
        local.tee 15
        i64.extend_i32_u
        i64.add
        local.tee 0
        local.get 1
        i64.lt_u
        local.get 0
        local.get 1
        i64.eq
        select
        local.get 6
        local.get 13
        local.get 14
        local.get 5
        i64.lt_u
        local.get 10
        local.get 4
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 4
        local.get 2
        i64.add
        local.tee 5
        local.get 15
        local.get 0
        local.get 14
        i64.lt_u
        local.get 0
        local.get 14
        i64.eq
        select
        i64.extend_i32_u
        i64.add
        local.tee 1
        local.get 2
        i64.lt_u
        local.get 7
        local.get 4
        local.get 6
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 3
        i64.add
        local.get 5
        local.get 4
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.get 1
        local.get 5
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 4
        local.get 3
        i64.lt_u
        local.get 4
        local.get 3
        i64.eq
        select
        local.get 1
        local.get 2
        i64.xor
        local.get 4
        local.get 3
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        local.get 12
        local.get 9
        i64.load
        i64.le_u
        local.get 0
        local.get 9
        i32.const 8
        i32.add
        i64.load
        local.tee 3
        i64.le_u
        local.get 0
        local.get 3
        i64.eq
        select
        local.get 1
        local.get 9
        i32.const 16
        i32.add
        i64.load
        local.tee 2
        i64.le_u
        local.get 4
        local.get 9
        i32.const 24
        i32.add
        i64.load
        local.tee 3
        i64.le_u
        local.get 4
        local.get 3
        i64.eq
        select
        local.get 1
        local.get 2
        i64.xor
        local.get 4
        local.get 3
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 1 (;@1;)
      end
      i32.const 0
      i32.const 65920
      call $wrapper_mstore_bytes32
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 8
    i32.const -32
    i32.add
    local.tee 8
    global.set $__stack_pointer
    local.get 8
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 8
    local.get 1
    i64.store offset=16
    local.get 8
    local.get 0
    i64.store offset=8
    local.get 8
    local.get 12
    i64.store
    i32.const 64
    local.get 8
    call $wrapper_mstore_u256
    local.get 9
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.zero_complex_memory_array_t_array$_t_struct$_JPoint_$1709_memory_ptr_$16_memory_ptr (type 16) (param i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i32 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 8
    local.set 9
    local.get 8
    global.set $__stack_pointer
    block  ;; label = @1
      local.get 4
      local.get 6
      i64.or
      local.get 5
      local.get 7
      i64.or
      i64.or
      i64.eqz
      br_if 0 (;@1;)
      local.get 9
      i32.const 80
      i32.add
      local.set 10
      local.get 9
      i32.const 72
      i32.add
      local.set 11
      i64.const 0
      local.set 12
      i64.const 0
      local.set 13
      i64.const 0
      local.set 14
      i64.const 0
      local.set 15
      loop  ;; label = @2
        i32.const 64
        local.get 9
        i32.const 64
        i32.add
        call $wrapper_mload_u256
        local.get 9
        i64.load offset=64
        local.tee 16
        local.get 11
        i64.load
        local.tee 17
        local.get 10
        i64.load
        local.tee 18
        local.get 9
        i32.const 64
        i32.add
        i32.const 24
        i32.add
        local.tee 19
        i64.load
        local.tee 20
        i64.const 96
        i64.const 0
        i64.const 0
        i64.const 0
        call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation
        local.get 19
        i64.const 0
        i64.store
        local.get 9
        i64.const 0
        i64.store offset=80
        local.get 9
        i64.const 0
        i64.store offset=72
        local.get 9
        i64.const 0
        i64.store offset=64
        local.get 16
        i32.wrap_i64
        local.tee 19
        local.get 9
        i32.const 64
        i32.add
        call $wrapper_mstore_u256
        local.get 9
        i32.const 32
        i32.add
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 9
        i64.const 0
        i64.store offset=48
        local.get 9
        i64.const 0
        i64.store offset=40
        local.get 9
        i64.const 0
        i64.store offset=32
        local.get 19
        i32.const 32
        i32.add
        local.get 9
        i32.const 32
        i32.add
        call $wrapper_mstore_u256
        local.get 9
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 9
        i64.const 0
        i64.store offset=16
        local.get 9
        i64.const 0
        i64.store offset=8
        local.get 9
        i64.const 0
        i64.store
        local.get 19
        i32.const 64
        i32.add
        local.get 9
        call $wrapper_mstore_u256
        local.get 8
        i32.const -32
        i32.add
        local.tee 19
        local.tee 8
        global.set $__stack_pointer
        local.get 19
        i32.const 24
        i32.add
        local.get 20
        i64.store
        local.get 19
        local.get 18
        i64.store offset=16
        local.get 19
        local.get 17
        i64.store offset=8
        local.get 19
        local.get 16
        i64.store
        local.get 12
        local.get 0
        i64.add
        i32.wrap_i64
        local.get 19
        call $wrapper_mstore_u256
        local.get 14
        local.get 12
        i64.const 32
        i64.add
        local.tee 16
        local.get 12
        i64.lt_u
        local.tee 19
        local.get 13
        local.get 19
        i64.extend_i32_u
        i64.add
        local.tee 17
        local.get 13
        i64.lt_u
        local.get 16
        local.get 12
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 18
        local.get 14
        i64.lt_u
        local.set 19
        local.get 16
        local.set 12
        local.get 17
        local.set 13
        local.get 18
        local.set 14
        local.get 16
        local.get 4
        i64.lt_u
        local.get 17
        local.get 5
        i64.lt_u
        local.get 17
        local.get 5
        i64.eq
        select
        local.get 18
        local.get 6
        i64.lt_u
        local.get 15
        local.get 19
        i64.extend_i32_u
        i64.add
        local.tee 15
        local.get 7
        i64.lt_u
        local.get 15
        local.get 7
        i64.eq
        select
        local.get 18
        local.get 6
        i64.xor
        local.get 15
        local.get 7
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
      end
    end
    local.get 9
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jDouble_2293 (type 15) (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 3136
    i32.sub
    local.tee 13
    global.set $__stack_pointer
    local.get 13
    i32.const 3008
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 13
    local.get 7
    i64.store offset=3024
    local.get 13
    local.get 6
    i64.store offset=3016
    local.get 13
    local.get 5
    i64.store offset=3008
    local.get 13
    i32.const 3008
    i32.add
    local.get 13
    i32.const 2976
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2944
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 13
    local.get 7
    i64.store offset=2960
    local.get 13
    local.get 6
    i64.store offset=2952
    local.get 13
    local.get 5
    i64.store offset=2944
    local.get 13
    i32.const 2944
    i32.add
    local.get 13
    i32.const 2912
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2880
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2896
    local.get 13
    i64.const 4294967295
    i64.store offset=2888
    local.get 13
    i64.const -1
    i64.store offset=2880
    local.get 13
    i32.const 2880
    i32.add
    local.get 13
    i32.const 2848
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2976
    i32.add
    local.get 13
    i32.const 2912
    i32.add
    local.get 13
    i32.const 2848
    i32.add
    local.get 13
    i32.const 2816
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 2784
    i32.add
    i32.const 24
    i32.add
    local.get 12
    i64.store
    local.get 13
    local.get 11
    i64.store offset=2800
    local.get 13
    local.get 10
    i64.store offset=2792
    local.get 13
    local.get 9
    i64.store offset=2784
    local.get 13
    i32.const 2784
    i32.add
    local.get 13
    i32.const 2752
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2720
    i32.add
    i32.const 24
    i32.add
    local.get 12
    i64.store
    local.get 13
    local.get 11
    i64.store offset=2736
    local.get 13
    local.get 10
    i64.store offset=2728
    local.get 13
    local.get 9
    i64.store offset=2720
    local.get 13
    i32.const 2720
    i32.add
    local.get 13
    i32.const 2688
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2656
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2672
    local.get 13
    i64.const 4294967295
    i64.store offset=2664
    local.get 13
    i64.const -1
    i64.store offset=2656
    local.get 13
    i32.const 2656
    i32.add
    local.get 13
    i32.const 2624
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2752
    i32.add
    local.get 13
    i32.const 2688
    i32.add
    local.get 13
    i32.const 2624
    i32.add
    local.get 13
    i32.const 2592
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 2560
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 13
    local.get 3
    i64.store offset=2576
    local.get 13
    local.get 2
    i64.store offset=2568
    local.get 13
    local.get 1
    i64.store offset=2560
    local.get 13
    i32.const 2560
    i32.add
    local.get 13
    i32.const 2528
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2496
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 13
    local.get 3
    i64.store offset=2512
    local.get 13
    local.get 2
    i64.store offset=2504
    local.get 13
    local.get 1
    i64.store offset=2496
    local.get 13
    i32.const 2496
    i32.add
    local.get 13
    i32.const 2464
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2432
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2448
    local.get 13
    i64.const 4294967295
    i64.store offset=2440
    local.get 13
    i64.const -1
    i64.store offset=2432
    local.get 13
    i32.const 2432
    i32.add
    local.get 13
    i32.const 2400
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2528
    i32.add
    local.get 13
    i32.const 2464
    i32.add
    local.get 13
    i32.const 2400
    i32.add
    local.get 13
    i32.const 2368
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 2336
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2352
    local.get 13
    i64.const 0
    i64.store offset=2344
    local.get 13
    i64.const 3
    i64.store offset=2336
    local.get 13
    i32.const 2336
    i32.add
    local.get 13
    i32.const 2304
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2272
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2288
    local.get 13
    i64.const 4294967295
    i64.store offset=2280
    local.get 13
    i64.const -1
    i64.store offset=2272
    local.get 13
    i32.const 2272
    i32.add
    local.get 13
    i32.const 2240
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2304
    i32.add
    local.get 13
    i32.const 2368
    i32.add
    local.get 13
    i32.const 2240
    i32.add
    local.get 13
    i32.const 2208
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 2176
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2192
    local.get 13
    i64.const 4294967295
    i64.store offset=2184
    local.get 13
    i64.const -1
    i64.store offset=2176
    local.get 13
    i32.const 2176
    i32.add
    local.get 13
    i32.const 2144
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2592
    i32.add
    local.get 13
    i32.const 2592
    i32.add
    local.get 13
    i32.const 2144
    i32.add
    local.get 13
    i32.const 2112
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 2080
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2096
    local.get 13
    i64.const 4294967295
    i64.store offset=2088
    local.get 13
    i64.const -4
    i64.store offset=2080
    local.get 13
    i32.const 2080
    i32.add
    local.get 13
    i32.const 2048
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2016
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=2032
    local.get 13
    i64.const 4294967295
    i64.store offset=2024
    local.get 13
    i64.const -1
    i64.store offset=2016
    local.get 13
    i32.const 2016
    i32.add
    local.get 13
    i32.const 1984
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2048
    i32.add
    local.get 13
    i32.const 2112
    i32.add
    local.get 13
    i32.const 1984
    i32.add
    local.get 13
    i32.const 1952
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 1920
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1936
    local.get 13
    i64.const 4294967295
    i64.store offset=1928
    local.get 13
    i64.const -1
    i64.store offset=1920
    local.get 13
    i32.const 1920
    i32.add
    local.get 13
    i32.const 1888
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2208
    i32.add
    local.get 13
    i32.const 1952
    i32.add
    local.get 13
    i32.const 1888
    i32.add
    local.get 13
    i32.const 1856
    i32.add
    call $wrapper_addmod
    local.get 13
    i32.const 1824
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 13
    local.get 3
    i64.store offset=1840
    local.get 13
    local.get 2
    i64.store offset=1832
    local.get 13
    local.get 1
    i64.store offset=1824
    local.get 13
    i32.const 1824
    i32.add
    local.get 13
    i32.const 1792
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1760
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1776
    local.get 13
    i64.const 4294967295
    i64.store offset=1768
    local.get 13
    i64.const -1
    i64.store offset=1760
    local.get 13
    i32.const 1760
    i32.add
    local.get 13
    i32.const 1728
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1792
    i32.add
    local.get 13
    i32.const 2816
    i32.add
    local.get 13
    i32.const 1728
    i32.add
    local.get 13
    i32.const 1696
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 1664
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1680
    local.get 13
    i64.const 0
    i64.store offset=1672
    local.get 13
    i64.const 4
    i64.store offset=1664
    local.get 13
    i32.const 1664
    i32.add
    local.get 13
    i32.const 1632
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1600
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1616
    local.get 13
    i64.const 4294967295
    i64.store offset=1608
    local.get 13
    i64.const -1
    i64.store offset=1600
    local.get 13
    i32.const 1600
    i32.add
    local.get 13
    i32.const 1568
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1632
    i32.add
    local.get 13
    i32.const 1696
    i32.add
    local.get 13
    i32.const 1568
    i32.add
    local.get 13
    i32.const 1536
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 1504
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1520
    local.get 13
    i64.const 4294967295
    i64.store offset=1512
    local.get 13
    i64.const -1
    i64.store offset=1504
    local.get 13
    i32.const 1504
    i32.add
    local.get 13
    i32.const 1472
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1856
    i32.add
    local.get 13
    i32.const 1856
    i32.add
    local.get 13
    i32.const 1472
    i32.add
    local.get 13
    i32.const 1440
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 1408
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1424
    local.get 13
    i64.const 0
    i64.store offset=1416
    local.get 13
    i64.const 2
    i64.store offset=1408
    local.get 13
    i32.const 1408
    i32.add
    local.get 13
    i32.const 1376
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1344
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1360
    local.get 13
    i64.const 4294967295
    i64.store offset=1352
    local.get 13
    i64.const -1
    i64.store offset=1344
    local.get 13
    i32.const 1344
    i32.add
    local.get 13
    i32.const 1312
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1376
    i32.add
    local.get 13
    i32.const 1536
    i32.add
    local.get 13
    i32.const 1312
    i32.add
    local.get 13
    i32.const 1280
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 1280
    i32.add
    local.get 13
    i32.const 1248
    i32.add
    call $u256_from_big_endian_bytes
    local.get 13
    i32.const 1216
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    local.get 13
    i32.const 1248
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.get 13
    i32.const 1248
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.tee 4
    i64.const 0
    i64.ne
    i64.extend_i32_u
    i64.add
    i64.const 0
    local.get 4
    i64.sub
    local.tee 3
    i32.const 0
    local.get 13
    i32.const 1248
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.tee 4
    i64.const 4294967295
    i64.gt_u
    local.get 4
    i64.const 4294967295
    i64.eq
    select
    i64.extend_i32_u
    local.tee 2
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.sub
    i64.store
    local.get 13
    i64.const 4294967295
    local.get 4
    i64.sub
    i64.store offset=1224
    local.get 13
    local.get 13
    i64.load offset=1248
    i64.const -1
    i64.xor
    i64.store offset=1216
    local.get 13
    local.get 3
    local.get 2
    i64.sub
    i64.store offset=1232
    local.get 13
    i32.const 1216
    i32.add
    local.get 13
    i32.const 1184
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1152
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1168
    local.get 13
    i64.const 4294967295
    i64.store offset=1160
    local.get 13
    i64.const -1
    i64.store offset=1152
    local.get 13
    i32.const 1152
    i32.add
    local.get 13
    i32.const 1120
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1440
    i32.add
    local.get 13
    i32.const 1184
    i32.add
    local.get 13
    i32.const 1120
    i32.add
    local.get 13
    i32.const 1088
    i32.add
    call $wrapper_addmod
    local.get 13
    i32.const 1088
    i32.add
    local.get 13
    i32.const 3040
    i32.add
    call $u256_from_big_endian_bytes
    local.get 13
    i32.const 1056
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    local.get 13
    i32.const 3040
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.tee 1
    local.get 13
    i32.const 3040
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.tee 3
    i64.const 0
    i64.ne
    i64.extend_i32_u
    i64.add
    i64.const 0
    local.get 3
    i64.sub
    local.tee 2
    i32.const 0
    local.get 13
    i32.const 3040
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.tee 4
    i64.const 4294967295
    i64.gt_u
    local.get 4
    i64.const 4294967295
    i64.eq
    select
    i64.extend_i32_u
    local.tee 14
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.sub
    i64.store
    local.get 13
    i64.const 4294967295
    local.get 4
    i64.sub
    i64.store offset=1064
    local.get 13
    local.get 13
    i64.load offset=3040
    local.tee 15
    i64.const -1
    i64.xor
    i64.store offset=1056
    local.get 13
    local.get 2
    local.get 14
    i64.sub
    i64.store offset=1072
    local.get 13
    i32.const 1056
    i32.add
    local.get 13
    i32.const 1024
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 992
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=1008
    local.get 13
    i64.const 4294967295
    i64.store offset=1000
    local.get 13
    i64.const -1
    i64.store offset=992
    local.get 13
    i32.const 992
    i32.add
    local.get 13
    i32.const 960
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1536
    i32.add
    local.get 13
    i32.const 1024
    i32.add
    local.get 13
    i32.const 960
    i32.add
    local.get 13
    i32.const 928
    i32.add
    call $wrapper_addmod
    local.get 13
    i32.const 896
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=912
    local.get 13
    i64.const 4294967295
    i64.store offset=904
    local.get 13
    i64.const -1
    i64.store offset=896
    local.get 13
    i32.const 896
    i32.add
    local.get 13
    i32.const 864
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 1856
    i32.add
    local.get 13
    i32.const 928
    i32.add
    local.get 13
    i32.const 864
    i32.add
    local.get 13
    i32.const 832
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 800
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=816
    local.get 13
    i64.const 4294967295
    i64.store offset=808
    local.get 13
    i64.const -1
    i64.store offset=800
    local.get 13
    i32.const 800
    i32.add
    local.get 13
    i32.const 768
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 2816
    i32.add
    local.get 13
    i32.const 2816
    i32.add
    local.get 13
    i32.const 768
    i32.add
    local.get 13
    i32.const 736
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 704
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=720
    local.get 13
    i64.const 0
    i64.store offset=712
    local.get 13
    i64.const 8
    i64.store offset=704
    local.get 13
    i32.const 704
    i32.add
    local.get 13
    i32.const 672
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 640
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=656
    local.get 13
    i64.const 4294967295
    i64.store offset=648
    local.get 13
    i64.const -1
    i64.store offset=640
    local.get 13
    i32.const 640
    i32.add
    local.get 13
    i32.const 608
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 672
    i32.add
    local.get 13
    i32.const 736
    i32.add
    local.get 13
    i32.const 608
    i32.add
    local.get 13
    i32.const 576
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 576
    i32.add
    local.get 13
    i32.const 544
    i32.add
    call $u256_from_big_endian_bytes
    local.get 13
    i32.const 512
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    local.get 13
    i32.const 544
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.get 13
    i32.const 544
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.tee 2
    i64.const 0
    i64.ne
    i64.extend_i32_u
    i64.add
    i64.const 0
    local.get 2
    i64.sub
    local.tee 14
    i32.const 0
    local.get 13
    i32.const 544
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.tee 2
    i64.const 4294967295
    i64.gt_u
    local.get 2
    i64.const 4294967295
    i64.eq
    select
    i64.extend_i32_u
    local.tee 16
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.sub
    i64.store
    local.get 13
    i64.const 4294967295
    local.get 2
    i64.sub
    i64.store offset=520
    local.get 13
    local.get 13
    i64.load offset=544
    i64.const -1
    i64.xor
    i64.store offset=512
    local.get 13
    local.get 14
    local.get 16
    i64.sub
    i64.store offset=528
    local.get 13
    i32.const 512
    i32.add
    local.get 13
    i32.const 480
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 448
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=464
    local.get 13
    i64.const 4294967295
    i64.store offset=456
    local.get 13
    i64.const -1
    i64.store offset=448
    local.get 13
    i32.const 448
    i32.add
    local.get 13
    i32.const 416
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 832
    i32.add
    local.get 13
    i32.const 480
    i32.add
    local.get 13
    i32.const 416
    i32.add
    local.get 13
    i32.const 384
    i32.add
    call $wrapper_addmod
    local.get 13
    i32.const 384
    i32.add
    local.get 13
    i32.const 3072
    i32.add
    call $u256_from_big_endian_bytes
    local.get 13
    i32.const 352
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 13
    local.get 7
    i64.store offset=368
    local.get 13
    local.get 6
    i64.store offset=360
    local.get 13
    local.get 5
    i64.store offset=352
    local.get 13
    i32.const 352
    i32.add
    local.get 13
    i32.const 320
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 288
    i32.add
    i32.const 24
    i32.add
    local.get 12
    i64.store
    local.get 13
    local.get 11
    i64.store offset=304
    local.get 13
    local.get 10
    i64.store offset=296
    local.get 13
    local.get 9
    i64.store offset=288
    local.get 13
    i32.const 288
    i32.add
    local.get 13
    i32.const 256
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 224
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=240
    local.get 13
    i64.const 4294967295
    i64.store offset=232
    local.get 13
    i64.const -1
    i64.store offset=224
    local.get 13
    i32.const 224
    i32.add
    local.get 13
    i32.const 192
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 320
    i32.add
    local.get 13
    i32.const 256
    i32.add
    local.get 13
    i32.const 192
    i32.add
    local.get 13
    i32.const 160
    i32.add
    call $wrapper_mulmod
    local.get 13
    i32.const 128
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=144
    local.get 13
    i64.const 0
    i64.store offset=136
    local.get 13
    i64.const 2
    i64.store offset=128
    local.get 13
    i32.const 128
    i32.add
    local.get 13
    i32.const 96
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 13
    i64.const 0
    i64.store offset=80
    local.get 13
    i64.const 4294967295
    i64.store offset=72
    local.get 13
    i64.const -1
    i64.store offset=64
    local.get 13
    i32.const 64
    i32.add
    local.get 13
    i32.const 32
    i32.add
    call $u256_to_big_endian_bytes
    local.get 13
    i32.const 96
    i32.add
    local.get 13
    i32.const 160
    i32.add
    local.get 13
    i32.const 32
    i32.add
    local.get 13
    call $wrapper_mulmod
    local.get 13
    local.get 13
    i32.const 3104
    i32.add
    call $u256_from_big_endian_bytes
    local.get 0
    local.get 13
    i64.load offset=3104
    i64.store offset=64
    local.get 0
    local.get 13
    i64.load offset=3072
    i64.store offset=32
    local.get 0
    local.get 3
    i64.store offset=16
    local.get 0
    local.get 4
    i64.store offset=8
    local.get 0
    local.get 15
    i64.store
    local.get 0
    i32.const 88
    i32.add
    local.get 13
    i32.const 3104
    i32.add
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 80
    i32.add
    local.get 13
    i32.const 3104
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 72
    i32.add
    local.get 13
    i32.const 3104
    i32.add
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 56
    i32.add
    local.get 13
    i32.const 3072
    i32.add
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 48
    i32.add
    local.get 13
    i32.const 3072
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 40
    i32.add
    local.get 13
    i32.const 3072
    i32.add
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 1
    i64.store
    local.get 13
    i32.const 3136
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_2275 (type 17) (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i64 i64 i32 i32 i32 i32 i32 i32 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 1920
    i32.sub
    local.tee 17
    global.set $__stack_pointer
    local.get 1
    i32.wrap_i64
    local.tee 18
    i32.const 64
    i32.add
    local.get 17
    local.tee 19
    i32.const 1760
    i32.add
    call $wrapper_mload_bytes32
    local.get 19
    i32.const 1728
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=1744
    local.get 19
    i64.const 4294967295
    i64.store offset=1736
    local.get 19
    i64.const -1
    i64.store offset=1728
    local.get 19
    i32.const 1728
    i32.add
    local.get 19
    i32.const 1696
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1760
    i32.add
    local.get 19
    i32.const 1760
    i32.add
    local.get 19
    i32.const 1696
    i32.add
    local.get 19
    i32.const 1664
    i32.add
    call $wrapper_mulmod
    local.get 18
    i32.const 32
    i32.add
    local.get 19
    i32.const 1632
    i32.add
    call $wrapper_mload_bytes32
    local.get 19
    i32.const 1600
    i32.add
    i32.const 24
    i32.add
    local.get 16
    i64.store
    local.get 19
    local.get 15
    i64.store offset=1616
    local.get 19
    local.get 14
    i64.store offset=1608
    local.get 19
    local.get 13
    i64.store offset=1600
    local.get 19
    i32.const 1600
    i32.add
    local.get 19
    i32.const 1568
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1536
    i32.add
    i32.const 24
    i32.add
    local.get 16
    i64.store
    local.get 19
    local.get 15
    i64.store offset=1552
    local.get 19
    local.get 14
    i64.store offset=1544
    local.get 19
    local.get 13
    i64.store offset=1536
    local.get 19
    i32.const 1536
    i32.add
    local.get 19
    i32.const 1504
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1472
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=1488
    local.get 19
    i64.const 4294967295
    i64.store offset=1480
    local.get 19
    i64.const -1
    i64.store offset=1472
    local.get 19
    i32.const 1472
    i32.add
    local.get 19
    i32.const 1440
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1568
    i32.add
    local.get 19
    i32.const 1504
    i32.add
    local.get 19
    i32.const 1440
    i32.add
    local.get 19
    i32.const 1408
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 1376
    i32.add
    i32.const 24
    i32.add
    local.get 16
    i64.store
    local.get 19
    local.get 15
    i64.store offset=1392
    local.get 19
    local.get 14
    i64.store offset=1384
    local.get 19
    local.get 13
    i64.store offset=1376
    local.get 19
    i32.const 1376
    i32.add
    local.get 19
    i32.const 1344
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1312
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=1328
    local.get 19
    i64.const 4294967295
    i64.store offset=1320
    local.get 19
    i64.const -1
    i64.store offset=1312
    local.get 19
    i32.const 1312
    i32.add
    local.get 19
    i32.const 1280
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1408
    i32.add
    local.get 19
    i32.const 1344
    i32.add
    local.get 19
    i32.const 1280
    i32.add
    local.get 19
    i32.const 1248
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 1216
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=1232
    local.get 19
    i64.const 4294967295
    i64.store offset=1224
    local.get 19
    i64.const -1
    i64.store offset=1216
    local.get 19
    i32.const 1216
    i32.add
    local.get 19
    i32.const 1184
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1632
    i32.add
    local.get 19
    i32.const 1248
    i32.add
    local.get 19
    i32.const 1184
    i32.add
    local.get 19
    i32.const 1152
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 1120
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=1136
    local.get 19
    i64.const 4294967295
    i64.store offset=1128
    local.get 19
    i64.const -1
    i64.store offset=1120
    local.get 19
    i32.const 1120
    i32.add
    local.get 19
    i32.const 1088
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 1664
    i32.add
    local.get 19
    i32.const 1760
    i32.add
    local.get 19
    i32.const 1088
    i32.add
    local.get 19
    i32.const 1056
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 1024
    i32.add
    i32.const 24
    i32.add
    local.get 12
    i64.store
    local.get 19
    local.get 11
    i64.store offset=1040
    local.get 19
    local.get 10
    i64.store offset=1032
    local.get 19
    local.get 9
    i64.store offset=1024
    local.get 19
    i32.const 1024
    i32.add
    local.get 19
    i32.const 992
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 960
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=976
    local.get 19
    i64.const 4294967295
    i64.store offset=968
    local.get 19
    i64.const -1
    i64.store offset=960
    local.get 19
    i32.const 960
    i32.add
    local.get 19
    i32.const 928
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 992
    i32.add
    local.get 19
    i32.const 1056
    i32.add
    local.get 19
    i32.const 928
    i32.add
    local.get 19
    i32.const 896
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 1152
    i32.add
    local.get 19
    i32.const 864
    i32.add
    call $u256_from_big_endian_bytes
    local.get 19
    i32.const 832
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    local.get 19
    i32.const 864
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.get 19
    i32.const 864
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.tee 1
    i64.const 0
    i64.ne
    i64.extend_i32_u
    i64.add
    i64.const 0
    local.get 1
    i64.sub
    local.tee 20
    i32.const 0
    local.get 19
    i32.const 864
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.tee 1
    i64.const 4294967295
    i64.gt_u
    local.get 1
    i64.const 4294967295
    i64.eq
    select
    i64.extend_i32_u
    local.tee 21
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.sub
    i64.store
    local.get 19
    i64.const 4294967295
    local.get 1
    i64.sub
    i64.store offset=840
    local.get 19
    local.get 19
    i64.load offset=864
    i64.const -1
    i64.xor
    i64.store offset=832
    local.get 19
    local.get 20
    local.get 21
    i64.sub
    i64.store offset=848
    local.get 19
    i32.const 832
    i32.add
    local.get 19
    i32.const 800
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 768
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=784
    local.get 19
    i64.const 4294967295
    i64.store offset=776
    local.get 19
    i64.const -1
    i64.store offset=768
    local.get 19
    i32.const 768
    i32.add
    local.get 19
    i32.const 736
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 896
    i32.add
    local.get 19
    i32.const 800
    i32.add
    local.get 19
    i32.const 736
    i32.add
    local.get 19
    i32.const 704
    i32.add
    call $wrapper_addmod
    local.get 18
    local.get 19
    i32.const 672
    i32.add
    call $wrapper_mload_bytes32
    local.get 19
    i32.const 640
    i32.add
    i32.const 24
    i32.add
    local.get 16
    i64.store
    local.get 19
    local.get 15
    i64.store offset=656
    local.get 19
    local.get 14
    i64.store offset=648
    local.get 19
    local.get 13
    i64.store offset=640
    local.get 19
    i32.const 640
    i32.add
    local.get 19
    i32.const 608
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 576
    i32.add
    i32.const 24
    i32.add
    local.get 16
    i64.store
    local.get 19
    local.get 15
    i64.store offset=592
    local.get 19
    local.get 14
    i64.store offset=584
    local.get 19
    local.get 13
    i64.store offset=576
    local.get 19
    i32.const 576
    i32.add
    local.get 19
    i32.const 544
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 512
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=528
    local.get 19
    i64.const 4294967295
    i64.store offset=520
    local.get 19
    i64.const -1
    i64.store offset=512
    local.get 19
    i32.const 512
    i32.add
    local.get 19
    i32.const 480
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 608
    i32.add
    local.get 19
    i32.const 544
    i32.add
    local.get 19
    i32.const 480
    i32.add
    local.get 19
    i32.const 448
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 416
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=432
    local.get 19
    i64.const 4294967295
    i64.store offset=424
    local.get 19
    i64.const -1
    i64.store offset=416
    local.get 19
    i32.const 416
    i32.add
    local.get 19
    i32.const 384
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 672
    i32.add
    local.get 19
    i32.const 448
    i32.add
    local.get 19
    i32.const 384
    i32.add
    local.get 19
    i32.const 352
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 320
    i32.add
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 19
    local.get 7
    i64.store offset=336
    local.get 19
    local.get 6
    i64.store offset=328
    local.get 19
    local.get 5
    i64.store offset=320
    local.get 19
    i32.const 320
    i32.add
    local.get 19
    i32.const 288
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 256
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=272
    local.get 19
    i64.const 4294967295
    i64.store offset=264
    local.get 19
    i64.const -1
    i64.store offset=256
    local.get 19
    i32.const 256
    i32.add
    local.get 19
    i32.const 224
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 288
    i32.add
    local.get 19
    i32.const 1664
    i32.add
    local.get 19
    i32.const 224
    i32.add
    local.get 19
    i32.const 192
    i32.add
    call $wrapper_mulmod
    local.get 19
    i32.const 352
    i32.add
    local.get 19
    i32.const 160
    i32.add
    call $u256_from_big_endian_bytes
    local.get 19
    i32.const 128
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    local.get 19
    i32.const 160
    i32.add
    i32.const 24
    i32.add
    i64.load
    local.get 19
    i32.const 160
    i32.add
    i32.const 16
    i32.add
    i64.load
    local.tee 1
    i64.const 0
    i64.ne
    i64.extend_i32_u
    i64.add
    i64.const 0
    local.get 1
    i64.sub
    local.tee 20
    i32.const 0
    local.get 19
    i32.const 160
    i32.add
    i32.const 8
    i32.add
    i64.load
    local.tee 1
    i64.const 4294967295
    i64.gt_u
    local.get 1
    i64.const 4294967295
    i64.eq
    select
    i64.extend_i32_u
    local.tee 21
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.sub
    i64.store
    local.get 19
    i64.const 4294967295
    local.get 1
    i64.sub
    i64.store offset=136
    local.get 19
    local.get 19
    i64.load offset=160
    i64.const -1
    i64.xor
    i64.store offset=128
    local.get 19
    local.get 20
    local.get 21
    i64.sub
    i64.store offset=144
    local.get 19
    i32.const 128
    i32.add
    local.get 19
    i32.const 96
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    i64.const -4294967295
    i64.store
    local.get 19
    i64.const 0
    i64.store offset=80
    local.get 19
    i64.const 4294967295
    i64.store offset=72
    local.get 19
    i64.const -1
    i64.store offset=64
    local.get 19
    i32.const 64
    i32.add
    local.get 19
    i32.const 32
    i32.add
    call $u256_to_big_endian_bytes
    local.get 19
    i32.const 192
    i32.add
    local.get 19
    i32.const 96
    i32.add
    local.get 19
    i32.const 32
    i32.add
    local.get 19
    call $wrapper_addmod
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 19
            i32.const 704
            i32.add
            call $wrapper_bytes32_iszero
            local.get 19
            call $wrapper_bytes32_iszero
            i32.and
            br_table 0 (;@4;) 1 (;@3;) 2 (;@2;)
          end
          local.get 17
          i32.const -32
          i32.add
          local.tee 18
          local.tee 17
          global.set $__stack_pointer
          local.get 18
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 18
          i64.const 0
          i64.store offset=16
          local.get 18
          i64.const 4294967295
          i64.store offset=8
          local.get 18
          i64.const -1
          i64.store
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 18
          local.get 17
          call $u256_to_big_endian_bytes
          local.get 22
          i32.const -32
          i32.add
          local.tee 18
          local.tee 22
          global.set $__stack_pointer
          local.get 19
          local.get 19
          local.get 17
          local.get 18
          call $wrapper_mulmod
          local.get 22
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 23
          i32.const -32
          i32.add
          local.tee 23
          local.tee 17
          global.set $__stack_pointer
          local.get 19
          i32.const 704
          i32.add
          local.get 19
          i32.const 704
          i32.add
          local.get 22
          local.get 23
          call $wrapper_mulmod
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 24
          local.tee 17
          global.set $__stack_pointer
          local.get 19
          local.get 18
          local.get 22
          local.get 24
          call $wrapper_mulmod
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 24
          local.get 17
          call $u256_from_big_endian_bytes
          local.get 17
          i32.const 8
          i32.add
          i64.load
          local.set 8
          local.get 17
          i32.const 16
          i32.add
          i64.load
          local.set 7
          local.get 17
          i32.const 24
          i32.add
          i64.load
          local.set 12
          local.get 17
          i64.load
          local.set 11
          local.get 22
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i64.const 0
          local.get 7
          i64.sub
          local.tee 10
          i32.const 0
          local.get 8
          i64.const 4294967295
          i64.gt_u
          local.get 8
          i64.const 4294967295
          i64.eq
          select
          i64.extend_i32_u
          local.tee 9
          i64.sub
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          local.get 8
          i64.sub
          i64.store offset=8
          local.get 17
          local.get 11
          i64.const -1
          i64.xor
          i64.store
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          local.get 12
          local.get 7
          i64.const 0
          i64.ne
          i64.extend_i32_u
          i64.add
          local.get 10
          local.get 9
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.sub
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 17
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 24
          i32.const -32
          i32.add
          local.tee 24
          local.tee 25
          global.set $__stack_pointer
          local.get 17
          local.get 24
          call $u256_to_big_endian_bytes
          local.get 25
          i32.const -32
          i32.add
          local.tee 25
          local.tee 17
          global.set $__stack_pointer
          local.get 23
          local.get 22
          local.get 24
          local.get 25
          call $wrapper_addmod
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 23
          i32.const -32
          i32.add
          local.tee 23
          local.tee 17
          global.set $__stack_pointer
          local.get 19
          i32.const 352
          i32.add
          local.get 18
          local.get 22
          local.get 23
          call $wrapper_mulmod
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const 0
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 0
          i64.store offset=8
          local.get 17
          i64.const 2
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 17
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 24
          i32.const -32
          i32.add
          local.tee 24
          local.tee 26
          global.set $__stack_pointer
          local.get 17
          local.get 24
          call $u256_to_big_endian_bytes
          local.get 26
          i32.const -32
          i32.add
          local.tee 26
          local.tee 17
          global.set $__stack_pointer
          local.get 22
          local.get 23
          local.get 24
          local.get 26
          call $wrapper_mulmod
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 26
          local.get 17
          call $u256_from_big_endian_bytes
          local.get 17
          i32.const 8
          i32.add
          i64.load
          local.set 8
          local.get 17
          i32.const 16
          i32.add
          i64.load
          local.set 7
          local.get 17
          i32.const 24
          i32.add
          i64.load
          local.set 12
          local.get 17
          i64.load
          local.set 11
          local.get 22
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i64.const 0
          local.get 7
          i64.sub
          local.tee 10
          i32.const 0
          local.get 8
          i64.const 4294967295
          i64.gt_u
          local.get 8
          i64.const 4294967295
          i64.eq
          select
          i64.extend_i32_u
          local.tee 9
          i64.sub
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          local.get 8
          i64.sub
          i64.store offset=8
          local.get 17
          local.get 11
          i64.const -1
          i64.xor
          i64.store
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          local.get 12
          local.get 7
          i64.const 0
          i64.ne
          i64.extend_i32_u
          i64.add
          local.get 10
          local.get 9
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.sub
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 23
          i32.const -32
          i32.add
          local.tee 17
          local.tee 23
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 23
          i32.const -32
          i32.add
          local.tee 23
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          local.get 23
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 17
          local.tee 24
          global.set $__stack_pointer
          local.get 25
          local.get 22
          local.get 23
          local.get 17
          call $wrapper_addmod
          local.get 17
          local.get 19
          i32.const 1856
          i32.add
          call $u256_from_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 23
          i32.const -32
          i32.add
          local.tee 23
          local.tee 17
          global.set $__stack_pointer
          local.get 19
          i32.const 352
          i32.add
          local.get 18
          local.get 22
          local.get 23
          call $wrapper_mulmod
          local.get 19
          i32.const 1856
          i32.add
          i32.const 8
          i32.add
          i64.load
          local.set 8
          local.get 19
          i32.const 1856
          i32.add
          i32.const 16
          i32.add
          i64.load
          local.set 7
          local.get 19
          i32.const 1856
          i32.add
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 19
          i64.load offset=1856
          local.set 5
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i64.const 0
          local.get 7
          i64.sub
          local.tee 12
          i32.const 0
          local.get 8
          i64.const 4294967295
          i64.gt_u
          local.get 8
          i64.const 4294967295
          i64.eq
          select
          i64.extend_i32_u
          local.tee 11
          i64.sub
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          local.get 8
          i64.sub
          i64.store offset=8
          local.get 17
          local.get 5
          i64.const -1
          i64.xor
          i64.store
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          local.get 6
          local.get 7
          i64.const 0
          i64.ne
          i64.extend_i32_u
          i64.add
          local.get 12
          local.get 11
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.sub
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 17
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 24
          i32.const -32
          i32.add
          local.tee 24
          local.tee 25
          global.set $__stack_pointer
          local.get 17
          local.get 24
          call $u256_to_big_endian_bytes
          local.get 25
          i32.const -32
          i32.add
          local.tee 25
          local.tee 17
          global.set $__stack_pointer
          local.get 23
          local.get 22
          local.get 24
          local.get 25
          call $wrapper_addmod
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 23
          i32.const -32
          i32.add
          local.tee 23
          local.tee 17
          global.set $__stack_pointer
          local.get 19
          i32.const 704
          i32.add
          local.get 25
          local.get 22
          local.get 23
          call $wrapper_mulmod
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 17
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 17
          i64.const 0
          i64.store offset=16
          local.get 17
          i64.const 4294967295
          i64.store offset=8
          local.get 17
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 17
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 17
          local.tee 24
          global.set $__stack_pointer
          local.get 19
          local.get 18
          local.get 22
          local.get 17
          call $wrapper_mulmod
          local.get 24
          i32.const -32
          i32.add
          local.tee 18
          local.tee 22
          global.set $__stack_pointer
          local.get 18
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 18
          i64.const 0
          i64.store offset=16
          local.get 18
          i64.const 4294967295
          i64.store offset=8
          local.get 18
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 18
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 24
          local.tee 18
          global.set $__stack_pointer
          local.get 19
          i32.const 1152
          i32.add
          local.get 17
          local.get 22
          local.get 24
          call $wrapper_mulmod
          local.get 18
          i32.const -32
          i32.add
          local.tee 18
          local.tee 17
          global.set $__stack_pointer
          local.get 24
          local.get 18
          call $u256_from_big_endian_bytes
          local.get 18
          i32.const 8
          i32.add
          i64.load
          local.set 12
          local.get 18
          i32.const 16
          i32.add
          i64.load
          local.set 11
          local.get 18
          i32.const 24
          i32.add
          i64.load
          local.set 10
          local.get 18
          i64.load
          local.set 9
          local.get 17
          i32.const -32
          i32.add
          local.tee 18
          local.tee 17
          global.set $__stack_pointer
          local.get 18
          i64.const 0
          local.get 11
          i64.sub
          local.tee 1
          i32.const 0
          local.get 12
          i64.const 4294967295
          i64.gt_u
          local.get 12
          i64.const 4294967295
          i64.eq
          select
          i64.extend_i32_u
          local.tee 20
          i64.sub
          i64.store offset=16
          local.get 18
          i64.const 4294967295
          local.get 12
          i64.sub
          i64.store offset=8
          local.get 18
          local.get 9
          i64.const -1
          i64.xor
          i64.store
          local.get 18
          i32.const 24
          i32.add
          i64.const -4294967295
          local.get 10
          local.get 11
          i64.const 0
          i64.ne
          i64.extend_i32_u
          i64.add
          local.get 1
          local.get 20
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.sub
          i64.store
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 18
          local.get 17
          call $u256_to_big_endian_bytes
          local.get 22
          i32.const -32
          i32.add
          local.tee 18
          local.tee 22
          global.set $__stack_pointer
          local.get 18
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 18
          i64.const 0
          i64.store offset=16
          local.get 18
          i64.const 4294967295
          i64.store offset=8
          local.get 18
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 18
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 18
          local.tee 24
          global.set $__stack_pointer
          local.get 23
          local.get 17
          local.get 22
          local.get 18
          call $wrapper_addmod
          local.get 18
          local.get 19
          i32.const 1792
          i32.add
          call $u256_from_big_endian_bytes
          local.get 24
          i32.const -32
          i32.add
          local.tee 18
          local.tee 17
          global.set $__stack_pointer
          local.get 18
          i32.const 24
          i32.add
          local.get 16
          i64.store
          local.get 18
          local.get 15
          i64.store offset=16
          local.get 18
          local.get 14
          i64.store offset=8
          local.get 18
          local.get 13
          i64.store
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 18
          local.get 17
          call $u256_to_big_endian_bytes
          local.get 22
          i32.const -32
          i32.add
          local.tee 18
          local.tee 22
          global.set $__stack_pointer
          local.get 18
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 18
          i64.const 0
          i64.store offset=16
          local.get 18
          i64.const 4294967295
          i64.store offset=8
          local.get 18
          i64.const -1
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 18
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 23
          i32.const -32
          i32.add
          local.tee 23
          local.tee 18
          global.set $__stack_pointer
          local.get 19
          i32.const 1760
          i32.add
          local.get 17
          local.get 22
          local.get 23
          call $wrapper_mulmod
          local.get 18
          i32.const -32
          i32.add
          local.tee 18
          local.tee 17
          global.set $__stack_pointer
          local.get 18
          i32.const 24
          i32.add
          i64.const -4294967295
          i64.store
          local.get 18
          i64.const 0
          i64.store offset=16
          local.get 18
          i64.const 4294967295
          i64.store offset=8
          local.get 18
          i64.const -1
          i64.store
          local.get 17
          i32.const -32
          i32.add
          local.tee 17
          local.tee 22
          global.set $__stack_pointer
          local.get 18
          local.get 17
          call $u256_to_big_endian_bytes
          local.get 22
          i32.const -32
          i32.add
          local.tee 18
          global.set $__stack_pointer
          local.get 19
          local.get 23
          local.get 17
          local.get 18
          call $wrapper_mulmod
          local.get 18
          local.get 19
          i32.const 1824
          i32.add
          call $u256_from_big_endian_bytes
          br 2 (;@1;)
        end
        local.get 17
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 12
        i64.store
        local.get 18
        local.get 11
        i64.store offset=16
        local.get 18
        local.get 10
        i64.store offset=8
        local.get 18
        local.get 9
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 22
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        local.get 22
        call $u256_to_big_endian_bytes
        local.get 17
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 12
        i64.store
        local.get 18
        local.get 11
        i64.store offset=16
        local.get 18
        local.get 10
        i64.store offset=8
        local.get 18
        local.get 9
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 23
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 17
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 24
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 17
        i32.const -32
        i32.add
        local.tee 17
        local.tee 18
        global.set $__stack_pointer
        local.get 22
        local.get 23
        local.get 24
        local.get 17
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 16
        i64.store
        local.get 18
        local.get 15
        i64.store offset=16
        local.get 18
        local.get 14
        i64.store offset=8
        local.get 18
        local.get 13
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 23
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 22
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 16
        i64.store
        local.get 18
        local.get 15
        i64.store offset=16
        local.get 18
        local.get 14
        i64.store offset=8
        local.get 18
        local.get 13
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 24
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 22
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 25
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        local.get 25
        call $u256_to_big_endian_bytes
        local.get 22
        i32.const -32
        i32.add
        local.tee 22
        local.tee 18
        global.set $__stack_pointer
        local.get 23
        local.get 24
        local.get 25
        local.get 22
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 8
        i64.store
        local.get 18
        local.get 7
        i64.store offset=16
        local.get 18
        local.get 6
        i64.store offset=8
        local.get 18
        local.get 5
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 8
        i64.store
        local.get 18
        local.get 7
        i64.store offset=16
        local.get 18
        local.get 6
        i64.store offset=8
        local.get 18
        local.get 5
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 25
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 18
        local.tee 25
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 26
        global.set $__stack_pointer
        local.get 18
        local.get 25
        call $u256_to_big_endian_bytes
        local.get 26
        i32.const -32
        i32.add
        local.tee 26
        local.tee 18
        global.set $__stack_pointer
        local.get 23
        local.get 24
        local.get 25
        local.get 26
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 0
        i64.store offset=8
        local.get 18
        i64.const 3
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 25
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 18
        global.set $__stack_pointer
        local.get 23
        local.get 26
        local.get 24
        local.get 25
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 18
        global.set $__stack_pointer
        local.get 22
        local.get 22
        local.get 23
        local.get 24
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -4
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 22
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        local.get 22
        call $u256_to_big_endian_bytes
        local.get 23
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 26
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 26
        i32.const -32
        i32.add
        local.tee 26
        local.tee 18
        global.set $__stack_pointer
        local.get 22
        local.get 24
        local.get 23
        local.get 26
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 23
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 22
        i32.const -32
        i32.add
        local.tee 22
        local.tee 18
        global.set $__stack_pointer
        local.get 25
        local.get 26
        local.get 23
        local.get 22
        call $wrapper_addmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 8
        i64.store
        local.get 18
        local.get 7
        i64.store offset=16
        local.get 18
        local.get 6
        i64.store offset=8
        local.get 18
        local.get 5
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 25
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 18
        global.set $__stack_pointer
        local.get 23
        local.get 17
        local.get 24
        local.get 25
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 0
        i64.store offset=8
        local.get 18
        i64.const 4
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 24
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 23
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 26
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        local.get 26
        call $u256_to_big_endian_bytes
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 18
        global.set $__stack_pointer
        local.get 24
        local.get 25
        local.get 26
        local.get 23
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 25
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 18
        global.set $__stack_pointer
        local.get 22
        local.get 22
        local.get 24
        local.get 25
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 0
        i64.store offset=8
        local.get 18
        i64.const 2
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 26
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 26
        i32.const -32
        i32.add
        local.tee 18
        local.tee 26
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 26
        i32.const -32
        i32.add
        local.tee 26
        local.tee 27
        global.set $__stack_pointer
        local.get 18
        local.get 26
        call $u256_to_big_endian_bytes
        local.get 27
        i32.const -32
        i32.add
        local.tee 27
        local.tee 18
        global.set $__stack_pointer
        local.get 24
        local.get 23
        local.get 26
        local.get 27
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 27
        local.get 18
        call $u256_from_big_endian_bytes
        local.get 18
        i32.const 8
        i32.add
        i64.load
        local.set 8
        local.get 18
        i32.const 16
        i32.add
        i64.load
        local.set 7
        local.get 18
        i32.const 24
        i32.add
        i64.load
        local.set 6
        local.get 18
        i64.load
        local.set 5
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i64.const 0
        local.get 7
        i64.sub
        local.tee 1
        i32.const 0
        local.get 8
        i64.const 4294967295
        i64.gt_u
        local.get 8
        i64.const 4294967295
        i64.eq
        select
        i64.extend_i32_u
        local.tee 20
        i64.sub
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        local.get 8
        i64.sub
        i64.store offset=8
        local.get 18
        local.get 5
        i64.const -1
        i64.xor
        i64.store
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        local.get 6
        local.get 7
        i64.const 0
        i64.ne
        i64.extend_i32_u
        i64.add
        local.get 1
        local.get 20
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.sub
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 26
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 26
        i32.const -32
        i32.add
        local.tee 18
        local.tee 26
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 26
        i32.const -32
        i32.add
        local.tee 26
        local.tee 27
        global.set $__stack_pointer
        local.get 18
        local.get 26
        call $u256_to_big_endian_bytes
        local.get 27
        i32.const -32
        i32.add
        local.tee 18
        local.tee 27
        global.set $__stack_pointer
        local.get 25
        local.get 24
        local.get 26
        local.get 18
        call $wrapper_addmod
        local.get 18
        local.get 19
        i32.const 1888
        i32.add
        call $u256_from_big_endian_bytes
        local.get 27
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 25
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 18
        global.set $__stack_pointer
        local.get 17
        local.get 17
        local.get 24
        local.get 25
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 0
        i64.store offset=8
        local.get 18
        i64.const 8
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 17
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 17
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 26
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 26
        i32.const -32
        i32.add
        local.tee 26
        local.tee 18
        global.set $__stack_pointer
        local.get 17
        local.get 25
        local.get 24
        local.get 26
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 26
        local.get 18
        call $u256_from_big_endian_bytes
        local.get 19
        i32.const 1888
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.set 8
        local.get 19
        i32.const 1888
        i32.add
        i32.const 16
        i32.add
        i64.load
        local.set 7
        local.get 18
        i64.load
        local.set 21
        local.get 18
        i32.const 8
        i32.add
        i64.load
        local.set 1
        local.get 18
        i32.const 24
        i32.add
        i64.load
        local.set 28
        local.get 18
        i32.const 16
        i32.add
        i64.load
        local.set 20
        local.get 19
        i32.const 1888
        i32.add
        i32.const 24
        i32.add
        i64.load
        local.set 6
        local.get 19
        i64.load offset=1888
        local.set 5
        local.get 17
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i64.const 0
        local.get 7
        i64.sub
        local.tee 29
        i32.const 0
        local.get 8
        i64.const 4294967295
        i64.gt_u
        local.get 8
        i64.const 4294967295
        i64.eq
        select
        i64.extend_i32_u
        local.tee 30
        i64.sub
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        local.get 8
        i64.sub
        i64.store offset=8
        local.get 18
        local.get 5
        i64.const -1
        i64.xor
        i64.store
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        local.get 6
        local.get 7
        i64.const 0
        i64.ne
        i64.extend_i32_u
        i64.add
        local.get 29
        local.get 30
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.sub
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 17
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 17
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 25
        global.set $__stack_pointer
        local.get 18
        local.get 24
        call $u256_to_big_endian_bytes
        local.get 25
        i32.const -32
        i32.add
        local.tee 25
        local.tee 18
        global.set $__stack_pointer
        local.get 23
        local.get 17
        local.get 24
        local.get 25
        call $wrapper_addmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 17
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        local.get 17
        call $u256_to_big_endian_bytes
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 18
        global.set $__stack_pointer
        local.get 22
        local.get 25
        local.get 17
        local.get 23
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        local.get 28
        local.get 20
        i64.const 0
        i64.ne
        i64.extend_i32_u
        i64.add
        i64.const 0
        local.get 20
        i64.sub
        local.tee 20
        i32.const 0
        local.get 1
        i64.const 4294967295
        i64.gt_u
        local.get 1
        i64.const 4294967295
        i64.eq
        select
        i64.extend_i32_u
        local.tee 28
        i64.lt_u
        i64.extend_i32_u
        i64.add
        i64.sub
        i64.store
        local.get 18
        local.get 20
        local.get 28
        i64.sub
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        local.get 1
        i64.sub
        i64.store offset=8
        local.get 18
        local.get 21
        i64.const -1
        i64.xor
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 17
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        local.get 17
        call $u256_to_big_endian_bytes
        local.get 22
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 22
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 22
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 24
        global.set $__stack_pointer
        local.get 23
        local.get 17
        local.get 22
        local.get 18
        call $wrapper_addmod
        local.get 18
        local.get 19
        i32.const 1792
        i32.add
        call $u256_from_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 12
        i64.store
        local.get 18
        local.get 11
        i64.store offset=16
        local.get 18
        local.get 10
        i64.store offset=8
        local.get 18
        local.get 9
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 17
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        local.get 17
        call $u256_to_big_endian_bytes
        local.get 22
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        local.get 16
        i64.store
        local.get 18
        local.get 15
        i64.store offset=16
        local.get 18
        local.get 14
        i64.store offset=8
        local.get 18
        local.get 13
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 22
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        local.get 22
        call $u256_to_big_endian_bytes
        local.get 23
        i32.const -32
        i32.add
        local.tee 18
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 23
        i32.const -32
        i32.add
        local.tee 23
        local.tee 24
        global.set $__stack_pointer
        local.get 18
        local.get 23
        call $u256_to_big_endian_bytes
        local.get 24
        i32.const -32
        i32.add
        local.tee 24
        local.tee 18
        global.set $__stack_pointer
        local.get 17
        local.get 22
        local.get 23
        local.get 24
        call $wrapper_mulmod
        local.get 18
        i32.const -32
        i32.add
        local.tee 18
        local.tee 17
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 0
        i64.store offset=8
        local.get 18
        i64.const 2
        i64.store
        local.get 17
        i32.const -32
        i32.add
        local.tee 17
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        local.get 17
        call $u256_to_big_endian_bytes
        local.get 22
        i32.const -32
        i32.add
        local.tee 18
        local.tee 22
        global.set $__stack_pointer
        local.get 18
        i32.const 24
        i32.add
        i64.const -4294967295
        i64.store
        local.get 18
        i64.const 0
        i64.store offset=16
        local.get 18
        i64.const 4294967295
        i64.store offset=8
        local.get 18
        i64.const -1
        i64.store
        local.get 22
        i32.const -32
        i32.add
        local.tee 22
        local.tee 23
        global.set $__stack_pointer
        local.get 18
        local.get 22
        call $u256_to_big_endian_bytes
        local.get 23
        i32.const -32
        i32.add
        local.tee 18
        global.set $__stack_pointer
        local.get 17
        local.get 24
        local.get 22
        local.get 18
        call $wrapper_mulmod
        local.get 18
        local.get 19
        i32.const 1824
        i32.add
        call $u256_from_big_endian_bytes
        br 1 (;@1;)
      end
      local.get 19
      i32.const 1792
      i32.add
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 19
      i32.const 1824
      i32.add
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 19
      i64.const 0
      i64.store offset=1808
      local.get 19
      i64.const 0
      i64.store offset=1800
      local.get 19
      i64.const 0
      i64.store offset=1792
      local.get 19
      i64.const 0
      i64.store offset=1840
      local.get 19
      i64.const 0
      i64.store offset=1832
      local.get 19
      i64.const 0
      i64.store offset=1824
      i64.const 0
      local.set 5
      i64.const 0
      local.set 8
      i64.const 0
      local.set 7
      i64.const 0
      local.set 6
    end
    local.get 0
    local.get 19
    i64.load offset=1824
    i64.store offset=64
    local.get 0
    local.get 19
    i64.load offset=1792
    i64.store offset=32
    local.get 0
    local.get 5
    i64.store
    local.get 0
    local.get 8
    i64.store offset=8
    local.get 0
    i32.const 88
    i32.add
    local.get 19
    i32.const 1824
    i32.add
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 80
    i32.add
    local.get 19
    i32.const 1824
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 72
    i32.add
    local.get 19
    i32.const 1824
    i32.add
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 56
    i32.add
    local.get 19
    i32.const 1792
    i32.add
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 48
    i32.add
    local.get 19
    i32.const 1792
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 40
    i32.add
    local.get 19
    i32.const 1792
    i32.add
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 0
    local.get 7
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 6
    i64.store
    local.get 19
    i32.const 1920
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__affineFromJacobian_2254 (type 15) (param i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i64 i64 i64 i64 i32 i64 i64 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 160
    i32.sub
    local.tee 13
    local.set 14
    local.get 13
    global.set $__stack_pointer
    i64.const 0
    local.set 15
    block  ;; label = @1
      block  ;; label = @2
        local.get 9
        local.get 11
        i64.or
        local.get 10
        local.get 12
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i64.const 0
        local.set 16
        i64.const 0
        local.set 17
        i64.const 0
        local.set 18
        i64.const 0
        local.set 12
        i64.const 0
        local.set 10
        i64.const 0
        local.set 11
        i64.const 0
        local.set 9
        br 1 (;@1;)
      end
      i32.const 66080
      local.get 14
      i32.const 128
      i32.add
      call $u256_from_big_endian_bytes
      local.get 14
      local.get 9
      local.get 10
      local.get 11
      local.get 12
      local.get 14
      i64.load offset=128
      local.tee 16
      i64.const -2
      i64.add
      local.tee 17
      local.get 14
      i32.const 128
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.tee 15
      local.get 17
      local.get 16
      i64.lt_u
      local.tee 19
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.tee 18
      local.get 14
      i32.const 128
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.tee 17
      i64.const -1
      i64.add
      local.tee 20
      local.get 19
      local.get 18
      local.get 15
      i64.lt_u
      local.get 18
      local.get 15
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 21
      local.get 14
      i32.const 128
      i32.add
      i32.const 24
      i32.add
      local.tee 19
      i64.load
      local.tee 18
      local.get 20
      local.get 17
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 21
      local.get 20
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.get 16
      local.get 15
      local.get 17
      local.get 18
      call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_tryModExp_905
      local.get 14
      i32.const 56
      i32.add
      i64.load
      local.set 12
      local.get 14
      i32.const 48
      i32.add
      i64.load
      local.set 10
      local.get 14
      i32.const 40
      i32.add
      i64.load
      local.set 11
      local.get 14
      i64.load offset=32
      local.set 9
      block  ;; label = @2
        local.get 14
        i64.load
        local.get 14
        i32.const 16
        i32.add
        i64.load
        i64.or
        local.get 14
        i32.const 8
        i32.add
        i64.load
        local.get 14
        i32.const 24
        i32.add
        i64.load
        i64.or
        i64.or
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
        i32.const 0
        i32.const 1313373041
        call $wrapper_mstore_u32
        local.get 19
        i64.const 0
        i64.store
        local.get 14
        i64.const 0
        i64.store offset=144
        local.get 14
        i64.const 0
        i64.store offset=136
        local.get 14
        i64.const 18
        i64.store offset=128
        i32.const 32
        local.get 14
        i32.const 128
        i32.add
        call $wrapper_mstore_u256
        i32.const 28
        i32.const 36
        call $wrapper_revert
      end
      local.get 13
      i32.const -32
      i32.add
      local.tee 13
      local.tee 19
      global.set $__stack_pointer
      local.get 13
      local.get 9
      i64.store
      local.get 13
      local.get 11
      i64.store offset=8
      local.get 13
      local.get 10
      i64.store offset=16
      local.get 13
      i32.const 24
      i32.add
      local.get 12
      i64.store
      local.get 19
      i32.const -32
      i32.add
      local.tee 22
      local.tee 19
      global.set $__stack_pointer
      local.get 13
      local.get 22
      call $u256_to_big_endian_bytes
      local.get 19
      i32.const -32
      i32.add
      local.tee 13
      local.tee 19
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 12
      i64.store
      local.get 13
      local.get 10
      i64.store offset=16
      local.get 13
      local.get 11
      i64.store offset=8
      local.get 13
      local.get 9
      i64.store
      local.get 19
      i32.const -32
      i32.add
      local.tee 23
      local.tee 19
      global.set $__stack_pointer
      local.get 13
      local.get 23
      call $u256_to_big_endian_bytes
      local.get 19
      i32.const -32
      i32.add
      local.tee 13
      local.tee 19
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 18
      i64.store
      local.get 13
      local.get 17
      i64.store offset=16
      local.get 13
      local.get 15
      i64.store offset=8
      local.get 13
      local.get 16
      i64.store
      local.get 19
      i32.const -32
      i32.add
      local.tee 24
      local.tee 19
      global.set $__stack_pointer
      local.get 13
      local.get 24
      call $u256_to_big_endian_bytes
      local.get 19
      i32.const -32
      i32.add
      local.tee 19
      local.tee 13
      global.set $__stack_pointer
      local.get 22
      local.get 23
      local.get 24
      local.get 19
      call $wrapper_mulmod
      local.get 13
      i32.const -32
      i32.add
      local.tee 13
      local.tee 22
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 4
      i64.store
      local.get 13
      local.get 3
      i64.store offset=16
      local.get 13
      local.get 2
      i64.store offset=8
      local.get 13
      local.get 1
      i64.store
      local.get 22
      i32.const -32
      i32.add
      local.tee 22
      local.tee 23
      global.set $__stack_pointer
      local.get 13
      local.get 22
      call $u256_to_big_endian_bytes
      local.get 23
      i32.const -32
      i32.add
      local.tee 13
      local.tee 23
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 18
      i64.store
      local.get 13
      local.get 17
      i64.store offset=16
      local.get 13
      local.get 15
      i64.store offset=8
      local.get 13
      local.get 16
      i64.store
      local.get 23
      i32.const -32
      i32.add
      local.tee 23
      local.tee 24
      global.set $__stack_pointer
      local.get 13
      local.get 23
      call $u256_to_big_endian_bytes
      local.get 24
      i32.const -32
      i32.add
      local.tee 13
      local.tee 24
      global.set $__stack_pointer
      local.get 22
      local.get 19
      local.get 23
      local.get 13
      call $wrapper_mulmod
      local.get 13
      local.get 14
      i32.const 64
      i32.add
      call $u256_from_big_endian_bytes
      local.get 24
      i32.const -32
      i32.add
      local.tee 13
      local.tee 22
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 12
      i64.store
      local.get 13
      local.get 10
      i64.store offset=16
      local.get 13
      local.get 11
      i64.store offset=8
      local.get 13
      local.get 9
      i64.store
      local.get 22
      i32.const -32
      i32.add
      local.tee 22
      local.tee 23
      global.set $__stack_pointer
      local.get 13
      local.get 22
      call $u256_to_big_endian_bytes
      local.get 23
      i32.const -32
      i32.add
      local.tee 13
      local.tee 23
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 18
      i64.store
      local.get 13
      local.get 17
      i64.store offset=16
      local.get 13
      local.get 15
      i64.store offset=8
      local.get 13
      local.get 16
      i64.store
      local.get 23
      i32.const -32
      i32.add
      local.tee 23
      local.tee 24
      global.set $__stack_pointer
      local.get 13
      local.get 23
      call $u256_to_big_endian_bytes
      local.get 24
      i32.const -32
      i32.add
      local.tee 24
      local.tee 13
      global.set $__stack_pointer
      local.get 19
      local.get 22
      local.get 23
      local.get 24
      call $wrapper_mulmod
      local.get 13
      i32.const -32
      i32.add
      local.tee 13
      local.tee 19
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 8
      i64.store
      local.get 13
      local.get 7
      i64.store offset=16
      local.get 13
      local.get 6
      i64.store offset=8
      local.get 13
      local.get 5
      i64.store
      local.get 19
      i32.const -32
      i32.add
      local.tee 19
      local.tee 22
      global.set $__stack_pointer
      local.get 13
      local.get 19
      call $u256_to_big_endian_bytes
      local.get 22
      i32.const -32
      i32.add
      local.tee 13
      local.tee 22
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      local.get 18
      i64.store
      local.get 13
      local.get 17
      i64.store offset=16
      local.get 13
      local.get 15
      i64.store offset=8
      local.get 13
      local.get 16
      i64.store
      local.get 22
      i32.const -32
      i32.add
      local.tee 22
      local.tee 23
      global.set $__stack_pointer
      local.get 13
      local.get 22
      call $u256_to_big_endian_bytes
      local.get 23
      i32.const -32
      i32.add
      local.tee 13
      global.set $__stack_pointer
      local.get 19
      local.get 24
      local.get 22
      local.get 13
      call $wrapper_mulmod
      local.get 13
      local.get 14
      i32.const 96
      i32.add
      call $u256_from_big_endian_bytes
      local.get 14
      i32.const 96
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 14
      i32.const 96
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 17
      local.get 14
      i32.const 96
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 16
      local.get 14
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 9
      local.get 14
      i32.const 64
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 11
      local.get 14
      i32.const 64
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 10
      local.get 14
      i64.load offset=96
      local.set 15
      local.get 14
      i64.load offset=64
      local.set 12
    end
    local.get 0
    local.get 15
    i64.store offset=32
    local.get 0
    local.get 12
    i64.store
    local.get 0
    i32.const 40
    i32.add
    local.get 16
    i64.store
    local.get 0
    local.get 10
    i64.store offset=8
    local.get 0
    i32.const 48
    i32.add
    local.get 17
    i64.store
    local.get 0
    local.get 11
    i64.store offset=16
    local.get 0
    i32.const 56
    i32.add
    local.get 18
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 9
    i64.store
    local.get 14
    i32.const 160
    i32.add
    global.set $__stack_pointer)
  (func $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.init (type 7)
    (local i32 i32 i64 i64 i64 i64)
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
      local.get 0
      i32.const -32
      i32.add
      local.tee 0
      global.set $__stack_pointer
      i32.const 0
      local.get 0
      call $wrapper_calldataload_bytes32
      local.get 0
      local.get 1
      i32.const 64
      i32.add
      call $u256_from_big_endian_bytes
      local.get 1
      i32.const 64
      i32.add
      i32.const 224
      local.get 1
      i32.const 32
      i32.add
      call $wrapper_u256_shr
      local.get 1
      i64.load offset=32
      i64.const 2917788737
      i64.xor
      local.get 1
      i32.const 48
      i32.add
      i64.load
      i64.or
      local.get 1
      i32.const 40
      i32.add
      i64.load
      local.get 1
      i32.const 56
      i32.add
      i64.load
      i64.or
      i64.or
      i64.eqz
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        call $wrapper_calldata_size
        i32.const 3
        i32.gt_u
        br_if 0 (;@2;)
        i32.const 0
        i32.const 0
        call $wrapper_revert
      end
      local.get 1
      call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_test_ecdsa_verify_p256_51
      local.get 1
      i32.const 16
      i32.add
      i64.load
      local.set 2
      local.get 1
      i32.const 24
      i32.add
      i64.load
      local.set 3
      local.get 1
      i32.const 8
      i32.add
      i64.load
      local.set 4
      local.get 1
      i64.load
      local.set 5
      i32.const 64
      local.get 1
      i32.const 64
      i32.add
      call $wrapper_mload_u256
      local.get 1
      i32.load offset=64
      local.set 0
      local.get 1
      i32.const 64
      i32.add
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 1
      i64.const 0
      i64.store offset=80
      local.get 1
      i64.const 0
      i64.store offset=72
      local.get 1
      local.get 5
      local.get 2
      i64.or
      local.get 4
      local.get 3
      i64.or
      i64.or
      i64.const 0
      i64.ne
      i64.extend_i32_u
      i64.store offset=64
      local.get 0
      local.get 1
      i32.const 64
      i32.add
      call $wrapper_mstore_u256
      local.get 0
      i32.const 32
      call $wrapper_return
    end
    i32.const 0
    i32.const 0
    call $wrapper_revert
    local.get 1
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $call (type 7)
    call $testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.init)
  (func $_start (type 7)
    i32.const 1
    call $__init_evm_heap)
  (func $deploy (type 7)
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
    i32.const 83664
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
  (data $.rodata (i32.const 65536) "out length is not enough\00call contract failed\00call failed with no revert data\00\00\00\ff\ff\ff\ff")
  (data $.data (i32.const 65632) "\08\c3y\a0")
  (data (;2;) (i32.const 65664) "\af+\db\e1\aa\9bn\c1\e2\ad\e1\d6\94\f4\1f\c7\1a\83\1d\02h\e9\89\15b\11=\8ab\ad\d1\bf\ef\d4\8b*\ac\b6\a8\fd\11@\dd\9c\d4^\81\d6\9d,\87{V\aa\f9\91\c3M\0e\a8N\af7\16\084\e3j\d2\9a\83\bf+\c98^I\1d`\99\c8\fd\f9\d1\edg\aa~\a5\f5\1f\93x(W\a9`\fe\d4\ba%Z\9d1\c9a\ebt\c65mh\c0I\b8\92;a\fal\e6ib.`\f2\9f\b6y\03\fe\10\08\b8\bc\99\a4\1a\e9\e9V(\bcd\f2\f1\b2\0c-~\9fQw\a3\c2\94\d4F\22\99\ff\ff\ff\ff\00\00\00\00\ff\ff\ff\ff\ff\ff\ff\ff\bc\e6\fa\ad\a7\17\9e\84\f3\b9\ca\c2\fcc%QNH{q")
  (data (;3;) (i32.const 65888) "\7f\ff\ff\ff\80\00\00\00\7f\ff\ff\ff\ff\ff\ff\ff\des}V\d3\8b\cfBy\dc\e5a~1\92\a8NH{q")
  (data (;4;) (i32.const 65976) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;5;) (i32.const 66008) "\ff\ff\ff\ff\ff\ff\ff\ffk\17\d1\f2\e1,BG\f8\bc\e6\e5c\a4@\f2w\03}\81-\eb3\a0\f4\a19E\d8\98\c2\96O\e3B\e2\fe\1a\7f\9b\8e\e7\ebJ|\0f\9e\16+\ce3Wk1^\ce\cb\b6@h7\bfQ\f5\ff\ff\ff\ff\00\00\00\01")
  (data (;6;) (i32.const 66100) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;7;) (i32.const 67256) "\01")
  (data (;8;) (i32.const 67262) "\02\00\00\00\03")
  (data (;9;) (i32.const 67274) "\01")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "producers" "\02\08language\01\03C99\00\0cprocessed-by\01\05clangV11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)")
  (@custom "name" "\01\db\0e9\00\0fgetCallDataSize\01\0ccallDataCopy\02\0cgetCallValue\03\06revert\04\06finish\05\0bgetCodeSize\06\08codeCopy\07\11getReturnDataSize\08\0ereturnDataCopy\09\0acallStatic\0a\0agetGasLeft\0b\06addmod\0c\06mulmod\0d\11__wasm_call_ctors\0e\08__multi3\0f\1au256_from_big_endian_bytes\10\18u256_to_big_endian_bytes\11\1bi32_from_big_endian_bytes32\12\1cwrapper_calldataload_bytes32\13\15wrapper_calldata_size\14\1awrapper_callvalue_not_zero\15\0ewrapper_revert\16\13evm_get_memory_addr\17\10wrapper_codecopy\18\14wrapper_memory_guard\19\16wrapper_mstore_bytes32\1a\13wrapper_mstore_u256\1b\12wrapper_mstore_u32\1c\12wrapper_mload_u256\1d\15wrapper_mload_bytes32\1e\0ewrapper_return\1f\0fwrite_call_data \12wrapper_staticcall!\0bwrapper_gas\22\13set_is_deploying_tx#\0ewrapper_addmod$\0ewrapper_mulmod%\0f__init_evm_heap&\12wrapper_bytes32_eq'\16wrapper_bytes32_iszero(\10wrapper_u256_shl)\10wrapper_u256_shr*]testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_test_ecdsa_verify_p256_51+WtestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_verifySolidity_2002,YtestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_isValidPublicKey_2179-btestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__preComputeJacobianPoints_2649.QtestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun_tryModExp_905/UtestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jMultShamir_24420StestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.finalize_allocation1\93\01testEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.zero_complex_memory_array_t_array$_t_struct$_JPoint_$1709_memory_ptr_$16_memory_ptr2QtestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jDouble_22933NtestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__jAdd_22754\5ctestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.fun__affineFromJacobian_22545DtestEcdsaR1Contract_52_deployed.testEcdsaR1Contract_52_deployed.init6\04call7\06_start8\06deploy\07\12\01\00\0f__stack_pointer\09\11\02\00\07.rodata\01\05.data")
  (@custom ".debug_str" "y\00x\00low\00wasisdk://v12.0/build/compiler-rt\00du_int\00ti_int\00di_int\00long long int\00long long unsigned int\00uint64_t\00twords\00r\00all\00lower_mask\00high\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins/multi3.c\00b\00a\00__int128\00__multi3\00__mulddi3\00bits_in_dword_2\00clang version 11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\00")
  (@custom ".debug_line" "M\01\00\00\04\00\c2\00\00\00\01\01\01\fb\0e\0d\00\01\01\01\01\00\00\00\01\00\00\01wasisdk://v12.0/build/install/opt/wasi-sdk/share/wasi-sysroot/include/bits\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins\00\00alltypes.h\00\01\00\00int_types.h\00\02\00\00multi3.c\00\02\00\00\00\04\03\00\05\02\05\00\00\00\03'\01\05\03\0aD\05,-\05\18\06X\05\0c\06\03rX\05\0b\1eo\05&`\05\0c\06<\05#\06\03u \05\10\06\ac\05\1e\90\03i<\05\16\06\03\18J\05\1f\22\05\05\06X\03f \05\10\06\03\1cJ\05\22\03\13 \05\0f\03n \05\1f\92\05\05\06X\03a \05\11\06\03!J\05\0c\03\0e \05\03!\05\1f\03pX\05\0b\03yX\97\05\03\03\10 \02\04\00\01\01")
  (@custom ".debug_abbrev" "\01\11\01%\0e\13\05\03\0e\10\17\1b\0e\11\01\12\06\00\00\02$\00\03\0e>\0b\0b\0b\00\00\03\16\00I\13\03\0e:\0b;\0b\00\00\04.\01\03\0e:\0b;\0b'\19I\13 \0b\00\00\05\05\00\03\0e:\0b;\0bI\13\00\00\064\00\03\0e:\0b;\0bI\13\00\00\07\17\01\0b\0b:\0b;\0b\00\00\08\0d\00\03\0eI\13:\0b;\0b8\0b\00\00\09\13\01\0b\0b:\0b;\0b\00\00\0a&\00I\13\00\00\0b.\01\11\01\12\06@\18\97B\19\03\0e:\0b;\0b'\19I\13?\19\00\00\0c\05\00\02\17\03\0e:\0b;\0bI\13\00\00\0d4\00\02\17\03\0e:\0b;\0bI\13\00\00\0e\1d\011\13U\17X\0bY\0bW\0b\00\00\0f\05\001\13\00\00\104\00\02\171\13\00\00\114\00\1c\0d1\13\00\00\124\00\1c\0f1\13\00\00\00")
  (@custom ".debug_ranges" "\0f\00\00\00G\00\00\00H\00\00\00\5c\00\00\00b\00\00\00q\00\00\00\00\00\00\00\00\00\00\00")
  (@custom ".debug_loc" "\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\007\00\00\009\00\00\00\06\00\ed\02\02\9f\93\089\00\00\00G\00\00\00\06\00\ed\00\05\9f\93\08G\00\00\00H\00\00\00\0c\00\ed\00\05\9f\93\08\ed\02\02\9f\93\08H\00\00\00p\00\00\00\06\00\ed\00\05\9f\93\08p\00\00\00q\00\00\00\06\00\ed\02\02\9f\93\08q\00\00\00t\00\00\00\06\00\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00]\00\00\00`\00\00\00\08\00\93\08\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00<\00\00\00B\00\00\00\04\00\ed\02\02\9fQ\00\00\00Y\00\00\00\04\00\ed\02\02\9fY\00\00\00u\00\00\00\04\00\ed\00\03\9f\00\00\00\00\00\00\00\00")
  (@custom ".debug_info" "\b4\01\00\00\04\00\00\00\00\00\04\01\fd\00\00\00\0c\00\8a\00\00\00\00\00\00\00\08\00\00\00\05\00\00\00u\00\00\00\02`\00\00\00\05\04\038\00\00\00*\00\00\00\02&\03C\00\00\00d\00\00\00\01\aa\02M\00\00\00\07\08\04\e3\00\00\00\03\13\99\00\00\00\01\05\cf\00\00\00\03\13-\00\00\00\05\cd\00\00\00\03\13-\00\00\00\06t\00\00\00\03\14\ab\00\00\00\06\ed\00\00\00\03\15\0d\01\00\00\06z\00\00\00\03\16\12\01\00\00\06k\00\00\00\03\18-\00\00\00\00\03\a4\00\00\001\00\00\00\02O\02\d1\00\00\00\05\10\03\b6\00\00\00m\00\00\00\02]\07\10\02R\08v\00\00\00\99\00\00\00\02S\00\08r\00\00\00\d2\00\00\00\02\5c\00\09\10\02T\08\04\00\00\00-\00\00\00\02V\00\08\85\00\00\00\f0\00\00\00\02W\08\00\00\03\fb\00\00\008\00\00\00\02%\03\06\01\00\00e\00\00\00\01\91\02?\00\00\00\05\08\0a&\00\00\00\0a-\00\00\00\0b\05\00\00\00u\00\00\00\07\ed\03\00\00\00\00\9f\da\00\00\00\03(\99\00\00\00\0c\00\00\00\00\cf\00\00\00\03(\99\00\00\00\0c\14\00\00\00\cd\00\00\00\03(\99\00\00\00\0d(\00\00\00\00\00\00\00\03+\ab\00\00\00\0d\aa\00\00\00\02\00\00\00\03)\ab\00\00\00\0d\be\00\00\00t\00\00\00\03-\ab\00\00\00\0eJ\00\00\00\00\00\00\00\03.\0b\0fV\00\00\00\0fa\00\00\00\10<\00\00\00l\00\00\00\11 w\00\00\00\12\ff\ff\ff\ff\0f\82\00\00\00\10\d8\00\00\00\8d\00\00\00\00\00\00"))
