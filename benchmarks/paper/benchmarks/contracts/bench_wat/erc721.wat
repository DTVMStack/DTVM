(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32 i32)))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func (param i32 i32 i32 i32 i32 i32 i32)))
  (type (;5;) (func (param i64 i32 i32 i32 i32) (result i32)))
  (type (;6;) (func (result i64)))
  (type (;7;) (func (param i32) (result i32)))
  (type (;8;) (func))
  (type (;9;) (func (param i32 i32 i32 i32 i32)))
  (type (;10;) (func (param i32 i32 i32 i32 i32 i32)))
  (type (;11;) (func (param i32 i32 i32) (result i32)))
  (type (;12;) (func (param i64 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;13;) (func (param i32 i32) (result i32)))
  (type (;14;) (func (param i32 i64 i64 i64 i64)))
  (type (;15;) (func (param i64 i64 i64 i64)))
  (type (;16;) (func (param i64 i64 i64 i64 i64 i64 i64 i64)))
  (type (;17;) (func (param i32 i32 i64 i64 i64 i64)))
  (type (;18;) (func (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)))
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
  (import "env" "getReturnDataSize" (func $getReturnDataSize (type 0)))
  (import "env" "returnDataCopy" (func $returnDataCopy (type 1)))
  (import "env" "callContract" (func $callContract (type 5)))
  (import "env" "getGasLeft" (func $getGasLeft (type 6)))
  (import "env" "getExternalCodeSize" (func $getExternalCodeSize (type 7)))
  (func $__wasm_call_ctors (type 8))
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
  (func $i32_to_bytes32_big_endian_bytes (type 3) (param i32 i32)
    local.get 1
    local.get 0
    i32.store8 offset=31
    local.get 1
    i32.const 0
    i32.store offset=24
    local.get 1
    i64.const 0
    i64.store offset=16
    local.get 1
    i64.const 0
    i64.store offset=8
    local.get 1
    i64.const 0
    i64.store
    local.get 1
    local.get 0
    i32.const 8
    i32.shr_u
    i32.store8 offset=30
    local.get 1
    local.get 0
    i32.const 16
    i32.shr_u
    i32.store8 offset=29
    local.get 1
    local.get 0
    i32.const 24
    i32.shr_u
    i32.store8 offset=28)
  (func $i32_from_big_endian_bytes32 (type 7) (param i32) (result i32)
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
              i32.load8_u offset=67540
              br_if 0 (;@5;)
              i32.const 67440
              i32.const 0
              local.get 3
              call $callDataCopy
              i32.const 0
              i32.const 1
              i32.store8 offset=67540
            end
            local.get 4
            i32.eqz
            br_if 2 (;@2;)
            local.get 0
            i32.const 67440
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
            i32.load8_u offset=67540
            br_if 0 (;@4;)
            i32.const 67440
            i32.const 0
            local.get 2
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=67540
          end
          local.get 1
          local.get 0
          i32.const 67440
          i32.add
          i32.load8_u
          i32.store8
          local.get 1
          local.get 0
          i32.const 67441
          i32.add
          i32.load8_u
          i32.store8 offset=1
          local.get 1
          local.get 0
          i32.const 67442
          i32.add
          i32.load8_u
          i32.store8 offset=2
          local.get 1
          local.get 0
          i32.const 67443
          i32.add
          i32.load8_u
          i32.store8 offset=3
          local.get 1
          local.get 0
          i32.const 67444
          i32.add
          i32.load8_u
          i32.store8 offset=4
          local.get 1
          local.get 0
          i32.const 67445
          i32.add
          i32.load8_u
          i32.store8 offset=5
          local.get 1
          local.get 0
          i32.const 67446
          i32.add
          i32.load8_u
          i32.store8 offset=6
          local.get 1
          local.get 0
          i32.const 67447
          i32.add
          i32.load8_u
          i32.store8 offset=7
          local.get 1
          local.get 0
          i32.const 67448
          i32.add
          i32.load8_u
          i32.store8 offset=8
          local.get 1
          local.get 0
          i32.const 67449
          i32.add
          i32.load8_u
          i32.store8 offset=9
          local.get 1
          local.get 0
          i32.const 67450
          i32.add
          i32.load8_u
          i32.store8 offset=10
          local.get 1
          local.get 0
          i32.const 67451
          i32.add
          i32.load8_u
          i32.store8 offset=11
          local.get 1
          local.get 0
          i32.const 67452
          i32.add
          i32.load8_u
          i32.store8 offset=12
          local.get 1
          local.get 0
          i32.const 67453
          i32.add
          i32.load8_u
          i32.store8 offset=13
          local.get 1
          local.get 0
          i32.const 67454
          i32.add
          i32.load8_u
          i32.store8 offset=14
          local.get 1
          local.get 0
          i32.const 67455
          i32.add
          i32.load8_u
          i32.store8 offset=15
          local.get 1
          local.get 0
          i32.const 67456
          i32.add
          i32.load8_u
          i32.store8 offset=16
          local.get 1
          local.get 0
          i32.const 67457
          i32.add
          i32.load8_u
          i32.store8 offset=17
          local.get 1
          local.get 0
          i32.const 67458
          i32.add
          i32.load8_u
          i32.store8 offset=18
          local.get 1
          local.get 0
          i32.const 67459
          i32.add
          i32.load8_u
          i32.store8 offset=19
          local.get 1
          local.get 0
          i32.const 67460
          i32.add
          i32.load8_u
          i32.store8 offset=20
          local.get 1
          local.get 0
          i32.const 67461
          i32.add
          i32.load8_u
          i32.store8 offset=21
          local.get 1
          local.get 0
          i32.const 67462
          i32.add
          i32.load8_u
          i32.store8 offset=22
          local.get 1
          local.get 0
          i32.const 67463
          i32.add
          i32.load8_u
          i32.store8 offset=23
          local.get 1
          local.get 0
          i32.const 67464
          i32.add
          i32.load8_u
          i32.store8 offset=24
          local.get 1
          local.get 0
          i32.const 67465
          i32.add
          i32.load8_u
          i32.store8 offset=25
          local.get 1
          local.get 0
          i32.const 67466
          i32.add
          i32.load8_u
          i32.store8 offset=26
          local.get 1
          local.get 0
          i32.const 67467
          i32.add
          i32.load8_u
          i32.store8 offset=27
          local.get 1
          local.get 0
          i32.const 67468
          i32.add
          i32.load8_u
          i32.store8 offset=28
          local.get 1
          local.get 0
          i32.const 67469
          i32.add
          i32.load8_u
          i32.store8 offset=29
          local.get 1
          local.get 0
          i32.const 67470
          i32.add
          i32.load8_u
          i32.store8 offset=30
          local.get 1
          local.get 0
          i32.const 67471
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
          i32.load8_u offset=67540
          br_if 0 (;@3;)
          i32.const 67440
          i32.const 0
          local.get 2
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=67540
        end
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.const 4
              i32.ge_u
              br_if 0 (;@5;)
              i32.const 67440
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
            i32.const 67440
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
              i32.const 67440
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
        i32.store offset=65616
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
          i32.load8_u offset=67540
          br_if 0 (;@3;)
          i32.const 67440
          i32.const 0
          local.get 2
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=67540
        end
        local.get 0
        i32.const 0
        i32.load offset=67440
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
    i32.load offset=67548
    local.get 0
    i32.add
    local.get 1
    call $revert)
  (func $evm_get_memory_addr (type 7) (param i32) (result i32)
    i32.const 0
    i32.load offset=67548
    local.get 0
    i32.add)
  (func $wrapper_codecopy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=67560
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
        i32.store offset=67556
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=67560
        i32.const 0
        i32.const 0
        i32.load offset=67552
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=67552
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=67556
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=67556
    end
    i32.const 0
    i32.load offset=67548
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
          i32.load8_u offset=67540
          br_if 0 (;@3;)
          i32.const 67440
          i32.const 0
          local.get 1
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=67540
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.const 67440
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
      i32.load offset=67560
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
      i32.store offset=67556
      i32.const 0
      local.get 2
      i32.const -65536
      i32.and
      i32.store offset=67560
      i32.const 0
      i32.const 0
      i32.load offset=67552
      local.get 1
      i32.const 16
      i32.shl
      i32.add
      i32.store offset=67552
      i32.const 96
      return
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=67556
      local.get 0
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 0
      i32.store offset=67556
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
          i32.load offset=67560
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
          i32.store offset=67556
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=67560
          i32.const 0
          i32.const 0
          i32.load offset=67552
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67552
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67556
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=67556
      end
      i32.const 0
      i32.load offset=67548
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
          i32.load offset=67560
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
          i32.store offset=67556
          i32.const 0
          local.get 7
          i32.const -65536
          i32.and
          i32.store offset=67560
          i32.const 0
          i32.const 0
          i32.load offset=67552
          local.get 1
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67552
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67556
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=67556
      end
      i32.const 0
      i32.load offset=67548
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
          i32.load offset=67560
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
          i32.store offset=67556
          i32.const 0
          local.get 4
          i32.const -65536
          i32.and
          i32.store offset=67560
          i32.const 0
          i32.const 0
          i32.load offset=67552
          local.get 3
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67552
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67556
        local.get 2
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 2
        i32.store offset=67556
      end
      i32.const 0
      i32.load offset=67548
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
    i32.load offset=67548
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
    i32.load offset=67548
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
    i32.load offset=67548
    local.get 0
    i32.add
    local.get 1
    local.get 2
    call $keccak256)
  (func $wrapper_return (type 3) (param i32 i32)
    i32.const 0
    i32.load offset=67548
    local.get 0
    i32.add
    local.get 1
    call $finish)
  (func $wrapper_log3 (type 9) (param i32 i32 i32 i32 i32)
    i32.const 0
    i32.load offset=67548
    local.get 0
    i32.add
    local.get 1
    i32.const 3
    local.get 2
    local.get 3
    local.get 4
    i32.const 0
    call $emitLogEvent)
  (func $wrapper_log4 (type 10) (param i32 i32 i32 i32 i32 i32)
    i32.const 0
    i32.load offset=67548
    local.get 0
    i32.add
    local.get 1
    i32.const 4
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    call $emitLogEvent)
  (func $write_call_data (type 11) (param i32 i32 i32) (result i32)
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
              i32.load offset=67560
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
              i32.store offset=67556
              i32.const 0
              local.get 4
              i32.const -65536
              i32.and
              i32.store offset=67560
              i32.const 0
              i32.const 0
              i32.load offset=67552
              local.get 2
              i32.const 16
              i32.shl
              i32.add
              i32.store offset=67552
              br 1 (;@4;)
            end
            i32.const 0
            i32.load offset=67556
            local.get 0
            i32.ge_u
            br_if 0 (;@4;)
            i32.const 0
            local.get 0
            i32.store offset=67556
          end
          i32.const 0
          i32.load offset=67548
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
          i32.const 66400
          i32.const 0
          local.get 3
          call $returnDataCopy
          i32.const 66400
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
          i32.load offset=67560
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
          i32.store offset=67556
          i32.const 0
          local.get 5
          i32.const -65536
          i32.and
          i32.store offset=67560
          i32.const 0
          i32.const 0
          i32.load offset=67552
          local.get 4
          i32.const 16
          i32.shl
          i32.add
          i32.store offset=67552
          br 1 (;@2;)
        end
        i32.const 0
        i32.load offset=67556
        local.get 3
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.get 3
        i32.store offset=67556
      end
      i32.const 0
      i32.load offset=67548
      local.get 1
      i32.add
      i32.const 0
      local.get 2
      call $returnDataCopy
    end
    local.get 0
    i32.eqz)
  (func $wrapper_returndata_copy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=67560
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
        i32.store offset=67556
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=67560
        i32.const 0
        i32.const 0
        i32.load offset=67552
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=67552
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=67556
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=67556
    end
    i32.const 0
    i32.load offset=67548
    local.get 0
    i32.add
    local.get 1
    local.get 2
    call $returnDataCopy)
  (func $wrapper_call_contract (type 12) (param i64 i32 i32 i32 i32 i32 i32) (result i32)
    (local i32 i64 i64 i64 i64 i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 7
    global.set $__stack_pointer
    local.get 2
    i32.const 8
    i32.add
    i64.load
    local.set 8
    local.get 2
    i32.const 16
    i32.add
    i64.load
    local.set 9
    local.get 2
    i64.load
    local.set 10
    local.get 7
    local.get 2
    i32.const 24
    i32.add
    i64.load
    local.tee 11
    i64.const 40
    i64.shr_u
    i64.store8 offset=2
    local.get 7
    local.get 11
    i64.const 56
    i64.shr_u
    i64.store8
    local.get 7
    local.get 9
    i64.const 40
    i64.shr_u
    i64.store8 offset=10
    local.get 7
    local.get 9
    i64.const 56
    i64.shr_u
    i64.store8 offset=8
    local.get 7
    local.get 11
    i64.const 32
    i64.shr_u
    i64.store8 offset=3
    local.get 7
    local.get 11
    i64.const 48
    i64.shr_u
    i64.store8 offset=1
    local.get 7
    local.get 8
    i64.const 40
    i64.shr_u
    i64.store8 offset=18
    local.get 7
    local.get 8
    i64.const 56
    i64.shr_u
    i64.store8 offset=16
    local.get 7
    local.get 9
    i64.const 32
    i64.shr_u
    i64.store8 offset=11
    local.get 7
    local.get 9
    i64.const 48
    i64.shr_u
    i64.store8 offset=9
    local.get 7
    local.get 8
    i32.wrap_i64
    local.tee 2
    i32.const 8
    i32.shr_u
    i32.store8 offset=22
    local.get 7
    local.get 2
    i32.const 24
    i32.shr_u
    i32.store8 offset=20
    local.get 7
    local.get 11
    i32.wrap_i64
    local.tee 12
    i32.store8 offset=7
    local.get 7
    local.get 12
    i32.const 8
    i32.shr_u
    i32.store8 offset=6
    local.get 7
    local.get 12
    i32.const 24
    i32.shr_u
    i32.store8 offset=4
    local.get 7
    local.get 9
    i32.wrap_i64
    local.tee 13
    i32.store8 offset=15
    local.get 7
    local.get 13
    i32.const 8
    i32.shr_u
    i32.store8 offset=14
    local.get 7
    local.get 13
    i32.const 24
    i32.shr_u
    i32.store8 offset=12
    local.get 7
    local.get 12
    i32.const 16
    i32.shr_u
    i32.store8 offset=5
    local.get 7
    local.get 13
    i32.const 16
    i32.shr_u
    i32.store8 offset=13
    local.get 7
    local.get 10
    i64.const 40
    i64.shr_u
    i64.store8 offset=26
    local.get 7
    local.get 10
    i64.const 56
    i64.shr_u
    i64.store8 offset=24
    local.get 7
    local.get 2
    i32.store8 offset=23
    local.get 7
    local.get 2
    i32.const 16
    i32.shr_u
    i32.store8 offset=21
    local.get 7
    local.get 8
    i64.const 32
    i64.shr_u
    i64.store8 offset=19
    local.get 7
    local.get 8
    i64.const 48
    i64.shr_u
    i64.store8 offset=17
    local.get 7
    local.get 10
    i64.const 32
    i64.shr_u
    i64.store8 offset=27
    local.get 7
    local.get 10
    i64.const 48
    i64.shr_u
    i64.store8 offset=25
    local.get 7
    local.get 10
    i32.wrap_i64
    local.tee 2
    i32.store8 offset=31
    local.get 7
    local.get 2
    i32.const 8
    i32.shr_u
    i32.store8 offset=30
    local.get 7
    local.get 2
    i32.const 24
    i32.shr_u
    i32.store8 offset=28
    local.get 7
    local.get 2
    i32.const 16
    i32.shr_u
    i32.store8 offset=29
    local.get 0
    local.get 1
    i32.const 12
    i32.add
    local.get 7
    i32.const 0
    i32.load offset=67548
    local.get 3
    i32.add
    local.get 4
    call $callContract
    local.get 5
    local.get 6
    call $write_call_data
    local.set 2
    local.get 7
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $wrapper_gas (type 6) (result i64)
    call $getGasLeft)
  (func $wrapper_returndata_size (type 0) (result i32)
    call $getReturnDataSize)
  (func $wrapper_calldata_copy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=67560
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
        i32.store offset=67556
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=67560
        i32.const 0
        i32.const 0
        i32.load offset=67552
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=67552
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=67556
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=67556
    end
    i32.const 0
    i32.load offset=67548
    local.set 3
    block  ;; label = @1
      i32.const 0
      i32.load offset=65616
      local.tee 4
      i32.const -1
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      call $getCallDataSize
      local.tee 4
      i32.store offset=65616
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
            i32.store offset=65616
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
            i32.load8_u offset=67540
            br_if 0 (;@4;)
            i32.const 67440
            i32.const 0
            local.get 3
            call $callDataCopy
            i32.const 0
            i32.const 1
            i32.store8 offset=67540
          end
          local.get 5
          i32.eqz
          br_if 1 (;@2;)
          local.get 1
          i32.const 67440
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
          i32.store offset=65616
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
          i32.load8_u offset=67540
          br_if 0 (;@3;)
          i32.const 67440
          i32.const 0
          local.get 4
          call $callDataCopy
          i32.const 0
          i32.const 1
          i32.store8 offset=67540
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        i32.const 67440
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
  (func $set_is_deploying_tx (type 8)
    i32.const 0
    i32.const 1
    i32.store8 offset=67424)
  (func $wrapper_extcode_size (type 7) (param i32) (result i32)
    local.get 0
    i32.const 12
    i32.add
    call $getExternalCodeSize)
  (func $wrapper_data_copy (type 1) (param i32 i32 i32)
    (local i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=67560
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
        i32.store offset=67556
        i32.const 0
        local.get 5
        i32.const -65536
        i32.and
        i32.store offset=67560
        i32.const 0
        i32.const 0
        i32.load offset=67552
        local.get 3
        i32.const 16
        i32.shl
        i32.add
        i32.store offset=67552
        br 1 (;@1;)
      end
      i32.const 0
      i32.load offset=67556
      local.get 4
      i32.ge_u
      br_if 0 (;@1;)
      i32.const 0
      local.get 4
      i32.store offset=67556
    end
    block  ;; label = @1
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      i32.load offset=67548
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
    local.get 0
    i32.const -4
    i32.add)
  (func $__init_evm_heap (type 8)
    (local i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load8_u offset=67544
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
          i32.store offset=67548
          i32.const 1
          memory.grow
          drop
          memory.size
          i32.const 16
          i32.shl
          local.tee 0
          i32.const 0
          i32.load offset=67548
          i32.sub
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 67568
        i32.store offset=67548
        i32.const 83952
        local.set 0
        i32.const 16384
        local.set 1
      end
      i32.const 0
      local.get 0
      i32.store offset=67552
      i32.const 0
      local.get 1
      i32.store offset=67560
      i32.const 0
      i32.const 1
      i32.store8 offset=67544
      i32.const 0
      i32.const 0
      i32.store offset=67556
    end)
  (func $wrapper_bytes32_eq (type 13) (param i32 i32) (result i32)
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
  (func $wrapper_bytes32_iszero (type 7) (param i32) (result i32)
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
  (func $wrapper_bytes32_add (type 1) (param i32 i32 i32)
    (local i32 i32 i32 i32 i32)
    i32.const 0
    local.set 3
    i32.const 0
    local.set 4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        local.get 3
        i32.add
        local.tee 5
        i32.const 31
        i32.add
        local.get 4
        local.get 0
        local.get 3
        i32.add
        local.tee 6
        i32.const 31
        i32.add
        i32.load8_u
        i32.add
        local.get 1
        local.get 3
        i32.add
        local.tee 4
        i32.const 31
        i32.add
        i32.load8_u
        i32.add
        local.tee 7
        i32.store8
        local.get 5
        i32.const 30
        i32.add
        local.get 7
        i32.const 8
        i32.shr_u
        local.get 6
        i32.const 30
        i32.add
        i32.load8_u
        i32.add
        local.get 4
        i32.const 30
        i32.add
        i32.load8_u
        i32.add
        local.tee 4
        i32.store8
        local.get 3
        i32.const -30
        i32.eq
        br_if 1 (;@1;)
        local.get 3
        i32.const -2
        i32.add
        local.set 3
        local.get 4
        i32.const 8
        i32.shr_u
        local.set 4
        br 0 (;@2;)
      end
    end)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.abi_decode_addresst_addresst_uint256 (type 14) (param i32 i64 i64 i64 i64)
    (local i32 i32 i64 i32)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 5
    local.set 6
    local.get 5
    global.set $__stack_pointer
    block  ;; label = @1
      local.get 1
      i64.const -4
      i64.add
      local.tee 7
      i64.const 95
      i64.gt_u
      local.get 2
      local.get 7
      local.get 1
      i64.lt_u
      local.tee 8
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.tee 1
      i64.const 0
      i64.ne
      local.get 1
      i64.eqz
      select
      local.get 3
      i64.const -1
      i64.add
      local.tee 7
      local.get 8
      local.get 1
      local.get 2
      i64.lt_u
      local.get 1
      local.get 2
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 2
      i64.const 0
      i64.ne
      local.get 4
      local.get 7
      local.get 3
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 2
      local.get 7
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.tee 1
      i64.const 0
      i64.gt_s
      local.get 1
      i64.eqz
      select
      local.get 2
      local.get 1
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      call $wrapper_revert
    end
    local.get 5
    i32.const -32
    i32.add
    local.tee 5
    local.tee 8
    global.set $__stack_pointer
    i32.const 4
    local.get 5
    call $wrapper_calldataload_bytes32
    local.get 5
    local.get 6
    call $u256_from_big_endian_bytes
    local.get 8
    i32.const -32
    i32.add
    local.tee 5
    local.tee 8
    global.set $__stack_pointer
    i32.const 36
    local.get 5
    call $wrapper_calldataload_bytes32
    local.get 5
    local.get 6
    i32.const 32
    i32.add
    call $u256_from_big_endian_bytes
    local.get 8
    i32.const -32
    i32.add
    local.tee 5
    global.set $__stack_pointer
    i32.const 68
    local.get 5
    call $wrapper_calldataload_bytes32
    local.get 5
    local.get 6
    i32.const 64
    i32.add
    call $u256_from_big_endian_bytes
    local.get 0
    local.get 6
    i64.load offset=64
    i64.store offset=64
    local.get 0
    local.get 6
    i64.load offset=32
    i64.store offset=32
    local.get 0
    local.get 6
    i32.const 16
    i32.add
    i64.load
    i64.store offset=16
    local.get 0
    local.get 6
    i32.const 8
    i32.add
    i64.load
    i64.store offset=8
    local.get 0
    local.get 6
    i64.load
    i64.store
    local.get 0
    i32.const 88
    i32.add
    local.get 6
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 80
    i32.add
    local.get 6
    i32.const 64
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 72
    i32.add
    local.get 6
    i32.const 64
    i32.add
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 56
    i32.add
    local.get 6
    i32.const 32
    i32.add
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 48
    i32.add
    local.get 6
    i32.const 32
    i32.add
    i32.const 16
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 40
    i32.add
    local.get 6
    i32.const 32
    i32.add
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.const 24
    i32.add
    local.get 6
    i32.const 24
    i32.add
    i64.load
    i64.store
    local.get 6
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation_17595 (type 15) (param i64 i64 i64 i64)
    (local i32 i32 i64 i32 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    i32.const 65632
    local.get 4
    local.tee 5
    call $u256_from_big_endian_bytes
    local.get 3
    local.get 2
    local.get 0
    i64.const 32
    i64.add
    local.tee 6
    local.get 0
    i64.lt_u
    local.tee 7
    local.get 1
    local.get 7
    i64.extend_i32_u
    i64.add
    local.tee 8
    local.get 1
    i64.lt_u
    local.get 6
    local.get 0
    i64.ge_u
    select
    i64.extend_i32_u
    i64.add
    local.tee 9
    local.get 2
    i64.lt_u
    i64.extend_i32_u
    i64.add
    local.set 10
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i64.const -33
        i64.gt_u
        i32.const 0
        local.get 1
        i64.const -1
        i64.eq
        select
        i32.const 0
        local.get 2
        local.get 3
        i64.and
        i64.const -1
        i64.eq
        select
        br_if 0 (;@2;)
        local.get 6
        local.get 5
        i64.load
        i64.le_u
        local.get 8
        local.get 5
        i32.const 8
        i32.add
        i64.load
        local.tee 0
        i64.le_u
        local.get 8
        local.get 0
        i64.eq
        select
        local.get 9
        local.get 5
        i32.const 16
        i32.add
        i64.load
        local.tee 1
        i64.le_u
        local.get 10
        local.get 5
        i32.const 24
        i32.add
        i64.load
        local.tee 0
        i64.le_u
        local.get 10
        local.get 0
        i64.eq
        select
        local.get 9
        local.get 1
        i64.xor
        local.get 10
        local.get 0
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 1 (;@1;)
      end
      local.get 4
      i32.const -32
      i32.add
      local.tee 7
      local.tee 4
      global.set $__stack_pointer
      local.get 7
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 7
      i64.const 0
      i64.store offset=16
      local.get 7
      i64.const 0
      i64.store offset=8
      local.get 7
      i64.const 0
      i64.store
      i32.const 0
      local.get 7
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 4
    i32.const -32
    i32.add
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    i32.const 24
    i32.add
    local.get 10
    i64.store
    local.get 4
    local.get 9
    i64.store offset=16
    local.get 4
    local.get 8
    i64.store offset=8
    local.get 4
    local.get 6
    i64.store
    i32.const 64
    local.get 4
    call $wrapper_mstore_u256
    local.get 5
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation (type 16) (param i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i64 i64 i64 i32 i64 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 8
    global.set $__stack_pointer
    i32.const 65664
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
      local.get 8
      i32.const -32
      i32.add
      local.tee 13
      local.tee 8
      global.set $__stack_pointer
      local.get 13
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 13
      i64.const 0
      i64.store offset=16
      local.get 13
      i64.const 0
      i64.store offset=8
      local.get 13
      i64.const 0
      i64.store
      i32.const 0
      local.get 13
      call $wrapper_mstore_u256
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
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.array_allocation_size_bytes (type 14) (param i32 i64 i64 i64 i64)
    (local i32 i32 i64 i64 i64 i64 i32 i64)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    i32.const 65696
    local.get 5
    local.tee 6
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      local.get 6
      i64.load
      local.get 1
      i64.ge_u
      local.get 6
      i32.const 8
      i32.add
      i64.load
      local.tee 7
      local.get 2
      i64.ge_u
      local.get 7
      local.get 2
      i64.eq
      select
      local.get 6
      i32.const 16
      i32.add
      i64.load
      local.tee 8
      local.get 3
      i64.ge_u
      local.get 6
      i32.const 24
      i32.add
      i64.load
      local.tee 7
      local.get 4
      i64.ge_u
      local.get 7
      local.get 4
      i64.eq
      select
      local.get 8
      local.get 3
      i64.xor
      local.get 7
      local.get 4
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      local.get 5
      i32.const -32
      i32.add
      local.tee 5
      global.set $__stack_pointer
      local.get 5
      i32.const 24
      i32.add
      i64.const 5640894258543067136
      i64.store
      local.get 5
      i64.const 0
      i64.store offset=16
      local.get 5
      i64.const 0
      i64.store offset=8
      local.get 5
      i64.const 0
      i64.store
      i32.const 0
      local.get 5
      call $wrapper_mstore_u256
      i32.const 4
      i32.const 65
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 36
      call $wrapper_revert
    end
    local.get 0
    local.get 1
    i64.const 31
    i64.add
    local.tee 7
    i64.const -32
    i64.and
    local.tee 8
    i64.const 32
    i64.add
    local.tee 9
    i64.store
    local.get 0
    local.get 2
    local.get 7
    local.get 1
    i64.lt_u
    local.tee 5
    i64.extend_i32_u
    i64.add
    local.tee 10
    local.get 9
    local.get 8
    i64.lt_u
    local.tee 11
    i64.extend_i32_u
    i64.add
    local.tee 12
    i64.store offset=8
    local.get 0
    local.get 3
    local.get 5
    local.get 10
    local.get 2
    i64.lt_u
    local.get 7
    local.get 1
    i64.ge_u
    select
    i64.extend_i32_u
    i64.add
    local.tee 2
    local.get 11
    local.get 12
    local.get 10
    i64.lt_u
    local.get 9
    local.get 8
    i64.ge_u
    select
    i64.extend_i32_u
    i64.add
    local.tee 1
    i64.store offset=16
    local.get 0
    i32.const 24
    i32.add
    local.get 4
    local.get 2
    local.get 3
    i64.lt_u
    i64.extend_i32_u
    i64.add
    local.get 1
    local.get 2
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.store
    local.get 6
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_transferFrom (type 17) (param i32 i32 i64 i64 i64 i64)
    (local i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 320
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    local.tee 7
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 7
    i64.const 4294967295
    i64.store offset=80
    local.get 7
    i64.const -1
    i64.store offset=72
    local.get 7
    i64.const -1
    i64.store offset=64
    local.get 7
    i32.const 64
    i32.add
    local.get 7
    i32.const 32
    i32.add
    call $u256_to_big_endian_bytes
    local.get 1
    local.get 7
    i32.const 32
    i32.add
    local.get 7
    call $wrapper_bytes32_and
    block  ;; label = @1
      local.get 7
      call $wrapper_bytes32_iszero
      i32.eqz
      br_if 0 (;@1;)
      local.get 6
      i32.const -32
      i32.add
      local.tee 1
      local.tee 6
      global.set $__stack_pointer
      i32.const 64
      local.get 1
      call $wrapper_mload_bytes32
      local.get 1
      call $i32_from_big_endian_bytes32
      local.set 8
      local.get 6
      i32.const -32
      i32.add
      local.tee 6
      local.tee 9
      global.set $__stack_pointer
      local.get 6
      i32.const 24
      i32.add
      i64.const 7250987342154956800
      i64.store
      local.get 6
      i64.const 0
      i64.store offset=16
      local.get 6
      i64.const 0
      i64.store offset=8
      local.get 6
      i64.const 0
      i64.store
      local.get 8
      local.get 6
      call $wrapper_mstore_u256
      local.get 9
      i32.const -32
      i32.add
      local.tee 9
      local.tee 6
      global.set $__stack_pointer
      local.get 1
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
    local.get 6
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    local.get 5
    i64.store
    local.get 6
    local.get 4
    i64.store offset=16
    local.get 6
    local.get 3
    i64.store offset=8
    local.get 6
    local.get 2
    i64.store
    i32.const 0
    local.get 6
    call $wrapper_mstore_u256
    i32.const 32
    i32.const 2
    call $wrapper_mstore_u32
    local.get 1
    i32.const -32
    i32.add
    local.tee 1
    local.tee 6
    global.set $__stack_pointer
    i32.const 0
    i32.const 64
    local.get 1
    call $wrapper_keccak256
    local.get 6
    i32.const -32
    i32.add
    local.tee 6
    local.tee 8
    global.set $__stack_pointer
    local.get 1
    local.get 6
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 6
    i32.const 8
    i32.add
    i64.load
    local.set 10
    local.get 6
    i64.load
    local.set 11
    local.get 6
    i32.const 16
    i32.add
    i64.load32_u
    local.set 12
    local.get 8
    i32.const -32
    i32.add
    local.tee 1
    local.tee 6
    global.set $__stack_pointer
    local.get 1
    call $wrapper_caller
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          call $wrapper_bytes32_iszero
          br_if 0 (;@3;)
          local.get 6
          i32.const -32
          i32.add
          local.tee 8
          local.tee 6
          global.set $__stack_pointer
          local.get 8
          call $wrapper_caller
          local.get 6
          i32.const -32
          i32.add
          local.tee 1
          local.tee 6
          global.set $__stack_pointer
          local.get 1
          i32.const 24
          i32.add
          i64.const 0
          i64.store
          local.get 1
          local.get 12
          i64.store offset=16
          local.get 1
          local.get 10
          i64.store offset=8
          local.get 1
          local.get 11
          i64.store
          local.get 6
          i32.const -32
          i32.add
          local.tee 9
          local.tee 6
          global.set $__stack_pointer
          local.get 1
          local.get 9
          call $u256_to_big_endian_bytes
          local.get 9
          local.get 8
          call $wrapper_bytes32_eq
          br_if 0 (;@3;)
          local.get 6
          i32.const -32
          i32.add
          local.tee 6
          local.tee 1
          global.set $__stack_pointer
          local.get 6
          i32.const 24
          i32.add
          i64.const 0
          i64.store
          local.get 6
          local.get 12
          i64.store offset=16
          local.get 6
          local.get 10
          i64.store offset=8
          local.get 6
          local.get 11
          i64.store
          i32.const 0
          local.get 6
          call $wrapper_mstore_u256
          i32.const 32
          i32.const 5
          call $wrapper_mstore_u32
          local.get 1
          i32.const -32
          i32.add
          local.tee 6
          local.tee 1
          global.set $__stack_pointer
          i32.const 0
          i32.const 64
          local.get 6
          call $wrapper_keccak256
          local.get 1
          i32.const -32
          i32.add
          local.tee 1
          local.tee 8
          global.set $__stack_pointer
          local.get 1
          call $wrapper_caller
          i32.const 0
          local.get 1
          call $wrapper_mstore_bytes32
          i32.const 32
          local.get 6
          call $wrapper_mstore_bytes32
          local.get 8
          i32.const -32
          i32.add
          local.tee 1
          local.tee 6
          global.set $__stack_pointer
          i32.const 0
          i32.const 64
          local.get 1
          call $wrapper_keccak256
          local.get 6
          i32.const -32
          i32.add
          local.tee 8
          local.tee 6
          global.set $__stack_pointer
          local.get 1
          local.get 8
          call $wrapper_sload_u256_using_little_endian_hostapi
          local.get 8
          i32.load8_u
          br_if 0 (;@3;)
          local.get 6
          i32.const -32
          i32.add
          local.tee 6
          local.tee 1
          global.set $__stack_pointer
          local.get 6
          i32.const 24
          i32.add
          local.get 5
          i64.store
          local.get 6
          local.get 4
          i64.store offset=16
          local.get 6
          local.get 3
          i64.store offset=8
          local.get 6
          local.get 2
          i64.store
          i32.const 0
          local.get 6
          call $wrapper_mstore_u256
          i32.const 32
          i32.const 4
          call $wrapper_mstore_u32
          local.get 1
          i32.const -32
          i32.add
          local.tee 1
          local.tee 6
          global.set $__stack_pointer
          i32.const 0
          i32.const 64
          local.get 1
          call $wrapper_keccak256
          local.get 6
          i32.const -32
          i32.add
          local.tee 6
          local.tee 8
          global.set $__stack_pointer
          local.get 1
          local.get 6
          call $wrapper_sload_u256_using_little_endian_hostapi
          local.get 6
          i64.load
          local.set 13
          local.get 6
          i32.const 8
          i32.add
          i64.load
          local.set 14
          local.get 6
          i32.const 16
          i32.add
          i64.load32_u
          local.set 15
          local.get 8
          i32.const -32
          i32.add
          local.tee 8
          local.tee 6
          global.set $__stack_pointer
          local.get 8
          call $wrapper_caller
          local.get 6
          i32.const -32
          i32.add
          local.tee 1
          local.tee 6
          global.set $__stack_pointer
          local.get 1
          i32.const 24
          i32.add
          i64.const 0
          i64.store
          local.get 1
          local.get 15
          i64.store offset=16
          local.get 1
          local.get 14
          i64.store offset=8
          local.get 1
          local.get 13
          i64.store
          local.get 6
          i32.const -32
          i32.add
          local.tee 9
          local.tee 6
          global.set $__stack_pointer
          local.get 1
          local.get 9
          call $u256_to_big_endian_bytes
          local.get 9
          local.get 8
          call $wrapper_bytes32_eq
          br_if 0 (;@3;)
          local.get 6
          i32.const -32
          i32.add
          local.tee 1
          local.tee 6
          global.set $__stack_pointer
          i32.const 64
          local.get 1
          call $wrapper_mload_bytes32
          local.get 1
          call $i32_from_big_endian_bytes32
          local.set 8
          local.get 6
          i32.const -32
          i32.add
          local.tee 6
          local.tee 9
          global.set $__stack_pointer
          block  ;; label = @4
            local.get 11
            local.get 12
            i64.or
            local.get 10
            i64.or
            i64.eqz
            br_if 0 (;@4;)
            local.get 6
            i64.const 0
            i64.store offset=16
            local.get 6
            i64.const 0
            i64.store offset=8
            local.get 6
            i64.const 0
            i64.store
            local.get 6
            i32.const 24
            i32.add
            i64.const 1692931449289703424
            i64.store
            local.get 8
            local.get 6
            call $wrapper_mstore_u256
            local.get 9
            i32.const -32
            i32.add
            local.tee 6
            local.tee 9
            global.set $__stack_pointer
            local.get 1
            local.get 6
            call $u256_from_big_endian_bytes
            local.get 6
            i32.load
            local.set 16
            local.get 9
            i32.const -32
            i32.add
            local.tee 6
            local.tee 9
            global.set $__stack_pointer
            local.get 6
            call $wrapper_caller
            local.get 16
            i32.const 4
            i32.add
            local.get 6
            call $wrapper_mstore_bytes32
            local.get 9
            i32.const -32
            i32.add
            local.tee 6
            local.tee 9
            global.set $__stack_pointer
            local.get 1
            local.get 6
            call $u256_from_big_endian_bytes
            local.get 6
            i32.load
            local.set 16
            local.get 9
            i32.const -32
            i32.add
            local.tee 1
            local.tee 6
            global.set $__stack_pointer
            local.get 1
            i32.const 24
            i32.add
            local.get 5
            i64.store
            local.get 1
            local.get 4
            i64.store offset=16
            local.get 1
            local.get 3
            i64.store offset=8
            local.get 1
            local.get 2
            i64.store
            local.get 16
            i32.const 36
            i32.add
            local.get 1
            call $wrapper_mstore_u256
            local.get 8
            i32.const 68
            call $wrapper_revert
            br 2 (;@2;)
          end
          local.get 6
          i64.const 0
          i64.store offset=16
          local.get 6
          i64.const 0
          i64.store offset=8
          local.get 6
          i64.const 0
          i64.store
          local.get 6
          i32.const 24
          i32.add
          i64.const 9090289936862543872
          i64.store
          local.get 8
          local.get 6
          call $wrapper_mstore_u256
          local.get 9
          i32.const -32
          i32.add
          local.tee 6
          local.tee 9
          global.set $__stack_pointer
          local.get 1
          local.get 6
          call $u256_from_big_endian_bytes
          local.get 6
          i32.load
          local.set 16
          local.get 9
          i32.const -32
          i32.add
          local.tee 1
          local.tee 6
          global.set $__stack_pointer
          local.get 1
          i32.const 24
          i32.add
          local.get 5
          i64.store
          local.get 1
          local.get 4
          i64.store offset=16
          local.get 1
          local.get 3
          i64.store offset=8
          local.get 1
          local.get 2
          i64.store
          local.get 16
          i32.const 4
          i32.add
          local.get 1
          call $wrapper_mstore_u256
          local.get 8
          i32.const 36
          call $wrapper_revert
          br 2 (;@1;)
        end
        local.get 11
        local.get 12
        i64.or
        local.get 10
        i64.or
        i64.eqz
        br_if 1 (;@1;)
      end
      local.get 7
      i32.const 288
      i32.add
      i32.const 24
      i32.add
      local.get 5
      i64.store
      local.get 7
      local.get 2
      i64.store offset=288
      local.get 7
      local.get 3
      i64.store offset=296
      local.get 7
      local.get 4
      i64.store offset=304
      i32.const 0
      local.get 7
      i32.const 288
      i32.add
      call $wrapper_mstore_u256
      i32.const 32
      i32.const 4
      call $wrapper_mstore_u32
      i32.const 0
      i32.const 64
      local.get 7
      i32.const 256
      i32.add
      call $wrapper_keccak256
      local.get 7
      i32.const 256
      i32.add
      local.get 7
      i32.const 224
      i32.add
      call $wrapper_sload_u256_using_little_endian_hostapi
      local.get 7
      i32.const 192
      i32.add
      i32.const 8
      i32.add
      i32.const 65856
      i32.const 8
      i32.add
      i64.load
      i64.store
      local.get 7
      i32.const 192
      i32.add
      i32.const 16
      i32.add
      i32.const 65856
      i32.const 16
      i32.add
      i64.load
      i64.store
      local.get 7
      i32.const 192
      i32.add
      i32.const 24
      i32.add
      i32.const 65856
      i32.const 24
      i32.add
      i64.load
      i64.store
      local.get 7
      i32.const 0
      i64.load offset=65856
      i64.store offset=192
      local.get 7
      i32.const 224
      i32.add
      i32.const 8
      i32.add
      i64.load
      local.set 13
      local.get 7
      i32.const 224
      i32.add
      i32.const 16
      i32.add
      i64.load
      local.set 14
      local.get 7
      i32.const 224
      i32.add
      i32.const 24
      i32.add
      i64.load
      local.set 15
      local.get 7
      i64.load offset=224
      local.set 17
      local.get 7
      i32.const 192
      i32.add
      local.get 7
      i32.const 160
      i32.add
      call $u256_from_big_endian_bytes
      local.get 7
      i32.const 160
      i32.add
      i32.const 160
      local.get 7
      i32.const 128
      i32.add
      call $wrapper_u256_shl
      local.get 7
      i32.const 96
      i32.add
      i32.const 24
      i32.add
      local.get 15
      local.get 7
      i32.const 128
      i32.add
      i32.const 24
      i32.add
      i64.load
      i64.and
      i64.store
      local.get 7
      local.get 14
      local.get 7
      i32.const 128
      i32.add
      i32.const 16
      i32.add
      i64.load
      i64.and
      i64.store offset=112
      local.get 7
      local.get 13
      local.get 7
      i32.const 128
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.and
      i64.store offset=104
      local.get 7
      local.get 17
      local.get 7
      i64.load offset=128
      i64.and
      i64.store offset=96
      local.get 7
      i32.const 256
      i32.add
      local.get 7
      i32.const 96
      i32.add
      call $wrapper_sstore_u256_using_little_endian_hostapi
      local.get 6
      i32.const -32
      i32.add
      local.tee 6
      local.tee 1
      global.set $__stack_pointer
      local.get 6
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 6
      local.get 12
      i64.store offset=16
      local.get 6
      local.get 10
      i64.store offset=8
      local.get 6
      local.get 11
      i64.store
      i32.const 0
      local.get 6
      call $wrapper_mstore_u256
      i32.const 32
      i32.const 3
      call $wrapper_mstore_u32
      local.get 1
      i32.const -32
      i32.add
      local.tee 8
      local.tee 6
      global.set $__stack_pointer
      i32.const 0
      i32.const 64
      local.get 8
      call $wrapper_keccak256
      local.get 6
      i32.const -32
      i32.add
      local.tee 6
      local.tee 1
      global.set $__stack_pointer
      local.get 8
      local.get 6
      call $wrapper_sload_u256_using_little_endian_hostapi
      local.get 6
      i64.load
      local.set 14
      local.get 6
      i32.const 8
      i32.add
      i64.load
      local.set 13
      local.get 6
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 6
      i32.const 16
      i32.add
      i64.load
      local.set 15
      local.get 1
      i32.const -32
      i32.add
      local.tee 1
      local.tee 6
      global.set $__stack_pointer
      local.get 1
      local.get 13
      local.get 14
      i64.const -1
      i64.add
      local.tee 17
      local.get 14
      i64.lt_u
      local.tee 9
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      local.tee 14
      i64.store offset=8
      local.get 1
      local.get 17
      i64.store
      local.get 1
      local.get 15
      i64.const -1
      i64.add
      local.tee 17
      local.get 9
      local.get 14
      local.get 13
      i64.lt_u
      local.get 14
      local.get 13
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 13
      i64.store offset=16
      local.get 1
      i32.const 24
      i32.add
      local.get 18
      local.get 17
      local.get 15
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 13
      local.get 17
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.const -1
      i64.add
      i64.store
      local.get 8
      local.get 1
      call $wrapper_sstore_u256_using_little_endian_hostapi
    end
    i32.const 0
    local.get 7
    call $wrapper_mstore_bytes32
    i32.const 32
    i32.const 3
    call $wrapper_mstore_u32
    local.get 6
    i32.const -32
    i32.add
    local.tee 1
    local.tee 6
    global.set $__stack_pointer
    i32.const 0
    i32.const 64
    local.get 1
    call $wrapper_keccak256
    local.get 6
    i32.const -32
    i32.add
    local.tee 6
    local.tee 8
    global.set $__stack_pointer
    local.get 1
    local.get 6
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 6
    i64.load
    local.set 13
    local.get 6
    i32.const 8
    i32.add
    i64.load
    local.set 14
    local.get 6
    i32.const 24
    i32.add
    i64.load
    local.set 18
    local.get 6
    i32.const 16
    i32.add
    i64.load
    local.set 15
    local.get 8
    i32.const -32
    i32.add
    local.tee 6
    local.tee 8
    global.set $__stack_pointer
    local.get 6
    local.get 14
    local.get 13
    i64.const 1
    i64.add
    local.tee 17
    local.get 13
    i64.lt_u
    local.tee 9
    i64.extend_i32_u
    i64.add
    local.tee 19
    i64.store offset=8
    local.get 6
    local.get 17
    i64.store
    local.get 6
    local.get 15
    local.get 9
    local.get 19
    local.get 14
    i64.lt_u
    local.get 17
    local.get 13
    i64.ge_u
    select
    i64.extend_i32_u
    i64.add
    local.tee 13
    i64.store offset=16
    local.get 6
    i32.const 24
    i32.add
    local.get 18
    local.get 13
    local.get 15
    i64.lt_u
    i64.extend_i32_u
    i64.add
    i64.store
    local.get 1
    local.get 6
    call $wrapper_sstore_u256_using_little_endian_hostapi
    local.get 8
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    local.get 5
    i64.store
    local.get 6
    local.get 4
    i64.store offset=16
    local.get 6
    local.get 3
    i64.store offset=8
    local.get 6
    local.get 2
    i64.store
    i32.const 0
    local.get 6
    call $wrapper_mstore_u256
    i32.const 32
    i32.const 2
    call $wrapper_mstore_u32
    local.get 1
    i32.const -32
    i32.add
    local.tee 8
    local.tee 6
    global.set $__stack_pointer
    i32.const 0
    i32.const 64
    local.get 8
    call $wrapper_keccak256
    local.get 6
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 8
    local.get 6
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 6
    i64.load
    local.set 13
    local.get 6
    i32.const 8
    i32.add
    i64.load
    local.set 14
    local.get 6
    i32.const 16
    i32.add
    i64.load
    local.set 15
    local.get 6
    i32.const 24
    i32.add
    i64.load
    local.set 17
    local.get 1
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    i32.const -32
    i32.add
    local.tee 1
    local.tee 9
    global.set $__stack_pointer
    local.get 1
    i32.const 24
    i32.add
    i32.const 65728
    i32.const 24
    i32.add
    i64.load
    i64.store align=1
    local.get 1
    i32.const 16
    i32.add
    i32.const 65728
    i32.const 16
    i32.add
    i64.load
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    i32.const 65728
    i32.const 8
    i32.add
    i64.load
    i64.store align=1
    local.get 1
    i32.const 0
    i64.load offset=65728
    i64.store align=1
    local.get 1
    local.get 6
    call $u256_from_big_endian_bytes
    local.get 6
    i64.load
    local.set 18
    local.get 6
    i32.const 8
    i32.add
    i64.load
    local.set 19
    local.get 6
    i32.const 16
    i32.add
    i64.load
    local.set 20
    local.get 6
    i32.const 24
    i32.add
    i64.load
    local.set 21
    local.get 9
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    local.get 21
    i64.store
    local.get 6
    local.get 20
    i64.store offset=16
    local.get 6
    local.get 19
    i64.store offset=8
    local.get 6
    local.get 18
    i64.store
    local.get 1
    i32.const -32
    i32.add
    local.tee 1
    local.tee 9
    global.set $__stack_pointer
    local.get 6
    i32.const 160
    local.get 1
    call $wrapper_u256_shl
    local.get 1
    i64.load
    local.set 18
    local.get 1
    i32.const 8
    i32.add
    i64.load
    local.set 19
    local.get 1
    i32.const 16
    i32.add
    i64.load
    local.set 20
    local.get 1
    i32.const 24
    i32.add
    i64.load
    local.set 21
    local.get 9
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 7
    local.get 6
    call $u256_from_big_endian_bytes
    local.get 6
    i32.const 24
    i32.add
    i64.load
    local.set 22
    local.get 6
    i64.load
    local.set 23
    local.get 6
    i32.const 8
    i32.add
    i64.load
    local.set 24
    local.get 6
    i32.const 16
    i32.add
    i64.load
    local.set 25
    local.get 1
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    local.get 22
    local.get 21
    local.get 17
    i64.and
    i64.or
    i64.store
    local.get 6
    local.get 25
    local.get 20
    local.get 15
    i64.and
    i64.or
    i64.store offset=16
    local.get 6
    local.get 24
    local.get 19
    local.get 14
    i64.and
    i64.or
    i64.store offset=8
    local.get 6
    local.get 23
    local.get 18
    local.get 13
    i64.and
    i64.or
    i64.store
    local.get 8
    local.get 6
    call $wrapper_sstore_u256_using_little_endian_hostapi
    local.get 1
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 6
    local.get 12
    i64.store offset=16
    local.get 6
    local.get 10
    i64.store offset=8
    local.get 6
    local.get 11
    i64.store
    local.get 1
    i32.const -32
    i32.add
    local.tee 1
    local.tee 8
    global.set $__stack_pointer
    local.get 6
    local.get 1
    call $u256_to_big_endian_bytes
    local.get 8
    i32.const -32
    i32.add
    local.tee 6
    local.tee 8
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    local.get 5
    i64.store
    local.get 6
    local.get 4
    i64.store offset=16
    local.get 6
    local.get 3
    i64.store offset=8
    local.get 6
    local.get 2
    i64.store
    local.get 8
    i32.const -32
    i32.add
    local.tee 8
    local.tee 9
    global.set $__stack_pointer
    local.get 6
    local.get 8
    call $u256_to_big_endian_bytes
    i32.const 0
    i32.const 0
    i32.const 65760
    local.get 1
    local.get 7
    local.get 8
    call $wrapper_log4
    local.get 9
    i32.const -32
    i32.add
    local.tee 6
    local.tee 1
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 6
    i64.const 4294967295
    i64.store offset=16
    local.get 6
    i64.const -1
    i64.store offset=8
    local.get 6
    i64.const -1
    i64.store
    local.get 1
    i32.const -32
    i32.add
    local.tee 8
    local.tee 1
    global.set $__stack_pointer
    local.get 6
    local.get 8
    call $u256_to_big_endian_bytes
    local.get 1
    i32.const -32
    i32.add
    local.tee 1
    local.tee 6
    global.set $__stack_pointer
    local.get 0
    local.get 8
    local.get 1
    call $wrapper_bytes32_and
    local.get 6
    i32.const -32
    i32.add
    local.tee 6
    local.tee 8
    global.set $__stack_pointer
    local.get 6
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 6
    local.get 12
    i64.store offset=16
    local.get 6
    local.get 10
    i64.store offset=8
    local.get 6
    local.get 11
    i64.store
    local.get 8
    i32.const -32
    i32.add
    local.tee 8
    local.tee 0
    global.set $__stack_pointer
    local.get 6
    local.get 8
    call $u256_to_big_endian_bytes
    block  ;; label = @1
      local.get 8
      local.get 1
      call $wrapper_bytes32_eq
      br_if 0 (;@1;)
      local.get 0
      i32.const -32
      i32.add
      local.tee 6
      local.tee 8
      global.set $__stack_pointer
      i32.const 64
      local.get 6
      call $wrapper_mload_bytes32
      local.get 6
      call $i32_from_big_endian_bytes32
      local.set 0
      local.get 8
      i32.const -32
      i32.add
      local.tee 8
      local.tee 9
      global.set $__stack_pointer
      local.get 8
      i32.const 24
      i32.add
      i64.const 7217086001351491584
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
      local.get 0
      local.get 8
      call $wrapper_mstore_u256
      local.get 9
      i32.const -32
      i32.add
      local.tee 8
      local.tee 9
      global.set $__stack_pointer
      local.get 6
      local.get 8
      call $u256_from_big_endian_bytes
      local.get 8
      i32.load
      i32.const 4
      i32.add
      local.get 1
      call $wrapper_mstore_bytes32
      local.get 9
      i32.const -32
      i32.add
      local.tee 1
      local.tee 8
      global.set $__stack_pointer
      local.get 6
      local.get 1
      call $u256_from_big_endian_bytes
      local.get 1
      i32.load
      local.set 9
      local.get 8
      i32.const -32
      i32.add
      local.tee 1
      local.tee 8
      global.set $__stack_pointer
      local.get 1
      i32.const 24
      i32.add
      local.get 5
      i64.store
      local.get 1
      local.get 4
      i64.store offset=16
      local.get 1
      local.get 3
      i64.store offset=8
      local.get 1
      local.get 2
      i64.store
      local.get 9
      i32.const 36
      i32.add
      local.get 1
      call $wrapper_mstore_u256
      local.get 8
      i32.const -32
      i32.add
      local.tee 1
      local.tee 8
      global.set $__stack_pointer
      local.get 6
      local.get 1
      call $u256_from_big_endian_bytes
      local.get 1
      i32.load
      local.set 1
      local.get 8
      i32.const -32
      i32.add
      local.tee 6
      global.set $__stack_pointer
      local.get 6
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 6
      local.get 12
      i64.store offset=16
      local.get 6
      local.get 10
      i64.store offset=8
      local.get 6
      local.get 11
      i64.store
      local.get 1
      i32.const 68
      i32.add
      local.get 6
      call $wrapper_mstore_u256
      local.get 0
      i32.const 100
      call $wrapper_revert
    end
    local.get 7
    i32.const 320
    i32.add
    global.set $__stack_pointer)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_requireOwned (type 14) (param i32 i64 i64 i64 i64)
    (local i32 i32 i64 i64 i64 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    local.tee 6
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    local.get 4
    i64.store
    local.get 6
    local.get 3
    i64.store offset=80
    local.get 6
    local.get 2
    i64.store offset=72
    local.get 6
    local.get 1
    i64.store offset=64
    i32.const 0
    local.get 6
    i32.const 64
    i32.add
    call $wrapper_mstore_u256
    i32.const 32
    i32.const 2
    call $wrapper_mstore_u32
    i32.const 0
    i32.const 64
    local.get 6
    i32.const 32
    i32.add
    call $wrapper_keccak256
    local.get 6
    i32.const 32
    i32.add
    local.get 6
    call $wrapper_sload_u256_using_little_endian_hostapi
    block  ;; label = @1
      local.get 6
      i64.load
      local.tee 7
      local.get 6
      i32.const 16
      i32.add
      i64.load32_u
      local.tee 8
      i64.or
      local.get 6
      i32.const 8
      i32.add
      i64.load
      local.tee 9
      i64.or
      i64.const 0
      i64.ne
      br_if 0 (;@1;)
      local.get 5
      i32.const -32
      i32.add
      local.tee 10
      local.tee 5
      global.set $__stack_pointer
      i32.const 64
      local.get 10
      call $wrapper_mload_bytes32
      local.get 10
      call $i32_from_big_endian_bytes32
      local.set 11
      local.get 5
      i32.const -32
      i32.add
      local.tee 5
      local.tee 12
      global.set $__stack_pointer
      local.get 5
      i32.const 24
      i32.add
      i64.const 9090289936862543872
      i64.store
      local.get 5
      i64.const 0
      i64.store offset=16
      local.get 5
      i64.const 0
      i64.store offset=8
      local.get 5
      i64.const 0
      i64.store
      local.get 11
      local.get 5
      call $wrapper_mstore_u256
      local.get 12
      i32.const -32
      i32.add
      local.tee 5
      local.tee 12
      global.set $__stack_pointer
      local.get 10
      local.get 5
      call $u256_from_big_endian_bytes
      local.get 5
      i32.load
      local.set 10
      local.get 12
      i32.const -32
      i32.add
      local.tee 5
      global.set $__stack_pointer
      local.get 5
      i32.const 24
      i32.add
      local.get 4
      i64.store
      local.get 5
      local.get 3
      i64.store offset=16
      local.get 5
      local.get 2
      i64.store offset=8
      local.get 5
      local.get 1
      i64.store
      local.get 10
      i32.const 4
      i32.add
      local.get 5
      call $wrapper_mstore_u256
      local.get 11
      i32.const 36
      call $wrapper_revert
    end
    local.get 0
    local.get 7
    i64.store
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 0
    local.get 9
    i64.store offset=8
    local.get 0
    local.get 8
    i64.store offset=16
    local.get 6
    i32.const 96
    i32.add
    global.set $__stack_pointer)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOwner (type 8)
    (local i32 i32 i64 i64 i64 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 192
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    local.tee 1
    i32.const 160
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 1
    i64.const 0
    i64.store offset=176
    local.get 1
    i64.const 0
    i64.store offset=168
    local.get 1
    i64.const 6
    i64.store offset=160
    local.get 1
    i32.const 160
    i32.add
    local.get 1
    i32.const 128
    i32.add
    call $u256_to_big_endian_bytes
    local.get 1
    i32.const 128
    i32.add
    local.get 1
    i32.const 96
    i32.add
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 1
    i32.const 104
    i32.add
    i64.load
    local.set 2
    local.get 1
    i32.const 112
    i32.add
    i64.load32_u
    local.set 3
    local.get 1
    i64.load offset=96
    local.set 4
    local.get 1
    i32.const 64
    i32.add
    call $wrapper_caller
    local.get 1
    i32.const 32
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 1
    local.get 3
    i64.store offset=48
    local.get 1
    local.get 2
    i64.store offset=40
    local.get 1
    local.get 4
    i64.store offset=32
    local.get 1
    i32.const 32
    i32.add
    local.get 1
    call $u256_to_big_endian_bytes
    block  ;; label = @1
      local.get 1
      local.get 1
      i32.const 64
      i32.add
      call $wrapper_bytes32_eq
      br_if 0 (;@1;)
      local.get 0
      i32.const -32
      i32.add
      local.tee 5
      local.tee 0
      global.set $__stack_pointer
      i32.const 64
      local.get 5
      call $wrapper_mload_bytes32
      local.get 5
      call $i32_from_big_endian_bytes32
      local.set 6
      local.get 0
      i32.const -32
      i32.add
      local.tee 0
      local.tee 7
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 1264626006178660352
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
      local.get 6
      local.get 0
      call $wrapper_mstore_u256
      local.get 7
      i32.const -32
      i32.add
      local.tee 0
      local.tee 7
      global.set $__stack_pointer
      local.get 5
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i32.load
      local.set 5
      local.get 7
      i32.const -32
      i32.add
      local.tee 0
      global.set $__stack_pointer
      local.get 0
      call $wrapper_caller
      local.get 5
      i32.const 4
      i32.add
      local.get 0
      call $wrapper_mstore_bytes32
      local.get 6
      i32.const 36
      call $wrapper_revert
    end
    local.get 1
    i32.const 192
    i32.add
    global.set $__stack_pointer)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOnERC721Received (type 18) (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 192
    i32.sub
    local.tee 20
    global.set $__stack_pointer
    local.get 20
    local.tee 21
    i32.const 64
    i32.add
    i32.const 24
    i32.add
    local.get 11
    i64.store
    local.get 21
    local.get 10
    i64.store offset=80
    local.get 21
    local.get 9
    i64.store offset=72
    local.get 21
    local.get 8
    i64.store offset=64
    local.get 21
    i32.const 64
    i32.add
    local.get 21
    i32.const 32
    i32.add
    call $u256_to_big_endian_bytes
    block  ;; label = @1
      local.get 21
      i32.const 32
      i32.add
      call $wrapper_extcode_size
      i32.eqz
      br_if 0 (;@1;)
      local.get 20
      i32.const -32
      i32.add
      local.tee 20
      local.tee 22
      global.set $__stack_pointer
      i32.const 64
      local.get 20
      call $wrapper_mload_bytes32
      local.get 20
      call $i32_from_big_endian_bytes32
      local.set 23
      local.get 22
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 22
      i32.const 24
      i32.add
      i64.const 1516439848548827136
      i64.store
      i64.const 0
      local.set 11
      local.get 22
      i64.const 0
      i64.store offset=16
      local.get 22
      i64.const 0
      i64.store offset=8
      local.get 22
      i64.const 0
      i64.store
      local.get 23
      local.get 22
      call $wrapper_mstore_u256
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 20
      local.get 22
      call $u256_from_big_endian_bytes
      local.get 22
      i32.load
      local.set 25
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 22
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 22
      local.get 2
      i64.const 4294967295
      i64.and
      i64.store offset=16
      local.get 22
      local.get 1
      i64.store offset=8
      local.get 22
      local.get 0
      i64.store
      local.get 25
      i32.const 4
      i32.add
      local.get 22
      call $wrapper_mstore_u256
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 20
      local.get 22
      call $u256_from_big_endian_bytes
      local.get 22
      i32.load
      local.set 25
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 22
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 22
      local.get 6
      i64.const 4294967295
      i64.and
      i64.store offset=16
      local.get 22
      local.get 5
      i64.store offset=8
      local.get 22
      local.get 4
      i64.store
      local.get 25
      i32.const 36
      i32.add
      local.get 22
      call $wrapper_mstore_u256
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 20
      local.get 22
      call $u256_from_big_endian_bytes
      local.get 22
      i32.load
      local.set 25
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 22
      i32.const 24
      i32.add
      local.get 15
      i64.store
      local.get 22
      local.get 14
      i64.store offset=16
      local.get 22
      local.get 13
      i64.store offset=8
      local.get 22
      local.get 12
      i64.store
      local.get 25
      i32.const 68
      i32.add
      local.get 22
      call $wrapper_mstore_u256
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 20
      local.get 22
      call $u256_from_big_endian_bytes
      i32.const 128
      local.set 26
      local.get 22
      i32.load
      i32.const 100
      i32.add
      i32.const 128
      call $wrapper_mstore_u32
      call $wrapper_gas
      local.set 14
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 20
      local.get 22
      call $u256_from_big_endian_bytes
      local.get 22
      i64.load
      local.set 15
      local.get 16
      i32.wrap_i64
      local.tee 22
      local.get 21
      i32.const 160
      i32.add
      call $wrapper_mload_bytes32
      local.get 15
      i64.const 132
      i64.add
      local.tee 16
      i32.wrap_i64
      local.tee 25
      local.get 21
      i32.const 160
      i32.add
      call $wrapper_mstore_bytes32
      local.get 25
      i32.const 32
      i32.add
      local.get 22
      i32.const 32
      i32.add
      local.get 21
      i32.const 160
      i32.add
      call $i32_from_big_endian_bytes32
      call $wrapper_data_copy
      local.get 21
      i32.const 160
      i32.add
      local.get 21
      i32.const 128
      i32.add
      call $u256_from_big_endian_bytes
      local.get 21
      i64.load offset=128
      local.get 16
      i64.add
      i32.wrap_i64
      i32.const 32
      i32.add
      i32.const 0
      call $wrapper_mstore_u32
      local.get 21
      i32.const 160
      i32.add
      local.get 21
      i32.const 96
      i32.add
      call $u256_from_big_endian_bytes
      local.get 21
      i64.load offset=96
      local.set 16
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 20
      local.get 22
      call $u256_from_big_endian_bytes
      local.get 22
      i64.load
      local.set 13
      local.get 24
      i32.const -32
      i32.add
      local.tee 22
      local.tee 24
      global.set $__stack_pointer
      local.get 22
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 22
      local.get 10
      i64.const 4294967295
      i64.and
      local.tee 12
      i64.store offset=16
      local.get 22
      local.get 9
      i64.store offset=8
      local.get 22
      local.get 8
      i64.store
      local.get 24
      i32.const -32
      i32.add
      local.tee 24
      local.tee 25
      global.set $__stack_pointer
      local.get 22
      local.get 24
      call $u256_to_big_endian_bytes
      local.get 25
      i32.const -32
      i32.add
      local.tee 22
      local.tee 25
      global.set $__stack_pointer
      local.get 22
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 22
      i64.const 0
      i64.store offset=16
      local.get 22
      i64.const 0
      i64.store offset=8
      local.get 22
      i64.const 0
      i64.store
      local.get 14
      local.get 24
      local.get 22
      local.get 23
      local.get 15
      local.get 16
      i64.const 31
      i64.add
      i64.const 4294967264
      i64.and
      i64.add
      local.get 13
      i64.sub
      i32.wrap_i64
      i32.const 164
      i32.add
      local.get 23
      i32.const 32
      call $wrapper_call_contract
      local.set 22
      call $wrapper_returndata_size
      local.set 24
      block  ;; label = @2
        block  ;; label = @3
          local.get 22
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            block  ;; label = @5
              local.get 24
              i32.const 32
              i32.lt_u
              br_if 0 (;@5;)
              i64.const 32
              local.set 14
              br 1 (;@4;)
            end
            call $wrapper_returndata_size
            i64.extend_i32_u
            local.set 14
            i64.const 0
            local.set 11
          end
          local.get 25
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 20
          local.get 22
          call $u256_from_big_endian_bytes
          local.get 22
          i64.load
          local.get 22
          i32.const 8
          i32.add
          i64.load
          local.get 22
          i32.const 16
          i32.add
          i64.load
          local.get 22
          i32.const 24
          i32.add
          i64.load
          local.get 14
          local.get 11
          local.get 11
          local.get 11
          call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation
          local.get 24
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 20
          local.get 22
          call $u256_from_big_endian_bytes
          local.get 22
          i32.const 24
          i32.add
          i64.load
          local.set 6
          local.get 22
          i32.const 16
          i32.add
          i64.load
          local.set 16
          local.get 22
          i32.const 8
          i32.add
          i64.load
          local.set 15
          local.get 22
          i64.load
          local.set 10
          local.get 24
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 20
          local.get 22
          call $u256_from_big_endian_bytes
          block  ;; label = @4
            local.get 10
            local.get 14
            i64.add
            local.tee 14
            local.get 22
            i64.load
            local.tee 5
            i64.sub
            i64.const 31
            i64.gt_u
            local.get 15
            local.get 11
            i64.add
            local.get 14
            local.get 10
            i64.lt_u
            local.tee 20
            i64.extend_i32_u
            i64.add
            local.tee 10
            local.get 22
            i32.const 8
            i32.add
            i64.load
            local.tee 13
            i64.sub
            local.get 14
            local.get 5
            i64.lt_u
            local.tee 25
            i64.extend_i32_u
            i64.sub
            local.tee 14
            i64.const 0
            i64.ne
            local.get 14
            i64.eqz
            select
            local.get 16
            local.get 11
            i64.add
            local.tee 14
            local.get 20
            local.get 10
            local.get 15
            i64.lt_u
            local.get 10
            local.get 15
            i64.eq
            select
            i64.extend_i32_u
            i64.add
            local.tee 15
            local.get 22
            i32.const 16
            i32.add
            i64.load
            local.tee 5
            i64.sub
            local.tee 4
            local.get 25
            local.get 10
            local.get 13
            i64.lt_u
            local.get 10
            local.get 13
            i64.eq
            select
            i64.extend_i32_u
            local.tee 10
            i64.sub
            local.tee 13
            i64.const 0
            i64.ne
            local.get 6
            local.get 11
            i64.add
            local.get 14
            local.get 16
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.get 15
            local.get 14
            i64.lt_u
            i64.extend_i32_u
            i64.add
            local.get 22
            i32.const 24
            i32.add
            i64.load
            i64.sub
            local.get 15
            local.get 5
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.get 4
            local.get 10
            i64.lt_u
            i64.extend_i32_u
            i64.sub
            local.tee 11
            i64.const 0
            i64.gt_s
            local.get 11
            i64.eqz
            select
            local.get 13
            local.get 11
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
            i32.const 0
            i32.const 0
            call $wrapper_revert
          end
          local.get 24
          i32.const -32
          i32.add
          local.tee 24
          local.tee 20
          global.set $__stack_pointer
          local.get 23
          local.get 24
          call $wrapper_mload_bytes32
          local.get 20
          i32.const -32
          i32.add
          local.tee 20
          local.tee 22
          global.set $__stack_pointer
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 22
          i32.const 24
          i32.add
          i32.const 65792
          i32.const 24
          i32.add
          i64.load
          i64.store align=1
          local.get 22
          i32.const 16
          i32.add
          i32.const 65792
          i32.const 16
          i32.add
          i64.load
          i64.store align=1
          local.get 22
          i32.const 8
          i32.add
          i32.const 65792
          i32.const 8
          i32.add
          i64.load
          i64.store align=1
          local.get 22
          i32.const 0
          i64.load offset=65792
          i64.store align=1
          local.get 22
          local.get 20
          call $u256_from_big_endian_bytes
          local.get 20
          i64.load
          local.set 11
          local.get 20
          i32.const 8
          i32.add
          i64.load
          local.set 10
          local.get 20
          i32.const 16
          i32.add
          i64.load
          local.set 15
          local.get 20
          i32.const 24
          i32.add
          i64.load
          local.set 16
          local.get 23
          i32.const -32
          i32.add
          local.tee 20
          local.tee 22
          global.set $__stack_pointer
          local.get 20
          i32.const 24
          i32.add
          local.get 16
          i64.store
          local.get 20
          local.get 15
          i64.store offset=16
          local.get 20
          local.get 10
          i64.store offset=8
          local.get 20
          local.get 11
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 20
          i32.const 224
          local.get 22
          call $wrapper_u256_shl
          local.get 22
          i64.load
          local.set 11
          local.get 22
          i32.const 8
          i32.add
          i64.load
          local.set 10
          local.get 22
          i32.const 16
          i32.add
          i64.load
          local.set 15
          local.get 22
          i32.const 24
          i32.add
          i64.load
          local.set 16
          local.get 23
          i32.const -32
          i32.add
          local.tee 20
          local.tee 22
          global.set $__stack_pointer
          local.get 20
          i32.const 24
          i32.add
          local.get 16
          i64.store
          local.get 20
          local.get 15
          i64.store offset=16
          local.get 20
          local.get 10
          i64.store offset=8
          local.get 20
          local.get 11
          i64.store
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 20
          local.get 22
          call $u256_to_big_endian_bytes
          local.get 23
          i32.const -32
          i32.add
          local.tee 20
          local.tee 23
          global.set $__stack_pointer
          local.get 24
          local.get 22
          local.get 20
          call $wrapper_bytes32_and
          local.get 24
          local.get 20
          call $wrapper_bytes32_eq
          br_if 1 (;@2;)
          i32.const 0
          i32.const 0
          call $wrapper_revert
          br 1 (;@2;)
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 24
            br_if 0 (;@4;)
            i32.const 96
            local.set 22
            br 1 (;@3;)
          end
          local.get 21
          call $wrapper_returndata_size
          local.tee 23
          i64.extend_i32_u
          i64.const 0
          i64.const 0
          i64.const 0
          call $MyERC721_48598_deployed.MyERC721_48598_deployed.array_allocation_size_bytes
          local.get 21
          i32.const 24
          i32.add
          i64.load
          local.set 11
          local.get 21
          i32.const 16
          i32.add
          i64.load
          local.set 10
          local.get 21
          i32.const 8
          i32.add
          i64.load
          local.set 15
          local.get 21
          i64.load
          local.set 16
          local.get 25
          i32.const -32
          i32.add
          local.tee 20
          local.tee 22
          global.set $__stack_pointer
          i32.const 64
          local.get 20
          call $wrapper_mload_bytes32
          local.get 22
          i32.const -32
          i32.add
          local.tee 22
          local.tee 24
          global.set $__stack_pointer
          local.get 20
          local.get 22
          call $u256_from_big_endian_bytes
          local.get 22
          i64.load
          local.get 22
          i32.const 8
          i32.add
          i64.load
          local.get 22
          i32.const 16
          i32.add
          i64.load
          local.get 22
          i32.const 24
          i32.add
          i64.load
          local.get 16
          local.get 15
          local.get 10
          local.get 11
          call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation
          local.get 20
          call $i32_from_big_endian_bytes32
          local.get 23
          call $wrapper_mstore_u32
          local.get 24
          i32.const -32
          i32.add
          local.tee 22
          local.tee 23
          global.set $__stack_pointer
          local.get 20
          local.get 22
          call $u256_from_big_endian_bytes
          local.get 22
          i32.load
          local.set 22
          local.get 23
          i32.const -32
          i32.add
          local.tee 23
          local.tee 25
          global.set $__stack_pointer
          local.get 20
          local.get 23
          call $u256_from_big_endian_bytes
          local.get 23
          i32.load
          i32.const 32
          i32.add
          i32.const 0
          call $wrapper_returndata_size
          call $wrapper_returndata_copy
          local.get 22
          i32.const 32
          i32.add
          local.set 26
        end
        local.get 25
        i32.const -32
        i32.add
        local.tee 20
        local.tee 23
        global.set $__stack_pointer
        local.get 22
        local.get 20
        call $wrapper_mload_bytes32
        block  ;; label = @3
          local.get 20
          call $wrapper_bytes32_iszero
          br_if 0 (;@3;)
          local.get 26
          local.get 20
          call $i32_from_big_endian_bytes32
          call $wrapper_revert
          br 2 (;@1;)
        end
        local.get 23
        i32.const -32
        i32.add
        local.tee 22
        local.tee 20
        global.set $__stack_pointer
        i32.const 64
        local.get 22
        call $wrapper_mload_bytes32
        local.get 22
        call $i32_from_big_endian_bytes32
        local.set 23
        local.get 20
        i32.const -32
        i32.add
        local.tee 20
        local.tee 24
        global.set $__stack_pointer
        local.get 20
        i32.const 24
        i32.add
        i64.const 7250987342154956800
        i64.store
        local.get 20
        i64.const 0
        i64.store offset=16
        local.get 20
        i64.const 0
        i64.store offset=8
        local.get 20
        i64.const 0
        i64.store
        local.get 23
        local.get 20
        call $wrapper_mstore_u256
        local.get 24
        i32.const -32
        i32.add
        local.tee 20
        local.tee 24
        global.set $__stack_pointer
        local.get 22
        local.get 20
        call $u256_from_big_endian_bytes
        local.get 20
        i32.load
        local.set 22
        local.get 24
        i32.const -32
        i32.add
        local.tee 20
        global.set $__stack_pointer
        local.get 20
        i32.const 24
        i32.add
        i64.const 0
        i64.store
        local.get 20
        local.get 12
        i64.store offset=16
        local.get 20
        local.get 9
        i64.store offset=8
        local.get 20
        local.get 8
        i64.store
        local.get 22
        i32.const 4
        i32.add
        local.get 20
        call $wrapper_mstore_u256
        local.get 23
        i32.const 36
        call $wrapper_revert
        br 1 (;@1;)
      end
      local.get 23
      i32.const -32
      i32.add
      local.tee 20
      local.tee 22
      global.set $__stack_pointer
      local.get 24
      local.get 20
      call $u256_from_big_endian_bytes
      local.get 20
      i32.const 24
      i32.add
      i64.load
      local.set 11
      local.get 20
      i32.const 8
      i32.add
      i64.load
      local.set 10
      local.get 20
      i64.load
      local.set 15
      local.get 20
      i32.const 16
      i32.add
      i64.load
      local.set 16
      local.get 22
      i32.const -32
      i32.add
      local.tee 20
      local.tee 22
      global.set $__stack_pointer
      local.get 22
      i32.const -32
      i32.add
      local.tee 22
      local.tee 23
      global.set $__stack_pointer
      local.get 22
      i32.const 24
      i32.add
      i32.const 65824
      i32.const 24
      i32.add
      i64.load
      i64.store align=1
      local.get 22
      i32.const 16
      i32.add
      i32.const 65824
      i32.const 16
      i32.add
      i64.load
      i64.store align=1
      local.get 22
      i32.const 8
      i32.add
      i32.const 65824
      i32.const 8
      i32.add
      i64.load
      i64.store align=1
      local.get 22
      i32.const 0
      i64.load offset=65824
      i64.store align=1
      local.get 22
      local.get 20
      call $u256_from_big_endian_bytes
      local.get 20
      i64.load
      local.set 14
      local.get 20
      i32.const 8
      i32.add
      i64.load
      local.set 13
      local.get 20
      i32.const 16
      i32.add
      i64.load
      local.set 6
      local.get 20
      i32.const 24
      i32.add
      i64.load
      local.set 5
      local.get 23
      i32.const -32
      i32.add
      local.tee 20
      local.tee 22
      global.set $__stack_pointer
      local.get 20
      i32.const 24
      i32.add
      local.get 5
      i64.store
      local.get 20
      local.get 6
      i64.store offset=16
      local.get 20
      local.get 13
      i64.store offset=8
      local.get 20
      local.get 14
      i64.store
      local.get 22
      i32.const -32
      i32.add
      local.tee 22
      local.tee 23
      global.set $__stack_pointer
      local.get 20
      i32.const 224
      local.get 22
      call $wrapper_u256_shl
      local.get 15
      local.get 22
      i64.load
      i64.and
      local.get 16
      local.get 22
      i32.const 16
      i32.add
      i64.load
      i64.and
      i64.or
      local.get 10
      local.get 22
      i32.const 8
      i32.add
      i64.load
      i64.and
      local.get 11
      local.get 22
      i32.const 24
      i32.add
      i64.load
      i64.and
      i64.const 1516439848548827136
      i64.xor
      i64.or
      i64.or
      i64.eqz
      br_if 0 (;@1;)
      local.get 23
      i32.const -32
      i32.add
      local.tee 22
      local.tee 20
      global.set $__stack_pointer
      i32.const 64
      local.get 22
      call $wrapper_mload_bytes32
      local.get 22
      call $i32_from_big_endian_bytes32
      local.set 23
      local.get 20
      i32.const -32
      i32.add
      local.tee 20
      local.tee 24
      global.set $__stack_pointer
      local.get 20
      i32.const 24
      i32.add
      i64.const 7250987342154956800
      i64.store
      local.get 20
      i64.const 0
      i64.store offset=16
      local.get 20
      i64.const 0
      i64.store offset=8
      local.get 20
      i64.const 0
      i64.store
      local.get 23
      local.get 20
      call $wrapper_mstore_u256
      local.get 24
      i32.const -32
      i32.add
      local.tee 20
      local.tee 24
      global.set $__stack_pointer
      local.get 22
      local.get 20
      call $u256_from_big_endian_bytes
      local.get 20
      i32.load
      local.set 22
      local.get 24
      i32.const -32
      i32.add
      local.tee 20
      global.set $__stack_pointer
      local.get 20
      i32.const 24
      i32.add
      i64.const 0
      i64.store
      local.get 20
      local.get 12
      i64.store offset=16
      local.get 20
      local.get 9
      i64.store offset=8
      local.get 20
      local.get 8
      i64.store
      local.get 22
      i32.const 4
      i32.add
      local.get 20
      call $wrapper_mstore_u256
      local.get 23
      i32.const 36
      call $wrapper_revert
    end
    local.get 21
    i32.const 192
    i32.add
    global.set $__stack_pointer)
  (func $MyERC721_48598_deployed.MyERC721_48598_deployed.init (type 8)
    (local i32 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i64 i64 i64 i64 i64 i64 i32 i32 i32 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 608
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
                          block  ;; label = @12
                            block  ;; label = @13
                              call $wrapper_calldata_load_selector
                              local.tee 2
                              i32.const 117300738
                              i32.gt_s
                              br_if 0 (;@13;)
                              block  ;; label = @14
                                local.get 2
                                i32.const -931440932
                                i32.gt_s
                                br_if 0 (;@14;)
                                block  ;; label = @15
                                  local.get 2
                                  i32.const -1574128540
                                  i32.gt_s
                                  br_if 0 (;@15;)
                                  local.get 2
                                  i32.const -1918514341
                                  i32.eq
                                  br_if 3 (;@12;)
                                  local.get 2
                                  i32.const -1780966591
                                  i32.ne
                                  br_if 14 (;@1;)
                                  block  ;; label = @16
                                    call $wrapper_callvalue_not_zero
                                    i32.eqz
                                    br_if 0 (;@16;)
                                    i32.const 0
                                    i32.const 0
                                    call $wrapper_revert
                                  end
                                  call $wrapper_calldata_size_minus_4
                                  drop
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 3
                                  local.tee 0
                                  global.set $__stack_pointer
                                  i32.const 64
                                  local.get 3
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
                                  i64.const 1
                                  i64.store
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 2
                                  call $u256_to_big_endian_bytes
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 2
                                  local.get 0
                                  call $wrapper_sload_u256_using_little_endian_hostapi
                                  local.get 0
                                  i64.load
                                  local.set 5
                                  local.get 0
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 6
                                  local.get 0
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.set 7
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.set 8
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  local.get 8
                                  i64.store
                                  local.get 0
                                  local.get 7
                                  i64.store offset=16
                                  local.get 0
                                  local.get 6
                                  i64.store offset=8
                                  local.get 0
                                  local.get 5
                                  i64.store
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 1
                                  local.get 2
                                  call $wrapper_u256_shr
                                  block  ;; label = @16
                                    local.get 5
                                    i32.wrap_i64
                                    i32.const 1
                                    i32.and
                                    local.get 2
                                    i64.load
                                    local.tee 9
                                    i64.const 127
                                    i64.and
                                    local.get 9
                                    local.get 5
                                    i64.const 1
                                    i64.and
                                    local.tee 10
                                    i64.eqz
                                    select
                                    local.tee 11
                                    i64.const 31
                                    i64.gt_u
                                    i64.const 0
                                    local.get 10
                                    i64.sub
                                    local.tee 9
                                    local.get 2
                                    i32.const 8
                                    i32.add
                                    i64.load
                                    i64.and
                                    local.tee 12
                                    i64.const 0
                                    i64.ne
                                    local.get 12
                                    i64.eqz
                                    select
                                    local.get 9
                                    local.get 2
                                    i32.const 16
                                    i32.add
                                    i64.load
                                    i64.and
                                    local.tee 13
                                    i64.const 0
                                    i64.ne
                                    local.get 9
                                    local.get 2
                                    i32.const 24
                                    i32.add
                                    i64.load
                                    i64.and
                                    local.tee 14
                                    i64.const 0
                                    i64.ne
                                    local.get 14
                                    i64.eqz
                                    select
                                    local.get 13
                                    local.get 14
                                    i64.or
                                    i64.eqz
                                    select
                                    i32.eq
                                    br_if 0 (;@16;)
                                    local.get 4
                                    i32.const -32
                                    i32.add
                                    local.tee 0
                                    local.tee 4
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
                                  local.get 3
                                  call $i32_from_big_endian_bytes32
                                  local.set 15
                                  local.get 4
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
                                  local.get 13
                                  i64.store offset=16
                                  local.get 0
                                  local.get 12
                                  i64.store offset=8
                                  local.get 0
                                  local.get 11
                                  i64.store
                                  local.get 15
                                  local.get 0
                                  call $wrapper_mstore_u256
                                  local.get 10
                                  i64.const 0
                                  i64.ne
                                  br_if 4 (;@11;)
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 3
                                  local.get 0
                                  call $u256_from_big_endian_bytes
                                  local.get 0
                                  i32.load
                                  local.set 4
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  local.get 8
                                  i64.store
                                  local.get 0
                                  local.get 7
                                  i64.store offset=16
                                  local.get 0
                                  local.get 6
                                  i64.store offset=8
                                  local.get 0
                                  local.get 5
                                  i64.const -256
                                  i64.and
                                  i64.store
                                  local.get 4
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
                                  local.get 11
                                  local.get 13
                                  i64.or
                                  local.get 12
                                  local.get 14
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
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 5
                                  local.get 2
                                  call $wrapper_u256_shl
                                  local.get 2
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.set 5
                                  local.get 2
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.set 10
                                  local.get 2
                                  i64.load
                                  local.set 9
                                  local.get 2
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 6
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 3
                                  local.get 0
                                  call $u256_from_big_endian_bytes
                                  local.get 5
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  i64.add
                                  local.get 10
                                  local.get 0
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.tee 5
                                  i64.add
                                  local.tee 10
                                  local.get 5
                                  i64.lt_u
                                  i64.extend_i32_u
                                  i64.add
                                  local.get 10
                                  local.get 9
                                  local.get 0
                                  i64.load
                                  local.tee 5
                                  i64.add
                                  local.tee 8
                                  local.get 5
                                  i64.lt_u
                                  local.tee 4
                                  local.get 6
                                  local.get 0
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.tee 9
                                  i64.add
                                  local.get 4
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 5
                                  local.get 9
                                  i64.lt_u
                                  local.get 5
                                  local.get 9
                                  i64.eq
                                  select
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 7
                                  local.get 10
                                  i64.lt_u
                                  i64.extend_i32_u
                                  i64.add
                                  local.set 12
                                  br 13 (;@2;)
                                end
                                local.get 2
                                i32.const -1574128539
                                i32.eq
                                br_if 4 (;@10;)
                                local.get 2
                                i32.const -1198698530
                                i32.ne
                                br_if 13 (;@1;)
                                block  ;; label = @15
                                  call $wrapper_callvalue_not_zero
                                  i32.eqz
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                block  ;; label = @15
                                  call $wrapper_calldata_size_minus_4
                                  i32.const 127
                                  i32.gt_u
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                i32.const 4
                                local.get 1
                                i32.const 384
                                i32.add
                                call $wrapper_calldataload_bytes32
                                local.get 1
                                i32.const 384
                                i32.add
                                local.get 1
                                i32.const 576
                                i32.add
                                call $u256_from_big_endian_bytes
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 24
                                i32.add
                                local.tee 2
                                i64.load
                                local.set 10
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 16
                                i32.add
                                local.tee 4
                                i64.load
                                local.set 9
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 8
                                i32.add
                                local.tee 3
                                i64.load
                                local.set 6
                                local.get 1
                                i64.load offset=576
                                local.set 7
                                i32.const 36
                                local.get 1
                                i32.const 384
                                i32.add
                                call $wrapper_calldataload_bytes32
                                local.get 1
                                i32.const 384
                                i32.add
                                local.get 1
                                i32.const 576
                                i32.add
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i64.load
                                local.set 8
                                local.get 4
                                i64.load
                                local.set 16
                                local.get 3
                                i64.load
                                local.set 17
                                local.get 1
                                i64.load offset=576
                                local.set 14
                                local.get 0
                                i32.const -32
                                i32.add
                                local.tee 15
                                local.tee 0
                                global.set $__stack_pointer
                                i32.const 68
                                local.get 15
                                call $wrapper_calldataload_bytes32
                                local.get 0
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                i32.const 100
                                local.get 0
                                call $wrapper_calldataload_bytes32
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
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
                                local.set 5
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                i32.const 66272
                                local.get 2
                                call $u256_from_big_endian_bytes
                                block  ;; label = @15
                                  local.get 18
                                  local.get 2
                                  i64.load
                                  i64.le_u
                                  local.get 19
                                  local.get 2
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.tee 18
                                  i64.le_u
                                  local.get 19
                                  local.get 18
                                  i64.eq
                                  select
                                  local.get 20
                                  local.get 2
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.tee 18
                                  i64.le_u
                                  local.get 5
                                  local.get 2
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.tee 19
                                  i64.le_u
                                  local.get 5
                                  local.get 19
                                  i64.eq
                                  select
                                  local.get 20
                                  local.get 18
                                  i64.xor
                                  local.get 5
                                  local.get 19
                                  i64.xor
                                  i64.or
                                  i64.eqz
                                  select
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                block  ;; label = @15
                                  local.get 2
                                  i64.load
                                  local.tee 5
                                  i64.const 35
                                  i64.add
                                  local.tee 19
                                  call $wrapper_calldata_size
                                  i64.extend_i32_u
                                  i64.lt_u
                                  i32.const 0
                                  local.get 2
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.tee 20
                                  local.get 19
                                  local.get 5
                                  i64.lt_u
                                  local.tee 3
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 18
                                  i64.eqz
                                  select
                                  local.get 2
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.get 2
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.tee 21
                                  local.get 3
                                  local.get 18
                                  local.get 20
                                  i64.lt_u
                                  local.get 19
                                  local.get 5
                                  i64.ge_u
                                  select
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 5
                                  local.get 21
                                  i64.lt_u
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 19
                                  i64.const 0
                                  i64.lt_s
                                  local.get 5
                                  local.get 19
                                  i64.or
                                  i64.eqz
                                  select
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i32.load
                                local.set 3
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 3
                                i32.const 4
                                i32.add
                                local.get 2
                                call $wrapper_calldataload_bytes32
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 4
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 2
                                local.get 4
                                call $u256_from_big_endian_bytes
                                local.get 1
                                i32.const 320
                                i32.add
                                local.get 4
                                i64.load
                                local.get 4
                                i32.const 8
                                i32.add
                                i64.load
                                local.get 4
                                i32.const 16
                                i32.add
                                i64.load
                                local.get 4
                                i32.const 24
                                i32.add
                                i64.load
                                call $MyERC721_48598_deployed.MyERC721_48598_deployed.array_allocation_size_bytes
                                local.get 1
                                i32.const 320
                                i32.add
                                i32.const 24
                                i32.add
                                i64.load
                                local.set 5
                                local.get 1
                                i32.const 320
                                i32.add
                                i32.const 16
                                i32.add
                                i64.load
                                local.set 19
                                local.get 1
                                i32.const 320
                                i32.add
                                i32.const 8
                                i32.add
                                i64.load
                                local.set 20
                                local.get 1
                                i64.load offset=320
                                local.set 18
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 4
                                local.tee 3
                                global.set $__stack_pointer
                                i32.const 64
                                local.get 4
                                call $wrapper_mload_bytes32
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 22
                                global.set $__stack_pointer
                                local.get 4
                                local.get 3
                                call $u256_from_big_endian_bytes
                                local.get 3
                                i64.load
                                local.get 3
                                i32.const 8
                                i32.add
                                i64.load
                                local.get 3
                                i32.const 16
                                i32.add
                                i64.load
                                local.get 3
                                i32.const 24
                                i32.add
                                i64.load
                                local.get 18
                                local.get 20
                                local.get 19
                                local.get 5
                                call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation
                                local.get 4
                                call $i32_from_big_endian_bytes32
                                local.get 2
                                call $wrapper_mstore_bytes32
                                local.get 22
                                i32.const -32
                                i32.add
                                local.tee 22
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                local.get 22
                                call $wrapper_bytes32_add
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 23
                                global.set $__stack_pointer
                                local.get 22
                                local.get 3
                                call $u256_from_big_endian_bytes
                                block  ;; label = @15
                                  local.get 3
                                  i64.load
                                  local.tee 5
                                  i64.const 36
                                  i64.add
                                  local.tee 19
                                  call $wrapper_calldata_size
                                  i64.extend_i32_u
                                  i64.le_u
                                  local.get 3
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.tee 20
                                  local.get 19
                                  local.get 5
                                  i64.lt_u
                                  local.tee 22
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 18
                                  i64.eqz
                                  local.tee 24
                                  local.get 24
                                  select
                                  local.get 3
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.tee 21
                                  local.get 22
                                  local.get 18
                                  local.get 20
                                  i64.lt_u
                                  local.get 19
                                  local.get 5
                                  i64.ge_u
                                  select
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 5
                                  i64.eqz
                                  local.get 3
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.get 5
                                  local.get 21
                                  i64.lt_u
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 19
                                  i64.eqz
                                  local.tee 3
                                  local.get 3
                                  select
                                  local.get 5
                                  local.get 19
                                  i64.or
                                  i64.eqz
                                  select
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                local.get 23
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 22
                                global.set $__stack_pointer
                                local.get 4
                                local.get 3
                                call $u256_from_big_endian_bytes
                                local.get 3
                                i32.load
                                local.set 23
                                local.get 22
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 22
                                global.set $__stack_pointer
                                local.get 0
                                local.get 3
                                call $u256_from_big_endian_bytes
                                local.get 23
                                i32.const 32
                                i32.add
                                local.get 3
                                i32.load
                                i32.const 36
                                i32.add
                                local.get 2
                                call $i32_from_big_endian_bytes32
                                call $wrapper_calldata_copy
                                local.get 22
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 4
                                local.get 2
                                local.get 0
                                call $wrapper_bytes32_add
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i32.load
                                i32.const 32
                                i32.add
                                i32.const 0
                                call $wrapper_mstore_u32
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                local.get 10
                                i64.store
                                local.get 0
                                local.get 9
                                i64.store offset=16
                                local.get 0
                                local.get 6
                                i64.store offset=8
                                local.get 0
                                local.get 7
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_to_big_endian_bytes
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                local.get 8
                                i64.store
                                local.get 0
                                local.get 16
                                i64.store offset=16
                                local.get 0
                                local.get 17
                                i64.store offset=8
                                local.get 0
                                local.get 14
                                i64.store
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 22
                                global.set $__stack_pointer
                                local.get 0
                                local.get 3
                                call $u256_to_big_endian_bytes
                                local.get 22
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 22
                                global.set $__stack_pointer
                                local.get 15
                                local.get 0
                                call $u256_from_big_endian_bytes
                                local.get 2
                                local.get 3
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
                                call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_transferFrom
                                local.get 22
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
                                local.set 19
                                local.get 0
                                i32.const 8
                                i32.add
                                i64.load
                                local.set 20
                                local.get 0
                                i64.load
                                local.set 18
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 15
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
                                local.set 12
                                local.get 0
                                i32.const 8
                                i32.add
                                i64.load
                                local.set 13
                                local.get 0
                                i64.load
                                local.set 25
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 0
                                global.set $__stack_pointer
                                local.get 4
                                local.get 0
                                call $u256_from_big_endian_bytes
                                local.get 18
                                local.get 20
                                local.get 19
                                local.get 5
                                local.get 7
                                local.get 6
                                local.get 9
                                local.get 10
                                local.get 14
                                local.get 17
                                local.get 16
                                local.get 8
                                local.get 25
                                local.get 13
                                local.get 12
                                local.get 21
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
                                call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOnERC721Received
                                i32.const 0
                                i32.const 0
                                call $wrapper_return
                                br 13 (;@1;)
                              end
                              block  ;; label = @14
                                local.get 2
                                i32.const -218242166
                                i32.gt_s
                                br_if 0 (;@14;)
                                local.get 2
                                i32.const -931440931
                                i32.eq
                                br_if 5 (;@9;)
                                local.get 2
                                i32.const -377099835
                                i32.ne
                                br_if 13 (;@1;)
                                block  ;; label = @15
                                  call $wrapper_callvalue_not_zero
                                  i32.eqz
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                block  ;; label = @15
                                  call $wrapper_calldata_size_minus_4
                                  i32.const 63
                                  i32.gt_u
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                i32.const 4
                                local.get 1
                                i32.const 384
                                i32.add
                                call $wrapper_calldataload_bytes32
                                local.get 1
                                i32.const 384
                                i32.add
                                local.get 1
                                i32.const 576
                                i32.add
                                call $u256_from_big_endian_bytes
                                local.get 1
                                i32.const 584
                                i32.add
                                local.tee 2
                                i64.load
                                local.set 5
                                local.get 1
                                i32.const 592
                                i32.add
                                local.tee 4
                                i64.load32_u
                                local.set 10
                                local.get 1
                                i64.load offset=576
                                local.set 9
                                i32.const 36
                                local.get 1
                                i32.const 384
                                i32.add
                                call $wrapper_calldataload_bytes32
                                local.get 1
                                i32.const 384
                                i32.add
                                local.get 1
                                i32.const 576
                                i32.add
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i64.load
                                local.set 6
                                local.get 4
                                i64.load32_u
                                local.set 7
                                local.get 1
                                i64.load offset=576
                                local.set 8
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
                                local.get 10
                                i64.store offset=16
                                local.get 0
                                local.get 5
                                i64.store offset=8
                                local.get 0
                                local.get 9
                                i64.store
                                i32.const 0
                                local.get 0
                                call $wrapper_mstore_u256
                                i32.const 32
                                i32.const 5
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
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                i64.const 0
                                i64.store
                                local.get 0
                                local.get 7
                                i64.store offset=16
                                local.get 0
                                local.get 6
                                i64.store offset=8
                                local.get 0
                                local.get 8
                                i64.store
                                i32.const 0
                                local.get 0
                                call $wrapper_mstore_u256
                                i32.const 32
                                local.get 2
                                call $wrapper_mstore_bytes32
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                i32.const 0
                                i32.const 64
                                local.get 0
                                call $wrapper_keccak256
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $wrapper_sload_u256_using_little_endian_hostapi
                                local.get 2
                                i64.load8_u
                                local.set 5
                                local.get 4
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
                                local.get 5
                                i64.const 0
                                i64.ne
                                call $wrapper_mstore_u32
                                local.get 0
                                i32.const 32
                                call $wrapper_return
                                br 13 (;@1;)
                              end
                              local.get 2
                              i32.const -218242165
                              i32.eq
                              br_if 5 (;@8;)
                              local.get 2
                              i32.const 33540519
                              i32.ne
                              br_if 12 (;@1;)
                              block  ;; label = @14
                                call $wrapper_callvalue_not_zero
                                i32.eqz
                                br_if 0 (;@14;)
                                i32.const 0
                                i32.const 0
                                call $wrapper_revert
                              end
                              block  ;; label = @14
                                call $wrapper_calldata_size_minus_4
                                i32.const 31
                                i32.gt_u
                                br_if 0 (;@14;)
                                i32.const 0
                                i32.const 0
                                call $wrapper_revert
                              end
                              local.get 0
                              i32.const -32
                              i32.add
                              local.tee 3
                              local.tee 0
                              global.set $__stack_pointer
                              i32.const 4
                              local.get 3
                              call $wrapper_calldataload_bytes32
                              local.get 0
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 2
                              global.set $__stack_pointer
                              local.get 2
                              i32.const -32
                              i32.add
                              local.tee 2
                              local.tee 4
                              global.set $__stack_pointer
                              local.get 2
                              i32.const 24
                              i32.add
                              i32.const 65888
                              i32.const 24
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 2
                              i32.const 16
                              i32.add
                              i32.const 65888
                              i32.const 16
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 2
                              i32.const 8
                              i32.add
                              i32.const 65888
                              i32.const 8
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 2
                              i32.const 0
                              i64.load offset=65888
                              i64.store align=1
                              local.get 2
                              local.get 0
                              call $u256_from_big_endian_bytes
                              local.get 0
                              i64.load
                              local.set 5
                              local.get 0
                              i32.const 8
                              i32.add
                              i64.load
                              local.set 10
                              local.get 0
                              i32.const 16
                              i32.add
                              i64.load
                              local.set 9
                              local.get 0
                              i32.const 24
                              i32.add
                              i64.load
                              local.set 6
                              local.get 4
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
                              local.get 9
                              i64.store offset=16
                              local.get 0
                              local.get 10
                              i64.store offset=8
                              local.get 0
                              local.get 5
                              i64.store
                              local.get 2
                              i32.const -32
                              i32.add
                              local.tee 2
                              local.tee 4
                              global.set $__stack_pointer
                              local.get 0
                              i32.const 224
                              local.get 2
                              call $wrapper_u256_shl
                              local.get 2
                              i64.load
                              local.set 5
                              local.get 2
                              i32.const 8
                              i32.add
                              i64.load
                              local.set 10
                              local.get 2
                              i32.const 16
                              i32.add
                              i64.load
                              local.set 9
                              local.get 2
                              i32.const 24
                              i32.add
                              i64.load
                              local.set 6
                              local.get 4
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
                              local.get 9
                              i64.store offset=16
                              local.get 0
                              local.get 10
                              i64.store offset=8
                              local.get 0
                              local.get 5
                              i64.store
                              local.get 2
                              i32.const -32
                              i32.add
                              local.tee 2
                              local.tee 4
                              global.set $__stack_pointer
                              local.get 0
                              local.get 2
                              call $u256_to_big_endian_bytes
                              local.get 4
                              i32.const -32
                              i32.add
                              local.tee 4
                              local.tee 0
                              global.set $__stack_pointer
                              local.get 3
                              local.get 2
                              local.get 4
                              call $wrapper_bytes32_and
                              block  ;; label = @14
                                local.get 3
                                local.get 4
                                call $wrapper_bytes32_eq
                                br_if 0 (;@14;)
                                i32.const 0
                                i32.const 0
                                call $wrapper_revert
                              end
                              local.get 0
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 2
                              global.set $__stack_pointer
                              local.get 2
                              i32.const -32
                              i32.add
                              local.tee 2
                              local.tee 3
                              global.set $__stack_pointer
                              local.get 2
                              i32.const 24
                              i32.add
                              i32.const 65920
                              i32.const 24
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 2
                              i32.const 16
                              i32.add
                              i32.const 65920
                              i32.const 16
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 2
                              i32.const 8
                              i32.add
                              i32.const 65920
                              i32.const 8
                              i32.add
                              i64.load
                              i64.store align=1
                              local.get 2
                              i32.const 0
                              i64.load offset=65920
                              i64.store align=1
                              local.get 2
                              local.get 0
                              call $u256_from_big_endian_bytes
                              local.get 0
                              i64.load
                              local.set 5
                              local.get 0
                              i32.const 8
                              i32.add
                              i64.load
                              local.set 10
                              local.get 0
                              i32.const 16
                              i32.add
                              i64.load
                              local.set 9
                              local.get 0
                              i32.const 24
                              i32.add
                              i64.load
                              local.set 6
                              local.get 3
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
                              local.get 9
                              i64.store offset=16
                              local.get 0
                              local.get 10
                              i64.store offset=8
                              local.get 0
                              local.get 5
                              i64.store
                              local.get 2
                              i32.const -32
                              i32.add
                              local.tee 2
                              local.tee 3
                              global.set $__stack_pointer
                              local.get 0
                              i32.const 224
                              local.get 2
                              call $wrapper_u256_shl
                              local.get 2
                              i64.load
                              local.set 5
                              local.get 2
                              i32.const 8
                              i32.add
                              i64.load
                              local.set 10
                              local.get 2
                              i32.const 16
                              i32.add
                              i64.load
                              local.set 9
                              local.get 2
                              i32.const 24
                              i32.add
                              i64.load
                              local.set 6
                              local.get 3
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
                              local.get 9
                              i64.store offset=16
                              local.get 0
                              local.get 10
                              i64.store offset=8
                              local.get 0
                              local.get 5
                              i64.store
                              local.get 2
                              i32.const -32
                              i32.add
                              local.tee 2
                              local.tee 15
                              global.set $__stack_pointer
                              local.get 0
                              local.get 2
                              call $u256_to_big_endian_bytes
                              i32.const 1
                              local.set 3
                              block  ;; label = @14
                                local.get 4
                                local.get 2
                                call $wrapper_bytes32_eq
                                br_if 0 (;@14;)
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                i64.const 6583721278882971648
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
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_to_big_endian_bytes
                                local.get 4
                                local.get 2
                                call $wrapper_bytes32_eq
                                br_if 0 (;@14;)
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                i64.const 144055432195866624
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
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_to_big_endian_bytes
                                local.get 4
                                local.get 2
                                call $wrapper_bytes32_eq
                                i32.const 0
                                i32.ne
                                local.set 3
                              end
                              i32.const 96
                              local.get 3
                              call $wrapper_mstore_u32
                              i32.const 96
                              i32.const 32
                              call $wrapper_return
                              br 12 (;@1;)
                            end
                            block  ;; label = @13
                              block  ;; label = @14
                                block  ;; label = @15
                                  block  ;; label = @16
                                    block  ;; label = @17
                                      block  ;; label = @18
                                        block  ;; label = @19
                                          local.get 2
                                          i32.const 1115958797
                                          i32.gt_s
                                          br_if 0 (;@19;)
                                          block  ;; label = @20
                                            local.get 2
                                            i32.const 157198258
                                            i32.gt_s
                                            br_if 0 (;@20;)
                                            local.get 2
                                            i32.const 117300739
                                            i32.eq
                                            br_if 2 (;@18;)
                                            local.get 2
                                            i32.const 135795452
                                            i32.ne
                                            br_if 19 (;@1;)
                                            block  ;; label = @21
                                              call $wrapper_callvalue_not_zero
                                              i32.eqz
                                              br_if 0 (;@21;)
                                              i32.const 0
                                              i32.const 0
                                              call $wrapper_revert
                                            end
                                            block  ;; label = @21
                                              call $wrapper_calldata_size_minus_4
                                              i32.const 31
                                              i32.gt_u
                                              br_if 0 (;@21;)
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
                                            local.tee 4
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
                                            call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_requireOwned
                                            i32.const 0
                                            local.get 2
                                            call $wrapper_mstore_bytes32
                                            local.get 4
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
                                            i32.const 32
                                            local.get 0
                                            call $wrapper_mstore_u256
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
                                            local.tee 4
                                            global.set $__stack_pointer
                                            local.get 2
                                            local.get 0
                                            call $wrapper_sload_u256_using_little_endian_hostapi
                                            local.get 0
                                            i64.load
                                            local.set 5
                                            local.get 0
                                            i32.const 8
                                            i32.add
                                            i64.load
                                            local.set 10
                                            local.get 0
                                            i32.const 16
                                            i32.add
                                            i64.load32_u
                                            local.set 9
                                            local.get 4
                                            i32.const -32
                                            i32.add
                                            local.tee 0
                                            local.tee 4
                                            global.set $__stack_pointer
                                            i32.const 64
                                            local.get 0
                                            call $wrapper_mload_bytes32
                                            local.get 0
                                            call $i32_from_big_endian_bytes32
                                            local.set 2
                                            local.get 4
                                            i32.const -32
                                            i32.add
                                            local.tee 0
                                            global.set $__stack_pointer
                                            local.get 0
                                            i32.const 24
                                            i32.add
                                            i64.const 0
                                            i64.store
                                            local.get 0
                                            local.get 9
                                            i64.store offset=16
                                            local.get 0
                                            local.get 10
                                            i64.store offset=8
                                            local.get 0
                                            local.get 5
                                            i64.store
                                            local.get 2
                                            local.get 0
                                            call $wrapper_mstore_u256
                                            local.get 2
                                            i32.const 32
                                            call $wrapper_return
                                            br 19 (;@1;)
                                          end
                                          local.get 2
                                          i32.const 157198259
                                          i32.eq
                                          br_if 2 (;@17;)
                                          local.get 2
                                          i32.const 599290589
                                          i32.ne
                                          br_if 18 (;@1;)
                                          block  ;; label = @20
                                            call $wrapper_callvalue_not_zero
                                            i32.eqz
                                            br_if 0 (;@20;)
                                            i32.const 0
                                            i32.const 0
                                            call $wrapper_revert
                                          end
                                          local.get 1
                                          i32.const 64
                                          i32.add
                                          call $wrapper_calldata_size
                                          i64.extend_i32_u
                                          i64.const 0
                                          i64.const 0
                                          i64.const 0
                                          call $MyERC721_48598_deployed.MyERC721_48598_deployed.abi_decode_addresst_addresst_uint256
                                          local.get 1
                                          i32.const 152
                                          i32.add
                                          i64.load
                                          local.set 5
                                          local.get 1
                                          i32.const 144
                                          i32.add
                                          i64.load
                                          local.set 10
                                          local.get 1
                                          i32.const 136
                                          i32.add
                                          i64.load
                                          local.set 9
                                          local.get 1
                                          i32.const 104
                                          i32.add
                                          i64.load
                                          local.set 6
                                          local.get 1
                                          i32.const 112
                                          i32.add
                                          i64.load
                                          local.set 7
                                          local.get 1
                                          i32.const 120
                                          i32.add
                                          i64.load
                                          local.set 8
                                          local.get 1
                                          i32.const 72
                                          i32.add
                                          i64.load
                                          local.set 16
                                          local.get 1
                                          i32.const 80
                                          i32.add
                                          i64.load
                                          local.set 17
                                          local.get 1
                                          i32.const 64
                                          i32.add
                                          i32.const 24
                                          i32.add
                                          i64.load
                                          local.set 14
                                          local.get 1
                                          i64.load offset=128
                                          local.set 19
                                          local.get 1
                                          i64.load offset=96
                                          local.set 20
                                          local.get 1
                                          i64.load offset=64
                                          local.set 18
                                          local.get 0
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
                                          local.get 17
                                          i64.store offset=16
                                          local.get 0
                                          local.get 16
                                          i64.store offset=8
                                          local.get 0
                                          local.get 18
                                          i64.store
                                          local.get 2
                                          i32.const -32
                                          i32.add
                                          local.tee 2
                                          local.tee 4
                                          global.set $__stack_pointer
                                          local.get 0
                                          local.get 2
                                          call $u256_to_big_endian_bytes
                                          local.get 4
                                          i32.const -32
                                          i32.add
                                          local.tee 0
                                          local.tee 4
                                          global.set $__stack_pointer
                                          local.get 0
                                          i32.const 24
                                          i32.add
                                          local.get 8
                                          i64.store
                                          local.get 0
                                          local.get 7
                                          i64.store offset=16
                                          local.get 0
                                          local.get 6
                                          i64.store offset=8
                                          local.get 0
                                          local.get 20
                                          i64.store
                                          local.get 4
                                          i32.const -32
                                          i32.add
                                          local.tee 4
                                          global.set $__stack_pointer
                                          local.get 0
                                          local.get 4
                                          call $u256_to_big_endian_bytes
                                          local.get 2
                                          local.get 4
                                          local.get 19
                                          local.get 9
                                          local.get 10
                                          local.get 5
                                          call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_transferFrom
                                          i32.const 0
                                          i32.const 0
                                          call $wrapper_return
                                          br 18 (;@1;)
                                        end
                                        block  ;; label = @19
                                          local.get 2
                                          i32.const 1784838209
                                          i32.gt_s
                                          br_if 0 (;@19;)
                                          local.get 2
                                          i32.const 1115958798
                                          i32.eq
                                          br_if 3 (;@16;)
                                          local.get 2
                                          i32.const 1666326814
                                          i32.ne
                                          br_if 18 (;@1;)
                                          block  ;; label = @20
                                            call $wrapper_callvalue_not_zero
                                            i32.eqz
                                            br_if 0 (;@20;)
                                            i32.const 0
                                            i32.const 0
                                            call $wrapper_revert
                                          end
                                          block  ;; label = @20
                                            call $wrapper_calldata_size_minus_4
                                            i32.const 31
                                            i32.gt_u
                                            br_if 0 (;@20;)
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
                                          local.tee 4
                                          global.set $__stack_pointer
                                          local.get 2
                                          local.get 0
                                          call $u256_from_big_endian_bytes
                                          local.get 1
                                          i32.const 256
                                          i32.add
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
                                          call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_requireOwned
                                          local.get 1
                                          i32.const 256
                                          i32.add
                                          i32.const 8
                                          i32.add
                                          i64.load
                                          local.set 5
                                          local.get 1
                                          i32.const 256
                                          i32.add
                                          i32.const 16
                                          i32.add
                                          i64.load
                                          local.set 10
                                          local.get 1
                                          i32.const 256
                                          i32.add
                                          i32.const 24
                                          i32.add
                                          i64.load
                                          local.set 9
                                          local.get 1
                                          i64.load offset=256
                                          local.set 6
                                          local.get 4
                                          i32.const -32
                                          i32.add
                                          local.tee 0
                                          local.tee 4
                                          global.set $__stack_pointer
                                          i32.const 64
                                          local.get 0
                                          call $wrapper_mload_bytes32
                                          local.get 0
                                          call $i32_from_big_endian_bytes32
                                          local.set 2
                                          local.get 4
                                          i32.const -32
                                          i32.add
                                          local.tee 0
                                          global.set $__stack_pointer
                                          local.get 0
                                          i32.const 24
                                          i32.add
                                          local.get 9
                                          i64.store
                                          local.get 0
                                          local.get 10
                                          i64.store offset=16
                                          local.get 0
                                          local.get 5
                                          i64.store offset=8
                                          local.get 0
                                          local.get 6
                                          i64.store
                                          local.get 2
                                          local.get 0
                                          call $wrapper_mstore_u256
                                          local.get 2
                                          i32.const 32
                                          call $wrapper_return
                                          br 18 (;@1;)
                                        end
                                        local.get 2
                                        i32.const 1784838210
                                        i32.eq
                                        br_if 3 (;@15;)
                                        local.get 2
                                        i32.const 1889567281
                                        i32.eq
                                        br_if 4 (;@14;)
                                        local.get 2
                                        i32.const 1901074598
                                        i32.eq
                                        br_if 5 (;@13;)
                                        br 17 (;@1;)
                                      end
                                      block  ;; label = @18
                                        call $wrapper_callvalue_not_zero
                                        i32.eqz
                                        br_if 0 (;@18;)
                                        i32.const 0
                                        i32.const 0
                                        call $wrapper_revert
                                      end
                                      call $wrapper_calldata_size_minus_4
                                      drop
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 3
                                      local.tee 0
                                      global.set $__stack_pointer
                                      i32.const 64
                                      local.get 3
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
                                      i64.const 0
                                      i64.store
                                      local.get 2
                                      i32.const -32
                                      i32.add
                                      local.tee 2
                                      local.tee 4
                                      global.set $__stack_pointer
                                      local.get 0
                                      local.get 2
                                      call $u256_to_big_endian_bytes
                                      local.get 4
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 4
                                      global.set $__stack_pointer
                                      local.get 2
                                      local.get 0
                                      call $wrapper_sload_u256_using_little_endian_hostapi
                                      local.get 0
                                      i64.load
                                      local.set 5
                                      local.get 0
                                      i32.const 8
                                      i32.add
                                      i64.load
                                      local.set 6
                                      local.get 0
                                      i32.const 16
                                      i32.add
                                      i64.load
                                      local.set 7
                                      local.get 0
                                      i32.const 24
                                      i32.add
                                      i64.load
                                      local.set 8
                                      local.get 4
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 2
                                      global.set $__stack_pointer
                                      local.get 0
                                      i32.const 24
                                      i32.add
                                      local.get 8
                                      i64.store
                                      local.get 0
                                      local.get 7
                                      i64.store offset=16
                                      local.get 0
                                      local.get 6
                                      i64.store offset=8
                                      local.get 0
                                      local.get 5
                                      i64.store
                                      local.get 2
                                      i32.const -32
                                      i32.add
                                      local.tee 2
                                      local.tee 4
                                      global.set $__stack_pointer
                                      local.get 0
                                      i32.const 1
                                      local.get 2
                                      call $wrapper_u256_shr
                                      block  ;; label = @18
                                        local.get 5
                                        i32.wrap_i64
                                        i32.const 1
                                        i32.and
                                        local.get 2
                                        i64.load
                                        local.tee 9
                                        i64.const 127
                                        i64.and
                                        local.get 9
                                        local.get 5
                                        i64.const 1
                                        i64.and
                                        local.tee 10
                                        i64.eqz
                                        select
                                        local.tee 11
                                        i64.const 31
                                        i64.gt_u
                                        i64.const 0
                                        local.get 10
                                        i64.sub
                                        local.tee 9
                                        local.get 2
                                        i32.const 8
                                        i32.add
                                        i64.load
                                        i64.and
                                        local.tee 12
                                        i64.const 0
                                        i64.ne
                                        local.get 12
                                        i64.eqz
                                        select
                                        local.get 9
                                        local.get 2
                                        i32.const 16
                                        i32.add
                                        i64.load
                                        i64.and
                                        local.tee 13
                                        i64.const 0
                                        i64.ne
                                        local.get 9
                                        local.get 2
                                        i32.const 24
                                        i32.add
                                        i64.load
                                        i64.and
                                        local.tee 14
                                        i64.const 0
                                        i64.ne
                                        local.get 14
                                        i64.eqz
                                        select
                                        local.get 13
                                        local.get 14
                                        i64.or
                                        i64.eqz
                                        select
                                        i32.eq
                                        br_if 0 (;@18;)
                                        local.get 4
                                        i32.const -32
                                        i32.add
                                        local.tee 0
                                        local.tee 4
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
                                      local.get 3
                                      call $i32_from_big_endian_bytes32
                                      local.set 15
                                      local.get 4
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
                                      local.get 13
                                      i64.store offset=16
                                      local.get 0
                                      local.get 12
                                      i64.store offset=8
                                      local.get 0
                                      local.get 11
                                      i64.store
                                      local.get 15
                                      local.get 0
                                      call $wrapper_mstore_u256
                                      block  ;; label = @18
                                        local.get 10
                                        i64.const 0
                                        i64.ne
                                        br_if 0 (;@18;)
                                        local.get 2
                                        i32.const -32
                                        i32.add
                                        local.tee 0
                                        local.tee 2
                                        global.set $__stack_pointer
                                        local.get 3
                                        local.get 0
                                        call $u256_from_big_endian_bytes
                                        local.get 0
                                        i32.load
                                        local.set 4
                                        local.get 2
                                        i32.const -32
                                        i32.add
                                        local.tee 0
                                        local.tee 2
                                        global.set $__stack_pointer
                                        local.get 0
                                        i32.const 24
                                        i32.add
                                        local.get 8
                                        i64.store
                                        local.get 0
                                        local.get 7
                                        i64.store offset=16
                                        local.get 0
                                        local.get 6
                                        i64.store offset=8
                                        local.get 0
                                        local.get 5
                                        i64.const -256
                                        i64.and
                                        i64.store
                                        local.get 4
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
                                        local.get 11
                                        local.get 13
                                        i64.or
                                        local.get 12
                                        local.get 14
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
                                        local.tee 4
                                        global.set $__stack_pointer
                                        local.get 0
                                        i32.const 5
                                        local.get 2
                                        call $wrapper_u256_shl
                                        local.get 2
                                        i32.const 24
                                        i32.add
                                        i64.load
                                        local.set 5
                                        local.get 2
                                        i32.const 16
                                        i32.add
                                        i64.load
                                        local.set 10
                                        local.get 2
                                        i64.load
                                        local.set 9
                                        local.get 2
                                        i32.const 8
                                        i32.add
                                        i64.load
                                        local.set 6
                                        local.get 4
                                        i32.const -32
                                        i32.add
                                        local.tee 0
                                        local.tee 2
                                        global.set $__stack_pointer
                                        local.get 3
                                        local.get 0
                                        call $u256_from_big_endian_bytes
                                        local.get 5
                                        local.get 0
                                        i32.const 24
                                        i32.add
                                        i64.load
                                        i64.add
                                        local.get 10
                                        local.get 0
                                        i32.const 16
                                        i32.add
                                        i64.load
                                        local.tee 5
                                        i64.add
                                        local.tee 10
                                        local.get 5
                                        i64.lt_u
                                        i64.extend_i32_u
                                        i64.add
                                        local.get 10
                                        local.get 9
                                        local.get 0
                                        i64.load
                                        local.tee 5
                                        i64.add
                                        local.tee 8
                                        local.get 5
                                        i64.lt_u
                                        local.tee 4
                                        local.get 6
                                        local.get 0
                                        i32.const 8
                                        i32.add
                                        i64.load
                                        local.tee 9
                                        i64.add
                                        local.get 4
                                        i64.extend_i32_u
                                        i64.add
                                        local.tee 5
                                        local.get 9
                                        i64.lt_u
                                        local.get 5
                                        local.get 9
                                        i64.eq
                                        select
                                        i64.extend_i32_u
                                        i64.add
                                        local.tee 7
                                        local.get 10
                                        i64.lt_u
                                        i64.extend_i32_u
                                        i64.add
                                        local.set 12
                                        br 15 (;@3;)
                                      end
                                      i32.const 0
                                      i32.const 0
                                      call $wrapper_mstore_u32
                                      block  ;; label = @18
                                        block  ;; label = @19
                                          local.get 11
                                          local.get 13
                                          i64.or
                                          local.get 12
                                          local.get 14
                                          i64.or
                                          i64.or
                                          i64.eqz
                                          i32.eqz
                                          br_if 0 (;@19;)
                                          i64.const 0
                                          local.set 6
                                          i64.const 0
                                          local.set 7
                                          i64.const 0
                                          local.set 8
                                          i64.const 0
                                          local.set 9
                                          br 1 (;@18;)
                                        end
                                        i64.const 2958280948422763176
                                        local.set 19
                                        i64.const -3025497930225651768
                                        local.set 16
                                        i64.const 5451251748326869238
                                        local.set 17
                                        i64.const 3904501124902937955
                                        local.set 5
                                        i64.const 0
                                        local.set 10
                                        i64.const 0
                                        local.set 20
                                        i64.const 0
                                        local.set 18
                                        i64.const 0
                                        local.set 9
                                        loop  ;; label = @19
                                          local.get 2
                                          i32.const -32
                                          i32.add
                                          local.tee 0
                                          local.tee 2
                                          global.set $__stack_pointer
                                          local.get 3
                                          local.get 0
                                          call $u256_from_big_endian_bytes
                                          local.get 0
                                          i64.load
                                          local.set 6
                                          local.get 2
                                          i32.const -32
                                          i32.add
                                          local.tee 0
                                          local.tee 2
                                          global.set $__stack_pointer
                                          local.get 0
                                          i32.const 24
                                          i32.add
                                          local.get 19
                                          i64.store
                                          local.get 0
                                          local.get 16
                                          i64.store offset=16
                                          local.get 0
                                          local.get 17
                                          i64.store offset=8
                                          local.get 0
                                          local.get 5
                                          i64.store
                                          local.get 2
                                          i32.const -32
                                          i32.add
                                          local.tee 2
                                          local.tee 4
                                          global.set $__stack_pointer
                                          local.get 0
                                          local.get 2
                                          call $u256_to_big_endian_bytes
                                          local.get 4
                                          i32.const -32
                                          i32.add
                                          local.tee 0
                                          local.tee 4
                                          global.set $__stack_pointer
                                          local.get 2
                                          local.get 0
                                          call $wrapper_sload_u256_using_little_endian_hostapi
                                          local.get 0
                                          i64.load
                                          local.set 7
                                          local.get 0
                                          i32.const 8
                                          i32.add
                                          i64.load
                                          local.set 8
                                          local.get 0
                                          i32.const 16
                                          i32.add
                                          i64.load
                                          local.set 21
                                          local.get 0
                                          i32.const 24
                                          i32.add
                                          i64.load
                                          local.set 25
                                          local.get 4
                                          i32.const -32
                                          i32.add
                                          local.tee 0
                                          local.tee 2
                                          global.set $__stack_pointer
                                          local.get 0
                                          i32.const 24
                                          i32.add
                                          local.get 25
                                          i64.store
                                          local.get 0
                                          local.get 21
                                          i64.store offset=16
                                          local.get 0
                                          local.get 8
                                          i64.store offset=8
                                          local.get 0
                                          local.get 7
                                          i64.store
                                          local.get 6
                                          local.get 10
                                          i64.add
                                          i32.wrap_i64
                                          i32.const 32
                                          i32.add
                                          local.get 0
                                          call $wrapper_mstore_u256
                                          local.get 18
                                          local.get 10
                                          i64.const 32
                                          i64.add
                                          local.tee 6
                                          local.get 10
                                          i64.lt_u
                                          local.tee 0
                                          local.get 20
                                          local.get 0
                                          i64.extend_i32_u
                                          i64.add
                                          local.tee 7
                                          local.get 20
                                          i64.lt_u
                                          local.get 6
                                          local.get 10
                                          i64.ge_u
                                          select
                                          i64.extend_i32_u
                                          i64.add
                                          local.tee 8
                                          local.get 18
                                          i64.lt_u
                                          local.set 0
                                          local.get 19
                                          local.get 16
                                          local.get 5
                                          i64.const 1
                                          i64.add
                                          local.tee 21
                                          local.get 5
                                          i64.lt_u
                                          local.tee 4
                                          local.get 17
                                          local.get 4
                                          i64.extend_i32_u
                                          i64.add
                                          local.tee 25
                                          local.get 17
                                          i64.lt_u
                                          local.get 21
                                          local.get 5
                                          i64.ge_u
                                          select
                                          i64.extend_i32_u
                                          i64.add
                                          local.tee 26
                                          local.get 16
                                          i64.lt_u
                                          i64.extend_i32_u
                                          i64.add
                                          local.set 19
                                          local.get 6
                                          local.set 10
                                          local.get 7
                                          local.set 20
                                          local.get 8
                                          local.set 18
                                          local.get 21
                                          local.set 5
                                          local.get 25
                                          local.set 17
                                          local.get 26
                                          local.set 16
                                          local.get 6
                                          local.get 11
                                          i64.lt_u
                                          local.get 7
                                          local.get 12
                                          i64.lt_u
                                          local.get 7
                                          local.get 12
                                          i64.eq
                                          select
                                          local.get 8
                                          local.get 13
                                          i64.lt_u
                                          local.get 9
                                          local.get 0
                                          i64.extend_i32_u
                                          i64.add
                                          local.tee 9
                                          local.get 14
                                          i64.lt_u
                                          local.get 9
                                          local.get 14
                                          i64.eq
                                          select
                                          local.get 8
                                          local.get 13
                                          i64.xor
                                          local.get 9
                                          local.get 14
                                          i64.xor
                                          i64.or
                                          i64.eqz
                                          select
                                          br_if 0 (;@19;)
                                        end
                                      end
                                      local.get 2
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 2
                                      global.set $__stack_pointer
                                      local.get 3
                                      local.get 0
                                      call $u256_from_big_endian_bytes
                                      local.get 0
                                      i32.const 24
                                      i32.add
                                      i64.load
                                      local.get 9
                                      i64.add
                                      local.get 0
                                      i32.const 16
                                      i32.add
                                      i64.load
                                      local.tee 5
                                      local.get 8
                                      i64.add
                                      local.tee 10
                                      local.get 5
                                      i64.lt_u
                                      i64.extend_i32_u
                                      i64.add
                                      local.get 10
                                      local.get 0
                                      i64.load
                                      local.tee 5
                                      local.get 6
                                      i64.add
                                      local.tee 8
                                      local.get 5
                                      i64.lt_u
                                      local.tee 4
                                      local.get 0
                                      i32.const 8
                                      i32.add
                                      i64.load
                                      local.tee 9
                                      local.get 7
                                      i64.add
                                      local.get 4
                                      i64.extend_i32_u
                                      i64.add
                                      local.tee 5
                                      local.get 9
                                      i64.lt_u
                                      local.get 5
                                      local.get 9
                                      i64.eq
                                      select
                                      i64.extend_i32_u
                                      i64.add
                                      local.tee 7
                                      local.get 10
                                      i64.lt_u
                                      i64.extend_i32_u
                                      i64.add
                                      local.set 12
                                      br 14 (;@3;)
                                    end
                                    block  ;; label = @17
                                      call $wrapper_callvalue_not_zero
                                      i32.eqz
                                      br_if 0 (;@17;)
                                      i32.const 0
                                      i32.const 0
                                      call $wrapper_revert
                                    end
                                    block  ;; label = @17
                                      call $wrapper_calldata_size_minus_4
                                      i32.const 63
                                      i32.gt_u
                                      br_if 0 (;@17;)
                                      i32.const 0
                                      i32.const 0
                                      call $wrapper_revert
                                    end
                                    i32.const 4
                                    local.get 1
                                    i32.const 384
                                    i32.add
                                    call $wrapper_calldataload_bytes32
                                    local.get 1
                                    i32.const 384
                                    i32.add
                                    local.get 1
                                    i32.const 576
                                    i32.add
                                    call $u256_from_big_endian_bytes
                                    local.get 1
                                    i32.const 576
                                    i32.add
                                    i32.const 16
                                    i32.add
                                    i64.load
                                    local.set 8
                                    local.get 1
                                    i32.const 576
                                    i32.add
                                    i32.const 8
                                    i32.add
                                    i64.load
                                    local.set 5
                                    local.get 1
                                    i64.load offset=576
                                    local.set 10
                                    local.get 0
                                    i32.const -32
                                    i32.add
                                    local.tee 2
                                    local.tee 0
                                    global.set $__stack_pointer
                                    i32.const 36
                                    local.get 2
                                    call $wrapper_calldataload_bytes32
                                    local.get 0
                                    i32.const -32
                                    i32.add
                                    local.tee 0
                                    local.tee 4
                                    global.set $__stack_pointer
                                    local.get 2
                                    local.get 0
                                    call $u256_from_big_endian_bytes
                                    local.get 1
                                    i32.const 32
                                    i32.add
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
                                    call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_requireOwned
                                    local.get 1
                                    i32.const 32
                                    i32.add
                                    i32.const 24
                                    i32.add
                                    i64.load
                                    local.set 16
                                    local.get 1
                                    i32.const 32
                                    i32.add
                                    i32.const 16
                                    i32.add
                                    i64.load
                                    local.set 9
                                    local.get 1
                                    i32.const 32
                                    i32.add
                                    i32.const 8
                                    i32.add
                                    i64.load
                                    local.set 6
                                    local.get 1
                                    i64.load offset=32
                                    local.set 7
                                    local.get 4
                                    i32.const -32
                                    i32.add
                                    local.tee 4
                                    local.tee 0
                                    global.set $__stack_pointer
                                    local.get 4
                                    call $wrapper_caller
                                    block  ;; label = @17
                                      local.get 4
                                      call $wrapper_bytes32_iszero
                                      br_if 0 (;@17;)
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 3
                                      local.tee 0
                                      global.set $__stack_pointer
                                      local.get 3
                                      call $wrapper_caller
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 4
                                      local.tee 0
                                      global.set $__stack_pointer
                                      local.get 4
                                      i32.const 24
                                      i32.add
                                      local.get 16
                                      i64.store
                                      local.get 4
                                      local.get 9
                                      i64.store offset=16
                                      local.get 4
                                      local.get 6
                                      i64.store offset=8
                                      local.get 4
                                      local.get 7
                                      i64.store
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 15
                                      local.tee 0
                                      global.set $__stack_pointer
                                      local.get 4
                                      local.get 15
                                      call $u256_to_big_endian_bytes
                                      local.get 15
                                      local.get 3
                                      call $wrapper_bytes32_eq
                                      br_if 0 (;@17;)
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 4
                                      global.set $__stack_pointer
                                      local.get 0
                                      i32.const 24
                                      i32.add
                                      local.get 16
                                      i64.store
                                      local.get 0
                                      local.get 9
                                      i64.store offset=16
                                      local.get 0
                                      local.get 6
                                      i64.store offset=8
                                      local.get 0
                                      local.get 7
                                      i64.store
                                      i32.const 0
                                      local.get 0
                                      call $wrapper_mstore_u256
                                      i32.const 32
                                      i32.const 5
                                      call $wrapper_mstore_u32
                                      local.get 4
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 4
                                      global.set $__stack_pointer
                                      i32.const 0
                                      i32.const 64
                                      local.get 0
                                      call $wrapper_keccak256
                                      local.get 4
                                      i32.const -32
                                      i32.add
                                      local.tee 4
                                      local.tee 3
                                      global.set $__stack_pointer
                                      local.get 4
                                      call $wrapper_caller
                                      i32.const 0
                                      local.get 4
                                      call $wrapper_mstore_bytes32
                                      i32.const 32
                                      local.get 0
                                      call $wrapper_mstore_bytes32
                                      local.get 3
                                      i32.const -32
                                      i32.add
                                      local.tee 4
                                      local.tee 0
                                      global.set $__stack_pointer
                                      i32.const 0
                                      i32.const 64
                                      local.get 4
                                      call $wrapper_keccak256
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 3
                                      local.tee 0
                                      global.set $__stack_pointer
                                      local.get 4
                                      local.get 3
                                      call $wrapper_sload_u256_using_little_endian_hostapi
                                      local.get 3
                                      i32.load8_u
                                      br_if 0 (;@17;)
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 3
                                      local.tee 0
                                      global.set $__stack_pointer
                                      i32.const 64
                                      local.get 3
                                      call $wrapper_mload_bytes32
                                      local.get 0
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 4
                                      global.set $__stack_pointer
                                      local.get 4
                                      i32.const -32
                                      i32.add
                                      local.tee 4
                                      local.tee 15
                                      global.set $__stack_pointer
                                      local.get 4
                                      i32.const 24
                                      i32.add
                                      i32.const 65952
                                      i32.const 24
                                      i32.add
                                      i64.load
                                      i64.store align=1
                                      local.get 4
                                      i32.const 16
                                      i32.add
                                      i32.const 65952
                                      i32.const 16
                                      i32.add
                                      i64.load
                                      i64.store align=1
                                      local.get 4
                                      i32.const 8
                                      i32.add
                                      i32.const 65952
                                      i32.const 8
                                      i32.add
                                      i64.load
                                      i64.store align=1
                                      local.get 4
                                      i32.const 0
                                      i64.load offset=65952
                                      i64.store align=1
                                      local.get 4
                                      local.get 0
                                      call $u256_from_big_endian_bytes
                                      local.get 0
                                      i64.load
                                      local.set 16
                                      local.get 0
                                      i32.const 8
                                      i32.add
                                      i64.load
                                      local.set 17
                                      local.get 0
                                      i32.const 16
                                      i32.add
                                      i64.load
                                      local.set 14
                                      local.get 0
                                      i32.const 24
                                      i32.add
                                      i64.load
                                      local.set 19
                                      local.get 15
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 4
                                      global.set $__stack_pointer
                                      local.get 0
                                      i32.const 24
                                      i32.add
                                      local.get 19
                                      i64.store
                                      local.get 0
                                      local.get 14
                                      i64.store offset=16
                                      local.get 0
                                      local.get 17
                                      i64.store offset=8
                                      local.get 0
                                      local.get 16
                                      i64.store
                                      local.get 4
                                      i32.const -32
                                      i32.add
                                      local.tee 4
                                      local.tee 15
                                      global.set $__stack_pointer
                                      local.get 0
                                      i32.const 224
                                      local.get 4
                                      call $wrapper_u256_shl
                                      local.get 4
                                      i64.load
                                      local.set 16
                                      local.get 4
                                      i32.const 8
                                      i32.add
                                      i64.load
                                      local.set 17
                                      local.get 4
                                      i32.const 16
                                      i32.add
                                      i64.load
                                      local.set 14
                                      local.get 4
                                      i32.const 24
                                      i32.add
                                      i64.load
                                      local.set 19
                                      local.get 3
                                      call $i32_from_big_endian_bytes32
                                      local.set 4
                                      local.get 15
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 15
                                      global.set $__stack_pointer
                                      local.get 0
                                      i32.const 24
                                      i32.add
                                      local.get 19
                                      i64.store
                                      local.get 0
                                      local.get 14
                                      i64.store offset=16
                                      local.get 0
                                      local.get 17
                                      i64.store offset=8
                                      local.get 0
                                      local.get 16
                                      i64.store
                                      local.get 4
                                      local.get 0
                                      call $wrapper_mstore_u256
                                      local.get 15
                                      i32.const -32
                                      i32.add
                                      local.tee 0
                                      local.tee 15
                                      global.set $__stack_pointer
                                      local.get 3
                                      local.get 0
                                      call $u256_from_big_endian_bytes
                                      local.get 0
                                      i32.load
                                      local.set 22
                                      local.get 15
                                      i32.const -32
                                      i32.add
                                      local.tee 3
                                      local.tee 0
                                      global.set $__stack_pointer
                                      local.get 3
                                      call $wrapper_caller
                                      local.get 22
                                      i32.const 4
                                      i32.add
                                      local.get 3
                                      call $wrapper_mstore_bytes32
                                      local.get 4
                                      i32.const 36
                                      call $wrapper_revert
                                    end
                                    local.get 0
                                    i32.const -32
                                    i32.add
                                    local.tee 0
                                    local.tee 4
                                    global.set $__stack_pointer
                                    local.get 0
                                    i32.const 24
                                    i32.add
                                    i64.const 0
                                    i64.store
                                    local.get 0
                                    local.get 9
                                    i64.const 4294967295
                                    i64.and
                                    i64.store offset=16
                                    local.get 0
                                    local.get 6
                                    i64.store offset=8
                                    local.get 0
                                    local.get 7
                                    i64.store
                                    local.get 4
                                    i32.const -32
                                    i32.add
                                    local.tee 4
                                    local.tee 3
                                    global.set $__stack_pointer
                                    local.get 0
                                    local.get 4
                                    call $u256_to_big_endian_bytes
                                    local.get 3
                                    i32.const -32
                                    i32.add
                                    local.tee 0
                                    local.tee 3
                                    global.set $__stack_pointer
                                    local.get 0
                                    i32.const 24
                                    i32.add
                                    i64.const 0
                                    i64.store
                                    local.get 0
                                    local.get 8
                                    i64.const 4294967295
                                    i64.and
                                    local.tee 9
                                    i64.store offset=16
                                    local.get 0
                                    local.get 5
                                    i64.store offset=8
                                    local.get 0
                                    local.get 10
                                    i64.store
                                    local.get 3
                                    i32.const -32
                                    i32.add
                                    local.tee 3
                                    local.tee 15
                                    global.set $__stack_pointer
                                    local.get 0
                                    local.get 3
                                    call $u256_to_big_endian_bytes
                                    i32.const 0
                                    i32.const 0
                                    i32.const 65984
                                    local.get 4
                                    local.get 3
                                    local.get 2
                                    call $wrapper_log4
                                    i32.const 0
                                    local.get 2
                                    call $wrapper_mstore_bytes32
                                    local.get 15
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
                                    i32.const 32
                                    local.get 0
                                    call $wrapper_mstore_u256
                                    local.get 2
                                    i32.const -32
                                    i32.add
                                    local.tee 4
                                    local.tee 0
                                    global.set $__stack_pointer
                                    i32.const 0
                                    i32.const 64
                                    local.get 4
                                    call $wrapper_keccak256
                                    local.get 0
                                    i32.const -32
                                    i32.add
                                    local.tee 0
                                    local.tee 2
                                    global.set $__stack_pointer
                                    local.get 4
                                    local.get 0
                                    call $wrapper_sload_u256_using_little_endian_hostapi
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
                                    local.set 8
                                    local.get 0
                                    i32.const 24
                                    i32.add
                                    i64.load
                                    local.set 16
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
                                    local.tee 3
                                    global.set $__stack_pointer
                                    local.get 2
                                    i32.const 24
                                    i32.add
                                    i32.const 66016
                                    i32.const 24
                                    i32.add
                                    i64.load
                                    i64.store align=1
                                    local.get 2
                                    i32.const 16
                                    i32.add
                                    i32.const 66016
                                    i32.const 16
                                    i32.add
                                    i64.load
                                    i64.store align=1
                                    local.get 2
                                    i32.const 8
                                    i32.add
                                    i32.const 66016
                                    i32.const 8
                                    i32.add
                                    i64.load
                                    i64.store align=1
                                    local.get 2
                                    i32.const 0
                                    i64.load offset=66016
                                    i64.store align=1
                                    local.get 2
                                    local.get 0
                                    call $u256_from_big_endian_bytes
                                    local.get 0
                                    i64.load
                                    local.set 17
                                    local.get 0
                                    i32.const 8
                                    i32.add
                                    i64.load
                                    local.set 14
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
                                    local.get 3
                                    i32.const -32
                                    i32.add
                                    local.tee 0
                                    local.tee 2
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
                                    local.get 14
                                    i64.store offset=8
                                    local.get 0
                                    local.get 17
                                    i64.store
                                    local.get 2
                                    i32.const -32
                                    i32.add
                                    local.tee 2
                                    local.tee 3
                                    global.set $__stack_pointer
                                    local.get 0
                                    i32.const 160
                                    local.get 2
                                    call $wrapper_u256_shl
                                    local.get 2
                                    i32.const 24
                                    i32.add
                                    i64.load
                                    local.set 17
                                    local.get 2
                                    i64.load
                                    local.set 14
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
                                    local.get 3
                                    i32.const -32
                                    i32.add
                                    local.tee 0
                                    global.set $__stack_pointer
                                    local.get 0
                                    i32.const 24
                                    i32.add
                                    local.get 17
                                    local.get 16
                                    i64.and
                                    i64.store
                                    local.get 0
                                    local.get 20
                                    local.get 8
                                    i64.and
                                    local.get 9
                                    i64.or
                                    i64.store offset=16
                                    local.get 0
                                    local.get 19
                                    local.get 7
                                    i64.and
                                    local.get 5
                                    i64.or
                                    i64.store offset=8
                                    local.get 0
                                    local.get 14
                                    local.get 6
                                    i64.and
                                    local.get 10
                                    i64.or
                                    i64.store
                                    local.get 4
                                    local.get 0
                                    call $wrapper_sstore_u256_using_little_endian_hostapi
                                    i32.const 0
                                    i32.const 0
                                    call $wrapper_return
                                    br 15 (;@1;)
                                  end
                                  block  ;; label = @16
                                    call $wrapper_callvalue_not_zero
                                    i32.eqz
                                    br_if 0 (;@16;)
                                    i32.const 0
                                    i32.const 0
                                    call $wrapper_revert
                                  end
                                  local.get 1
                                  i32.const 160
                                  i32.add
                                  call $wrapper_calldata_size
                                  i64.extend_i32_u
                                  i64.const 0
                                  i64.const 0
                                  i64.const 0
                                  call $MyERC721_48598_deployed.MyERC721_48598_deployed.abi_decode_addresst_addresst_uint256
                                  local.get 1
                                  i32.const 248
                                  i32.add
                                  i64.load
                                  local.set 5
                                  local.get 1
                                  i32.const 240
                                  i32.add
                                  i64.load
                                  local.set 10
                                  local.get 1
                                  i32.const 232
                                  i32.add
                                  i64.load
                                  local.set 9
                                  local.get 1
                                  i32.const 200
                                  i32.add
                                  i64.load
                                  local.set 6
                                  local.get 1
                                  i32.const 208
                                  i32.add
                                  i64.load
                                  local.set 7
                                  local.get 1
                                  i32.const 216
                                  i32.add
                                  i64.load
                                  local.set 8
                                  local.get 1
                                  i32.const 160
                                  i32.add
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 16
                                  local.get 1
                                  i32.const 160
                                  i32.add
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.set 17
                                  local.get 1
                                  i32.const 160
                                  i32.add
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.set 14
                                  local.get 1
                                  i64.load offset=224
                                  local.set 19
                                  local.get 1
                                  i64.load offset=192
                                  local.set 20
                                  local.get 1
                                  i64.load offset=160
                                  local.set 18
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 0
                                  global.set $__stack_pointer
                                  i32.const 64
                                  local.get 2
                                  call $wrapper_mload_bytes32
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 2
                                  local.get 0
                                  call $u256_from_big_endian_bytes
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
                                  call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation_17595
                                  local.get 2
                                  call $i32_from_big_endian_bytes32
                                  i32.const 0
                                  call $wrapper_mstore_u32
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  local.get 14
                                  i64.store
                                  local.get 0
                                  local.get 17
                                  i64.store offset=16
                                  local.get 0
                                  local.get 16
                                  i64.store offset=8
                                  local.get 0
                                  local.get 18
                                  i64.store
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 4
                                  local.tee 3
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 4
                                  call $u256_to_big_endian_bytes
                                  local.get 3
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 3
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  local.get 8
                                  i64.store
                                  local.get 0
                                  local.get 7
                                  i64.store offset=16
                                  local.get 0
                                  local.get 6
                                  i64.store offset=8
                                  local.get 0
                                  local.get 20
                                  i64.store
                                  local.get 3
                                  i32.const -32
                                  i32.add
                                  local.tee 3
                                  local.tee 15
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 3
                                  call $u256_to_big_endian_bytes
                                  local.get 4
                                  local.get 3
                                  local.get 19
                                  local.get 9
                                  local.get 10
                                  local.get 5
                                  call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_transferFrom
                                  local.get 15
                                  i32.const -32
                                  i32.add
                                  local.tee 4
                                  local.tee 0
                                  global.set $__stack_pointer
                                  local.get 4
                                  call $wrapper_caller
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 3
                                  global.set $__stack_pointer
                                  local.get 4
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
                                  local.set 12
                                  local.get 0
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 13
                                  local.get 0
                                  i64.load
                                  local.set 25
                                  local.get 3
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  global.set $__stack_pointer
                                  local.get 2
                                  local.get 0
                                  call $u256_from_big_endian_bytes
                                  local.get 25
                                  local.get 13
                                  local.get 12
                                  local.get 21
                                  local.get 18
                                  local.get 16
                                  local.get 17
                                  local.get 14
                                  local.get 20
                                  local.get 6
                                  local.get 7
                                  local.get 8
                                  local.get 19
                                  local.get 9
                                  local.get 10
                                  local.get 5
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
                                  call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOnERC721Received
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_return
                                  br 14 (;@1;)
                                end
                                block  ;; label = @15
                                  call $wrapper_callvalue_not_zero
                                  i32.eqz
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                block  ;; label = @15
                                  call $wrapper_calldata_size_minus_4
                                  i32.const 31
                                  i32.gt_u
                                  br_if 0 (;@15;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                end
                                i32.const 4
                                local.get 1
                                i32.const 384
                                i32.add
                                call $wrapper_calldataload_bytes32
                                local.get 1
                                i32.const 384
                                i32.add
                                local.get 1
                                i32.const 576
                                i32.add
                                call $u256_from_big_endian_bytes
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 24
                                i32.add
                                i64.load
                                local.set 25
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 16
                                i32.add
                                i64.load
                                local.set 14
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 8
                                i32.add
                                i64.load
                                local.set 7
                                local.get 1
                                i64.load offset=576
                                local.set 8
                                call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOwner
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
                                i64.const 7
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_to_big_endian_bytes
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 2
                                local.get 0
                                call $wrapper_sload_u256_using_little_endian_hostapi
                                block  ;; label = @15
                                  local.get 0
                                  i64.load
                                  local.tee 5
                                  local.get 0
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.tee 10
                                  i64.and
                                  local.get 0
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.tee 9
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.tee 6
                                  i64.and
                                  i64.and
                                  i64.const -1
                                  i64.ne
                                  br_if 0 (;@15;)
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 4
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
                                local.get 4
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
                                i64.const 7
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_to_big_endian_bytes
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                local.get 6
                                local.get 10
                                local.get 5
                                i64.const 1
                                i64.add
                                local.tee 16
                                local.get 5
                                i64.lt_u
                                local.tee 3
                                local.get 9
                                local.get 3
                                i64.extend_i32_u
                                i64.add
                                local.tee 17
                                local.get 9
                                i64.lt_u
                                local.get 16
                                local.get 5
                                i64.ge_u
                                select
                                i64.extend_i32_u
                                i64.add
                                local.tee 19
                                local.get 10
                                i64.lt_u
                                i64.extend_i32_u
                                i64.add
                                i64.store
                                local.get 0
                                local.get 19
                                i64.store offset=16
                                local.get 0
                                local.get 17
                                i64.store offset=8
                                local.get 0
                                local.get 16
                                i64.store
                                local.get 2
                                local.get 0
                                call $wrapper_sstore_u256_using_little_endian_hostapi
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 4
                                local.tee 0
                                global.set $__stack_pointer
                                i32.const 64
                                local.get 4
                                call $wrapper_mload_bytes32
                                local.get 0
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 4
                                local.get 0
                                call $u256_from_big_endian_bytes
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
                                call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation_17595
                                local.get 4
                                call $i32_from_big_endian_bytes32
                                i32.const 0
                                call $wrapper_mstore_u32
                                block  ;; label = @15
                                  local.get 8
                                  local.get 14
                                  i64.const 4294967295
                                  i64.and
                                  local.tee 16
                                  i64.or
                                  local.get 7
                                  i64.or
                                  i64.const 0
                                  i64.ne
                                  br_if 0 (;@15;)
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 3
                                  local.tee 0
                                  global.set $__stack_pointer
                                  i32.const 64
                                  local.get 3
                                  call $wrapper_mload_bytes32
                                  local.get 3
                                  call $i32_from_big_endian_bytes32
                                  local.set 15
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  i64.const 7250987342154956800
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
                                  local.get 15
                                  local.get 0
                                  call $wrapper_mstore_u256
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 3
                                  local.get 0
                                  call $u256_from_big_endian_bytes
                                  local.get 0
                                  i32.load
                                  i32.const 4
                                  i32.add
                                  i32.const 0
                                  call $wrapper_mstore_u32
                                  local.get 15
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
                                local.get 6
                                i64.store
                                local.get 0
                                local.get 10
                                i64.store offset=16
                                local.get 0
                                local.get 9
                                i64.store offset=8
                                local.get 0
                                local.get 5
                                i64.store
                                i32.const 0
                                local.get 0
                                call $wrapper_mstore_u256
                                i32.const 32
                                i32.const 2
                                call $wrapper_mstore_u32
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 0
                                global.set $__stack_pointer
                                i32.const 0
                                i32.const 64
                                local.get 3
                                call $wrapper_keccak256
                                local.get 0
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 3
                                local.get 0
                                call $wrapper_sload_u256_using_little_endian_hostapi
                                block  ;; label = @15
                                  local.get 0
                                  i64.load
                                  local.tee 21
                                  local.get 0
                                  i32.const 16
                                  i32.add
                                  i64.load32_u
                                  local.tee 12
                                  i64.or
                                  local.get 0
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.tee 13
                                  i64.or
                                  i64.eqz
                                  local.tee 23
                                  br_if 0 (;@15;)
                                  local.get 1
                                  i32.const 576
                                  i32.add
                                  i32.const 24
                                  i32.add
                                  local.get 6
                                  i64.store
                                  local.get 1
                                  local.get 5
                                  i64.store offset=576
                                  local.get 1
                                  local.get 9
                                  i64.store offset=584
                                  local.get 1
                                  local.get 10
                                  i64.store offset=592
                                  i32.const 0
                                  local.get 1
                                  i32.const 576
                                  i32.add
                                  call $wrapper_mstore_u256
                                  i32.const 32
                                  i32.const 4
                                  call $wrapper_mstore_u32
                                  i32.const 0
                                  i32.const 64
                                  local.get 1
                                  i32.const 384
                                  i32.add
                                  call $wrapper_keccak256
                                  local.get 1
                                  i32.const 384
                                  i32.add
                                  local.get 1
                                  i32.const 544
                                  i32.add
                                  call $wrapper_sload_u256_using_little_endian_hostapi
                                  local.get 1
                                  i32.const 512
                                  i32.add
                                  i32.const 8
                                  i32.add
                                  i32.const 65856
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  i64.store
                                  local.get 1
                                  i32.const 512
                                  i32.add
                                  i32.const 16
                                  i32.add
                                  i32.const 65856
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  i64.store
                                  local.get 1
                                  i32.const 512
                                  i32.add
                                  i32.const 24
                                  i32.add
                                  i32.const 65856
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  i64.store
                                  local.get 1
                                  i32.const 0
                                  i64.load offset=65856
                                  i64.store offset=512
                                  local.get 1
                                  i32.const 544
                                  i32.add
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 17
                                  local.get 1
                                  i32.const 544
                                  i32.add
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.set 19
                                  local.get 1
                                  i32.const 544
                                  i32.add
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.set 20
                                  local.get 1
                                  i64.load offset=544
                                  local.set 18
                                  local.get 1
                                  i32.const 512
                                  i32.add
                                  local.get 1
                                  i32.const 480
                                  i32.add
                                  call $u256_from_big_endian_bytes
                                  local.get 1
                                  i32.const 480
                                  i32.add
                                  i32.const 160
                                  local.get 1
                                  i32.const 448
                                  i32.add
                                  call $wrapper_u256_shl
                                  local.get 1
                                  i32.const 416
                                  i32.add
                                  i32.const 24
                                  i32.add
                                  local.get 20
                                  local.get 1
                                  i32.const 448
                                  i32.add
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  i64.and
                                  i64.store
                                  local.get 1
                                  local.get 19
                                  local.get 1
                                  i32.const 448
                                  i32.add
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  i64.and
                                  i64.store offset=432
                                  local.get 1
                                  local.get 17
                                  local.get 1
                                  i32.const 448
                                  i32.add
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  i64.and
                                  i64.store offset=424
                                  local.get 1
                                  local.get 18
                                  local.get 1
                                  i64.load offset=448
                                  i64.and
                                  i64.store offset=416
                                  local.get 1
                                  i32.const 384
                                  i32.add
                                  local.get 1
                                  i32.const 416
                                  i32.add
                                  call $wrapper_sstore_u256_using_little_endian_hostapi
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
                                  local.get 12
                                  i64.store offset=16
                                  local.get 0
                                  local.get 13
                                  i64.store offset=8
                                  local.get 0
                                  local.get 21
                                  i64.store
                                  i32.const 0
                                  local.get 0
                                  call $wrapper_mstore_u256
                                  i32.const 32
                                  i32.const 3
                                  call $wrapper_mstore_u32
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 3
                                  local.tee 0
                                  global.set $__stack_pointer
                                  i32.const 0
                                  i32.const 64
                                  local.get 3
                                  call $wrapper_keccak256
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 3
                                  local.get 0
                                  call $wrapper_sload_u256_using_little_endian_hostapi
                                  local.get 0
                                  i64.load
                                  local.set 19
                                  local.get 0
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 17
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.set 26
                                  local.get 0
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.set 20
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 17
                                  local.get 19
                                  i64.const -1
                                  i64.add
                                  local.tee 18
                                  local.get 19
                                  i64.lt_u
                                  local.tee 15
                                  i64.extend_i32_u
                                  i64.add
                                  i64.const -1
                                  i64.add
                                  local.tee 19
                                  i64.store offset=8
                                  local.get 0
                                  local.get 18
                                  i64.store
                                  local.get 0
                                  local.get 20
                                  i64.const -1
                                  i64.add
                                  local.tee 18
                                  local.get 15
                                  local.get 19
                                  local.get 17
                                  i64.lt_u
                                  local.get 19
                                  local.get 17
                                  i64.eq
                                  select
                                  i64.extend_i32_u
                                  i64.add
                                  local.tee 17
                                  i64.store offset=16
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  local.get 26
                                  local.get 18
                                  local.get 20
                                  i64.lt_u
                                  i64.extend_i32_u
                                  i64.add
                                  local.get 17
                                  local.get 18
                                  i64.lt_u
                                  i64.extend_i32_u
                                  i64.add
                                  i64.const -1
                                  i64.add
                                  i64.store
                                  local.get 3
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
                                i32.const 24
                                i32.add
                                i64.const 0
                                i64.store
                                local.get 0
                                local.get 16
                                i64.store offset=16
                                local.get 0
                                local.get 7
                                i64.store offset=8
                                local.get 0
                                local.get 8
                                i64.store
                                i32.const 0
                                local.get 0
                                call $wrapper_mstore_u256
                                i32.const 32
                                i32.const 3
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
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 2
                                local.get 0
                                call $wrapper_sload_u256_using_little_endian_hostapi
                                local.get 0
                                i64.load
                                local.set 17
                                local.get 0
                                i32.const 8
                                i32.add
                                i64.load
                                local.set 19
                                local.get 0
                                i32.const 24
                                i32.add
                                i64.load
                                local.set 26
                                local.get 0
                                i32.const 16
                                i32.add
                                i64.load
                                local.set 20
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 0
                                local.get 19
                                local.get 17
                                i64.const 1
                                i64.add
                                local.tee 18
                                local.get 17
                                i64.lt_u
                                local.tee 15
                                i64.extend_i32_u
                                i64.add
                                local.tee 11
                                i64.store offset=8
                                local.get 0
                                local.get 18
                                i64.store
                                local.get 0
                                local.get 20
                                local.get 15
                                local.get 11
                                local.get 19
                                i64.lt_u
                                local.get 18
                                local.get 17
                                i64.ge_u
                                select
                                i64.extend_i32_u
                                i64.add
                                local.tee 17
                                i64.store offset=16
                                local.get 0
                                i32.const 24
                                i32.add
                                local.get 26
                                local.get 17
                                local.get 20
                                i64.lt_u
                                i64.extend_i32_u
                                i64.add
                                i64.store
                                local.get 2
                                local.get 0
                                call $wrapper_sstore_u256_using_little_endian_hostapi
                                local.get 3
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
                                local.get 10
                                i64.store offset=16
                                local.get 0
                                local.get 9
                                i64.store offset=8
                                local.get 0
                                local.get 5
                                i64.store
                                i32.const 0
                                local.get 0
                                call $wrapper_mstore_u256
                                i32.const 32
                                i32.const 2
                                call $wrapper_mstore_u32
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 0
                                global.set $__stack_pointer
                                i32.const 0
                                i32.const 64
                                local.get 3
                                call $wrapper_keccak256
                                local.get 0
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 3
                                local.get 0
                                call $wrapper_sload_u256_using_little_endian_hostapi
                                local.get 0
                                i64.load
                                local.set 17
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
                                local.set 18
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
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 2
                                i32.const 24
                                i32.add
                                i32.const 66048
                                i32.const 24
                                i32.add
                                i64.load
                                i64.store align=1
                                local.get 2
                                i32.const 16
                                i32.add
                                i32.const 66048
                                i32.const 16
                                i32.add
                                i64.load
                                i64.store align=1
                                local.get 2
                                i32.const 8
                                i32.add
                                i32.const 66048
                                i32.const 8
                                i32.add
                                i64.load
                                i64.store align=1
                                local.get 2
                                i32.const 0
                                i64.load offset=66048
                                i64.store align=1
                                local.get 2
                                local.get 0
                                call $u256_from_big_endian_bytes
                                local.get 0
                                i64.load
                                local.set 26
                                local.get 0
                                i32.const 8
                                i32.add
                                i64.load
                                local.set 11
                                local.get 0
                                i32.const 16
                                i32.add
                                i64.load
                                local.set 27
                                local.get 0
                                i32.const 24
                                i32.add
                                i64.load
                                local.set 28
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                local.get 28
                                i64.store
                                local.get 0
                                local.get 27
                                i64.store offset=16
                                local.get 0
                                local.get 11
                                i64.store offset=8
                                local.get 0
                                local.get 26
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 160
                                local.get 2
                                call $wrapper_u256_shl
                                local.get 2
                                i32.const 24
                                i32.add
                                i64.load
                                local.set 26
                                local.get 2
                                i64.load
                                local.set 11
                                local.get 2
                                i32.const 8
                                i32.add
                                i64.load
                                local.set 27
                                local.get 2
                                i32.const 16
                                i32.add
                                i64.load
                                local.set 28
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                local.get 26
                                local.get 18
                                i64.and
                                i64.store
                                local.get 0
                                local.get 28
                                local.get 20
                                i64.and
                                local.get 16
                                i64.or
                                i64.store offset=16
                                local.get 0
                                local.get 27
                                local.get 19
                                i64.and
                                local.get 7
                                i64.or
                                i64.store offset=8
                                local.get 0
                                local.get 11
                                local.get 17
                                i64.and
                                local.get 8
                                i64.or
                                i64.store
                                local.get 3
                                local.get 0
                                call $wrapper_sstore_u256_using_little_endian_hostapi
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
                                local.get 12
                                i64.store offset=16
                                local.get 0
                                local.get 13
                                i64.store offset=8
                                local.get 0
                                local.get 21
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                local.get 3
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
                                i64.const 0
                                i64.store
                                local.get 0
                                local.get 16
                                i64.store offset=16
                                local.get 0
                                local.get 7
                                i64.store offset=8
                                local.get 0
                                local.get 8
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 15
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                local.get 15
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
                                local.get 6
                                i64.store
                                local.get 0
                                local.get 10
                                i64.store offset=16
                                local.get 0
                                local.get 9
                                i64.store offset=8
                                local.get 0
                                local.get 5
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 22
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                local.get 22
                                call $u256_to_big_endian_bytes
                                i32.const 0
                                i32.const 0
                                i32.const 66080
                                local.get 3
                                local.get 15
                                local.get 22
                                call $wrapper_log4
                                block  ;; label = @15
                                  local.get 23
                                  br_if 0 (;@15;)
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 3
                                  local.tee 0
                                  global.set $__stack_pointer
                                  i32.const 64
                                  local.get 3
                                  call $wrapper_mload_bytes32
                                  local.get 3
                                  call $i32_from_big_endian_bytes32
                                  local.set 15
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 24
                                  i32.add
                                  i64.const 8342544948196802560
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
                                  local.get 15
                                  local.get 0
                                  call $wrapper_mstore_u256
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 3
                                  local.get 0
                                  call $u256_from_big_endian_bytes
                                  local.get 0
                                  i32.load
                                  i32.const 4
                                  i32.add
                                  i32.const 0
                                  call $wrapper_mstore_u32
                                  local.get 15
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
                                local.get 25
                                i64.store
                                local.get 0
                                local.get 14
                                i64.store offset=16
                                local.get 0
                                local.get 7
                                i64.store offset=8
                                local.get 0
                                local.get 8
                                i64.store
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 2
                                global.set $__stack_pointer
                                local.get 0
                                local.get 3
                                call $u256_to_big_endian_bytes
                                local.get 3
                                call $wrapper_extcode_size
                                i32.eqz
                                br_if 10 (;@4;)
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 2
                                global.set $__stack_pointer
                                i32.const 64
                                local.get 0
                                call $wrapper_mload_bytes32
                                local.get 0
                                call $i32_from_big_endian_bytes32
                                local.set 3
                                local.get 2
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 2
                                i32.const 24
                                i32.add
                                i64.const 1516439848548827136
                                i64.store
                                i64.const 0
                                local.set 17
                                local.get 2
                                i64.const 0
                                i64.store offset=16
                                local.get 2
                                i64.const 0
                                i64.store offset=8
                                local.get 2
                                i64.const 0
                                i64.store
                                local.get 3
                                local.get 2
                                call $wrapper_mstore_u256
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i32.load
                                local.set 22
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 2
                                call $wrapper_caller
                                local.get 22
                                i32.const 4
                                i32.add
                                local.get 2
                                call $wrapper_mstore_bytes32
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i32.load
                                i32.const 36
                                i32.add
                                i32.const 0
                                call $wrapper_mstore_u32
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i32.load
                                local.set 22
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 2
                                i32.const 24
                                i32.add
                                local.get 6
                                i64.store
                                local.get 2
                                local.get 10
                                i64.store offset=16
                                local.get 2
                                local.get 9
                                i64.store offset=8
                                local.get 2
                                local.get 5
                                i64.store
                                local.get 22
                                i32.const 68
                                i32.add
                                local.get 2
                                call $wrapper_mstore_u256
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                i32.const 128
                                local.set 22
                                local.get 2
                                i32.load
                                i32.const 100
                                i32.add
                                i32.const 128
                                call $wrapper_mstore_u32
                                call $wrapper_gas
                                local.set 19
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 4
                                local.get 2
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i32.load
                                local.set 2
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 4
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 0
                                local.get 4
                                call $u256_from_big_endian_bytes
                                local.get 4
                                i64.load
                                local.set 14
                                local.get 2
                                local.get 1
                                i32.const 384
                                i32.add
                                call $wrapper_mload_bytes32
                                local.get 14
                                i64.const 132
                                i64.add
                                local.tee 20
                                i32.wrap_i64
                                local.tee 4
                                local.get 1
                                i32.const 384
                                i32.add
                                call $wrapper_mstore_bytes32
                                local.get 4
                                i32.const 32
                                i32.add
                                local.get 2
                                i32.const 32
                                i32.add
                                local.get 1
                                i32.const 384
                                i32.add
                                call $i32_from_big_endian_bytes32
                                call $wrapper_data_copy
                                local.get 1
                                i32.const 384
                                i32.add
                                local.get 1
                                i32.const 576
                                i32.add
                                call $u256_from_big_endian_bytes
                                local.get 1
                                i64.load offset=576
                                local.get 20
                                i64.add
                                i32.wrap_i64
                                i32.const 32
                                i32.add
                                i32.const 0
                                call $wrapper_mstore_u32
                                local.get 1
                                i32.const 384
                                i32.add
                                local.get 1
                                i32.const 544
                                i32.add
                                call $u256_from_big_endian_bytes
                                local.get 1
                                i64.load offset=544
                                local.set 20
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 0
                                local.get 2
                                call $u256_from_big_endian_bytes
                                local.get 2
                                i64.load
                                local.set 18
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 4
                                global.set $__stack_pointer
                                local.get 2
                                i32.const 24
                                i32.add
                                i64.const 0
                                i64.store
                                local.get 2
                                local.get 16
                                i64.store offset=16
                                local.get 2
                                local.get 7
                                i64.store offset=8
                                local.get 2
                                local.get 8
                                i64.store
                                local.get 4
                                i32.const -32
                                i32.add
                                local.tee 4
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 2
                                local.get 4
                                call $u256_to_big_endian_bytes
                                local.get 15
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 15
                                global.set $__stack_pointer
                                local.get 2
                                i32.const 24
                                i32.add
                                i64.const 0
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
                                local.get 19
                                local.get 4
                                local.get 2
                                local.get 3
                                local.get 14
                                local.get 20
                                i64.const 31
                                i64.add
                                i64.const 4294967264
                                i64.and
                                i64.add
                                local.get 18
                                i64.sub
                                i32.wrap_i64
                                i32.const 164
                                i32.add
                                local.get 3
                                i32.const 32
                                call $wrapper_call_contract
                                local.set 2
                                call $wrapper_returndata_size
                                local.set 4
                                block  ;; label = @15
                                  local.get 2
                                  i32.eqz
                                  br_if 0 (;@15;)
                                  block  ;; label = @16
                                    block  ;; label = @17
                                      local.get 4
                                      i32.const 32
                                      i32.lt_u
                                      br_if 0 (;@17;)
                                      i64.const 32
                                      local.set 18
                                      br 1 (;@16;)
                                    end
                                    call $wrapper_returndata_size
                                    i64.extend_i32_u
                                    local.set 18
                                    i64.const 0
                                    local.set 17
                                  end
                                  local.get 15
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 2
                                  call $u256_from_big_endian_bytes
                                  local.get 2
                                  i64.load
                                  local.get 2
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.get 2
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.get 2
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.get 18
                                  local.get 17
                                  local.get 17
                                  local.get 17
                                  call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 2
                                  call $u256_from_big_endian_bytes
                                  local.get 2
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.set 12
                                  local.get 2
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.set 20
                                  local.get 2
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 19
                                  local.get 2
                                  i64.load
                                  local.set 14
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 4
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 2
                                  call $u256_from_big_endian_bytes
                                  block  ;; label = @16
                                    local.get 14
                                    local.get 18
                                    i64.add
                                    local.tee 18
                                    local.get 2
                                    i64.load
                                    local.tee 13
                                    i64.sub
                                    i64.const 31
                                    i64.gt_u
                                    local.get 19
                                    local.get 17
                                    i64.add
                                    local.get 18
                                    local.get 14
                                    i64.lt_u
                                    local.tee 0
                                    i64.extend_i32_u
                                    i64.add
                                    local.tee 14
                                    local.get 2
                                    i32.const 8
                                    i32.add
                                    i64.load
                                    local.tee 21
                                    i64.sub
                                    local.get 18
                                    local.get 13
                                    i64.lt_u
                                    local.tee 15
                                    i64.extend_i32_u
                                    i64.sub
                                    local.tee 18
                                    i64.const 0
                                    i64.ne
                                    local.get 18
                                    i64.eqz
                                    select
                                    local.get 20
                                    local.get 17
                                    i64.add
                                    local.tee 18
                                    local.get 0
                                    local.get 14
                                    local.get 19
                                    i64.lt_u
                                    local.get 14
                                    local.get 19
                                    i64.eq
                                    select
                                    i64.extend_i32_u
                                    i64.add
                                    local.tee 19
                                    local.get 2
                                    i32.const 16
                                    i32.add
                                    i64.load
                                    local.tee 13
                                    i64.sub
                                    local.tee 25
                                    local.get 15
                                    local.get 14
                                    local.get 21
                                    i64.lt_u
                                    local.get 14
                                    local.get 21
                                    i64.eq
                                    select
                                    i64.extend_i32_u
                                    local.tee 14
                                    i64.sub
                                    local.tee 21
                                    i64.const 0
                                    i64.ne
                                    local.get 12
                                    local.get 17
                                    i64.add
                                    local.get 18
                                    local.get 20
                                    i64.lt_u
                                    i64.extend_i32_u
                                    i64.add
                                    local.get 19
                                    local.get 18
                                    i64.lt_u
                                    i64.extend_i32_u
                                    i64.add
                                    local.get 2
                                    i32.const 24
                                    i32.add
                                    i64.load
                                    i64.sub
                                    local.get 19
                                    local.get 13
                                    i64.lt_u
                                    i64.extend_i32_u
                                    i64.sub
                                    local.get 25
                                    local.get 14
                                    i64.lt_u
                                    i64.extend_i32_u
                                    i64.sub
                                    local.tee 17
                                    i64.const 0
                                    i64.gt_s
                                    local.get 17
                                    i64.eqz
                                    select
                                    local.get 21
                                    local.get 17
                                    i64.or
                                    i64.eqz
                                    select
                                    br_if 0 (;@16;)
                                    i32.const 0
                                    i32.const 0
                                    call $wrapper_revert
                                  end
                                  local.get 4
                                  i32.const -32
                                  i32.add
                                  local.tee 4
                                  local.tee 0
                                  global.set $__stack_pointer
                                  local.get 3
                                  local.get 4
                                  call $wrapper_mload_bytes32
                                  local.get 0
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
                                  global.set $__stack_pointer
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 3
                                  global.set $__stack_pointer
                                  local.get 2
                                  i32.const 24
                                  i32.add
                                  i32.const 66112
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  i64.store align=1
                                  local.get 2
                                  i32.const 16
                                  i32.add
                                  i32.const 66112
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  i64.store align=1
                                  local.get 2
                                  i32.const 8
                                  i32.add
                                  i32.const 66112
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  i64.store align=1
                                  local.get 2
                                  i32.const 0
                                  i64.load offset=66112
                                  i64.store align=1
                                  local.get 2
                                  local.get 0
                                  call $u256_from_big_endian_bytes
                                  local.get 0
                                  i64.load
                                  local.set 17
                                  local.get 0
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 14
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
                                  local.get 3
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
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
                                  local.get 14
                                  i64.store offset=8
                                  local.get 0
                                  local.get 17
                                  i64.store
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 3
                                  global.set $__stack_pointer
                                  local.get 0
                                  i32.const 224
                                  local.get 2
                                  call $wrapper_u256_shl
                                  local.get 2
                                  i64.load
                                  local.set 17
                                  local.get 2
                                  i32.const 8
                                  i32.add
                                  i64.load
                                  local.set 14
                                  local.get 2
                                  i32.const 16
                                  i32.add
                                  i64.load
                                  local.set 19
                                  local.get 2
                                  i32.const 24
                                  i32.add
                                  i64.load
                                  local.set 20
                                  local.get 3
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 2
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
                                  local.get 14
                                  i64.store offset=8
                                  local.get 0
                                  local.get 17
                                  i64.store
                                  local.get 2
                                  i32.const -32
                                  i32.add
                                  local.tee 2
                                  local.tee 3
                                  global.set $__stack_pointer
                                  local.get 0
                                  local.get 2
                                  call $u256_to_big_endian_bytes
                                  local.get 3
                                  i32.const -32
                                  i32.add
                                  local.tee 0
                                  local.tee 3
                                  global.set $__stack_pointer
                                  local.get 4
                                  local.get 2
                                  local.get 0
                                  call $wrapper_bytes32_and
                                  local.get 4
                                  local.get 0
                                  call $wrapper_bytes32_eq
                                  br_if 10 (;@5;)
                                  i32.const 0
                                  i32.const 0
                                  call $wrapper_revert
                                  br 10 (;@5;)
                                end
                                local.get 4
                                br_if 7 (;@7;)
                                i32.const 96
                                local.set 4
                                br 8 (;@6;)
                              end
                              block  ;; label = @14
                                call $wrapper_callvalue_not_zero
                                i32.eqz
                                br_if 0 (;@14;)
                                i32.const 0
                                i32.const 0
                                call $wrapper_revert
                              end
                              block  ;; label = @14
                                call $wrapper_calldata_size_minus_4
                                i32.const 31
                                i32.gt_u
                                br_if 0 (;@14;)
                                i32.const 0
                                i32.const 0
                                call $wrapper_revert
                              end
                              i32.const 4
                              local.get 1
                              i32.const 384
                              i32.add
                              call $wrapper_calldataload_bytes32
                              local.get 1
                              i32.const 384
                              i32.add
                              local.get 1
                              i32.const 576
                              i32.add
                              call $u256_from_big_endian_bytes
                              block  ;; label = @14
                                local.get 1
                                i64.load offset=576
                                local.tee 5
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 16
                                i32.add
                                i64.load32_u
                                local.tee 10
                                i64.or
                                local.get 1
                                i32.const 576
                                i32.add
                                i32.const 8
                                i32.add
                                i64.load
                                local.tee 9
                                i64.or
                                i64.const 0
                                i64.ne
                                br_if 0 (;@14;)
                                local.get 0
                                i32.const -32
                                i32.add
                                local.tee 2
                                local.tee 0
                                global.set $__stack_pointer
                                i32.const 64
                                local.get 2
                                call $wrapper_mload_bytes32
                                local.get 2
                                call $i32_from_big_endian_bytes32
                                local.set 4
                                local.get 0
                                i32.const -32
                                i32.add
                                local.tee 0
                                local.tee 3
                                global.set $__stack_pointer
                                local.get 0
                                i32.const 24
                                i32.add
                                i64.const -8519073936627990528
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
                                local.get 4
                                local.get 0
                                call $wrapper_mstore_u256
                                local.get 3
                                i32.const -32
                                i32.add
                                local.tee 3
                                local.tee 0
                                global.set $__stack_pointer
                                local.get 2
                                local.get 3
                                call $u256_from_big_endian_bytes
                                local.get 3
                                i32.load
                                i32.const 4
                                i32.add
                                i32.const 0
                                call $wrapper_mstore_u32
                                local.get 4
                                i32.const 36
                                call $wrapper_revert
                              end
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
                              local.get 10
                              i64.store offset=16
                              local.get 0
                              local.get 9
                              i64.store offset=8
                              local.get 0
                              local.get 5
                              i64.store
                              i32.const 0
                              local.get 0
                              call $wrapper_mstore_u256
                              i32.const 32
                              i32.const 3
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
                              local.tee 4
                              global.set $__stack_pointer
                              local.get 2
                              local.get 0
                              call $wrapper_sload_u256_using_little_endian_hostapi
                              local.get 0
                              i64.load
                              local.set 5
                              local.get 0
                              i32.const 8
                              i32.add
                              i64.load
                              local.set 10
                              local.get 0
                              i32.const 16
                              i32.add
                              i64.load
                              local.set 9
                              local.get 0
                              i32.const 24
                              i32.add
                              i64.load
                              local.set 6
                              local.get 4
                              i32.const -32
                              i32.add
                              local.tee 0
                              local.tee 4
                              global.set $__stack_pointer
                              i32.const 64
                              local.get 0
                              call $wrapper_mload_bytes32
                              local.get 0
                              call $i32_from_big_endian_bytes32
                              local.set 2
                              local.get 4
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
                              local.get 9
                              i64.store offset=16
                              local.get 0
                              local.get 10
                              i64.store offset=8
                              local.get 0
                              local.get 5
                              i64.store
                              local.get 2
                              local.get 0
                              call $wrapper_mstore_u256
                              local.get 2
                              i32.const 32
                              call $wrapper_return
                              br 12 (;@1;)
                            end
                            block  ;; label = @13
                              call $wrapper_callvalue_not_zero
                              i32.eqz
                              br_if 0 (;@13;)
                              i32.const 0
                              i32.const 0
                              call $wrapper_revert
                            end
                            call $wrapper_calldata_size_minus_4
                            drop
                            call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOwner
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
                            i64.const 6
                            i64.store
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 0
                            local.get 2
                            call $u256_to_big_endian_bytes
                            local.get 4
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 2
                            local.get 0
                            call $wrapper_sload_u256_using_little_endian_hostapi
                            local.get 0
                            i64.load
                            local.set 5
                            local.get 0
                            i32.const 8
                            i32.add
                            i64.load
                            local.set 10
                            local.get 0
                            i32.const 16
                            i32.add
                            i64.load
                            local.set 9
                            local.get 0
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 6
                            local.get 4
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 2
                            global.set $__stack_pointer
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 2
                            i32.const 24
                            i32.add
                            i32.const 66176
                            i32.const 24
                            i32.add
                            i64.load
                            i64.store align=1
                            local.get 2
                            i32.const 16
                            i32.add
                            i32.const 66176
                            i32.const 16
                            i32.add
                            i64.load
                            i64.store align=1
                            local.get 2
                            i32.const 8
                            i32.add
                            i32.const 66176
                            i32.const 8
                            i32.add
                            i64.load
                            i64.store align=1
                            local.get 2
                            i32.const 0
                            i64.load offset=66176
                            i64.store align=1
                            local.get 2
                            local.get 0
                            call $u256_from_big_endian_bytes
                            local.get 0
                            i64.load
                            local.set 7
                            local.get 0
                            i32.const 8
                            i32.add
                            i64.load
                            local.set 8
                            local.get 0
                            i32.const 16
                            i32.add
                            i64.load
                            local.set 16
                            local.get 0
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 17
                            local.get 4
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
                            local.get 16
                            i64.store offset=16
                            local.get 0
                            local.get 8
                            i64.store offset=8
                            local.get 0
                            local.get 7
                            i64.store
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 0
                            i32.const 160
                            local.get 2
                            call $wrapper_u256_shl
                            local.get 2
                            i64.load
                            local.set 7
                            local.get 2
                            i32.const 8
                            i32.add
                            i64.load
                            local.set 8
                            local.get 2
                            i32.const 16
                            i32.add
                            i64.load
                            local.set 16
                            local.get 2
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 17
                            local.get 4
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
                            i64.const 6
                            i64.store
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 0
                            local.get 2
                            call $u256_to_big_endian_bytes
                            local.get 4
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 0
                            i32.const 24
                            i32.add
                            local.get 17
                            local.get 6
                            i64.and
                            i64.store
                            local.get 0
                            local.get 16
                            local.get 9
                            i64.and
                            i64.store offset=16
                            local.get 0
                            local.get 8
                            local.get 10
                            i64.and
                            i64.store offset=8
                            local.get 0
                            local.get 7
                            local.get 5
                            i64.and
                            i64.store
                            local.get 2
                            local.get 0
                            call $wrapper_sstore_u256_using_little_endian_hostapi
                            local.get 4
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
                            local.get 9
                            i64.store offset=16
                            local.get 0
                            local.get 10
                            i64.store offset=8
                            local.get 0
                            local.get 5
                            i64.store
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 0
                            local.get 2
                            call $u256_to_big_endian_bytes
                            local.get 4
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 4
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
                            local.get 4
                            i32.const -32
                            i32.add
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 0
                            local.get 4
                            call $u256_to_big_endian_bytes
                            i32.const 0
                            i32.const 0
                            i32.const 66208
                            local.get 2
                            local.get 4
                            call $wrapper_log3
                            i32.const 0
                            i32.const 0
                            call $wrapper_return
                            br 11 (;@1;)
                          end
                          block  ;; label = @12
                            call $wrapper_callvalue_not_zero
                            i32.eqz
                            br_if 0 (;@12;)
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
                          i64.const 6
                          i64.store
                          local.get 2
                          i32.const -32
                          i32.add
                          local.tee 2
                          local.tee 4
                          global.set $__stack_pointer
                          local.get 0
                          local.get 2
                          call $u256_to_big_endian_bytes
                          local.get 4
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 4
                          global.set $__stack_pointer
                          local.get 2
                          local.get 0
                          call $wrapper_sload_u256_using_little_endian_hostapi
                          local.get 0
                          i64.load
                          local.set 5
                          local.get 0
                          i32.const 8
                          i32.add
                          i64.load
                          local.set 10
                          local.get 0
                          i32.const 16
                          i32.add
                          i64.load32_u
                          local.set 9
                          local.get 4
                          i32.const -32
                          i32.add
                          local.tee 0
                          local.tee 4
                          global.set $__stack_pointer
                          i32.const 64
                          local.get 0
                          call $wrapper_mload_bytes32
                          local.get 0
                          call $i32_from_big_endian_bytes32
                          local.set 2
                          local.get 4
                          i32.const -32
                          i32.add
                          local.tee 0
                          global.set $__stack_pointer
                          local.get 0
                          i32.const 24
                          i32.add
                          i64.const 0
                          i64.store
                          local.get 0
                          local.get 9
                          i64.store offset=16
                          local.get 0
                          local.get 10
                          i64.store offset=8
                          local.get 0
                          local.get 5
                          i64.store
                          local.get 2
                          local.get 0
                          call $wrapper_mstore_u256
                          local.get 2
                          i32.const 32
                          call $wrapper_return
                          br 10 (;@1;)
                        end
                        i32.const 0
                        i32.const 1
                        call $wrapper_mstore_u32
                        block  ;; label = @11
                          block  ;; label = @12
                            local.get 11
                            local.get 13
                            i64.or
                            local.get 12
                            local.get 14
                            i64.or
                            i64.or
                            i64.eqz
                            i32.eqz
                            br_if 0 (;@12;)
                            i64.const 0
                            local.set 6
                            i64.const 0
                            local.set 7
                            i64.const 0
                            local.set 8
                            i64.const 0
                            local.set 9
                            br 1 (;@11;)
                          end
                          i64.const -5688559447130896581
                          local.set 19
                          i64.const 2805406106312927794
                          local.set 16
                          i64.const 933453808179261555
                          local.set 17
                          i64.const 3287570427613416694
                          local.set 5
                          i64.const 0
                          local.set 10
                          i64.const 0
                          local.set 20
                          i64.const 0
                          local.set 18
                          i64.const 0
                          local.set 9
                          loop  ;; label = @12
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 2
                            global.set $__stack_pointer
                            local.get 3
                            local.get 0
                            call $u256_from_big_endian_bytes
                            local.get 0
                            i64.load
                            local.set 6
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 2
                            global.set $__stack_pointer
                            local.get 0
                            i32.const 24
                            i32.add
                            local.get 19
                            i64.store
                            local.get 0
                            local.get 16
                            i64.store offset=16
                            local.get 0
                            local.get 17
                            i64.store offset=8
                            local.get 0
                            local.get 5
                            i64.store
                            local.get 2
                            i32.const -32
                            i32.add
                            local.tee 2
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 0
                            local.get 2
                            call $u256_to_big_endian_bytes
                            local.get 4
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 4
                            global.set $__stack_pointer
                            local.get 2
                            local.get 0
                            call $wrapper_sload_u256_using_little_endian_hostapi
                            local.get 0
                            i64.load
                            local.set 7
                            local.get 0
                            i32.const 8
                            i32.add
                            i64.load
                            local.set 8
                            local.get 0
                            i32.const 16
                            i32.add
                            i64.load
                            local.set 21
                            local.get 0
                            i32.const 24
                            i32.add
                            i64.load
                            local.set 25
                            local.get 4
                            i32.const -32
                            i32.add
                            local.tee 0
                            local.tee 2
                            global.set $__stack_pointer
                            local.get 0
                            i32.const 24
                            i32.add
                            local.get 25
                            i64.store
                            local.get 0
                            local.get 21
                            i64.store offset=16
                            local.get 0
                            local.get 8
                            i64.store offset=8
                            local.get 0
                            local.get 7
                            i64.store
                            local.get 6
                            local.get 10
                            i64.add
                            i32.wrap_i64
                            i32.const 32
                            i32.add
                            local.get 0
                            call $wrapper_mstore_u256
                            local.get 18
                            local.get 10
                            i64.const 32
                            i64.add
                            local.tee 6
                            local.get 10
                            i64.lt_u
                            local.tee 0
                            local.get 20
                            local.get 0
                            i64.extend_i32_u
                            i64.add
                            local.tee 7
                            local.get 20
                            i64.lt_u
                            local.get 6
                            local.get 10
                            i64.ge_u
                            select
                            i64.extend_i32_u
                            i64.add
                            local.tee 8
                            local.get 18
                            i64.lt_u
                            local.set 0
                            local.get 19
                            local.get 16
                            local.get 5
                            i64.const 1
                            i64.add
                            local.tee 21
                            local.get 5
                            i64.lt_u
                            local.tee 4
                            local.get 17
                            local.get 4
                            i64.extend_i32_u
                            i64.add
                            local.tee 25
                            local.get 17
                            i64.lt_u
                            local.get 21
                            local.get 5
                            i64.ge_u
                            select
                            i64.extend_i32_u
                            i64.add
                            local.tee 26
                            local.get 16
                            i64.lt_u
                            i64.extend_i32_u
                            i64.add
                            local.set 19
                            local.get 6
                            local.set 10
                            local.get 7
                            local.set 20
                            local.get 8
                            local.set 18
                            local.get 21
                            local.set 5
                            local.get 25
                            local.set 17
                            local.get 26
                            local.set 16
                            local.get 6
                            local.get 11
                            i64.lt_u
                            local.get 7
                            local.get 12
                            i64.lt_u
                            local.get 7
                            local.get 12
                            i64.eq
                            select
                            local.get 8
                            local.get 13
                            i64.lt_u
                            local.get 9
                            local.get 0
                            i64.extend_i32_u
                            i64.add
                            local.tee 9
                            local.get 14
                            i64.lt_u
                            local.get 9
                            local.get 14
                            i64.eq
                            select
                            local.get 8
                            local.get 13
                            i64.xor
                            local.get 9
                            local.get 14
                            i64.xor
                            i64.or
                            i64.eqz
                            select
                            br_if 0 (;@12;)
                          end
                        end
                        local.get 2
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 2
                        global.set $__stack_pointer
                        local.get 3
                        local.get 0
                        call $u256_from_big_endian_bytes
                        local.get 0
                        i32.const 24
                        i32.add
                        i64.load
                        local.get 9
                        i64.add
                        local.get 0
                        i32.const 16
                        i32.add
                        i64.load
                        local.tee 5
                        local.get 8
                        i64.add
                        local.tee 10
                        local.get 5
                        i64.lt_u
                        i64.extend_i32_u
                        i64.add
                        local.get 10
                        local.get 0
                        i64.load
                        local.tee 5
                        local.get 6
                        i64.add
                        local.tee 8
                        local.get 5
                        i64.lt_u
                        local.tee 4
                        local.get 0
                        i32.const 8
                        i32.add
                        i64.load
                        local.tee 9
                        local.get 7
                        i64.add
                        local.get 4
                        i64.extend_i32_u
                        i64.add
                        local.tee 5
                        local.get 9
                        i64.lt_u
                        local.get 5
                        local.get 9
                        i64.eq
                        select
                        i64.extend_i32_u
                        i64.add
                        local.tee 7
                        local.get 10
                        i64.lt_u
                        i64.extend_i32_u
                        i64.add
                        local.set 12
                        br 8 (;@2;)
                      end
                      block  ;; label = @10
                        call $wrapper_callvalue_not_zero
                        i32.eqz
                        br_if 0 (;@10;)
                        i32.const 0
                        i32.const 0
                        call $wrapper_revert
                      end
                      block  ;; label = @10
                        call $wrapper_calldata_size_minus_4
                        i32.const 63
                        i32.gt_u
                        br_if 0 (;@10;)
                        i32.const 0
                        i32.const 0
                        call $wrapper_revert
                      end
                      i32.const 4
                      local.get 1
                      i32.const 384
                      i32.add
                      call $wrapper_calldataload_bytes32
                      local.get 1
                      i32.const 384
                      i32.add
                      local.get 1
                      i32.const 576
                      i32.add
                      call $u256_from_big_endian_bytes
                      local.get 1
                      i32.const 600
                      i32.add
                      i64.load
                      local.set 5
                      local.get 1
                      i32.const 592
                      i32.add
                      i64.load
                      local.set 10
                      local.get 1
                      i32.const 584
                      i32.add
                      i64.load
                      local.set 9
                      local.get 1
                      i64.load offset=576
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
                      local.get 0
                      call $wrapper_bytes32_iszero
                      local.set 4
                      local.get 2
                      i32.const -32
                      i32.add
                      local.tee 2
                      local.tee 3
                      global.set $__stack_pointer
                      local.get 4
                      i32.eqz
                      local.tee 4
                      local.get 2
                      call $i32_to_bytes32_big_endian_bytes
                      block  ;; label = @10
                        local.get 0
                        local.get 2
                        call $wrapper_bytes32_eq
                        br_if 0 (;@10;)
                        i32.const 0
                        i32.const 0
                        call $wrapper_revert
                      end
                      block  ;; label = @10
                        local.get 6
                        local.get 10
                        i64.or
                        local.get 9
                        local.get 5
                        i64.or
                        i64.or
                        i64.const 0
                        i64.ne
                        br_if 0 (;@10;)
                        local.get 3
                        i32.const -32
                        i32.add
                        local.tee 2
                        local.tee 0
                        global.set $__stack_pointer
                        i32.const 64
                        local.get 2
                        call $wrapper_mload_bytes32
                        local.get 2
                        call $i32_from_big_endian_bytes32
                        local.set 15
                        local.get 0
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 3
                        global.set $__stack_pointer
                        local.get 0
                        i32.const 24
                        i32.add
                        i64.const 6559697469507108864
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
                        local.get 15
                        local.get 0
                        call $wrapper_mstore_u256
                        local.get 3
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 3
                        global.set $__stack_pointer
                        local.get 2
                        local.get 0
                        call $u256_from_big_endian_bytes
                        local.get 0
                        i32.load
                        local.set 2
                        local.get 3
                        i32.const -32
                        i32.add
                        local.tee 0
                        local.tee 3
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
                        i32.const 4
                        i32.add
                        local.get 0
                        call $wrapper_mstore_u256
                        local.get 15
                        i32.const 36
                        call $wrapper_revert
                      end
                      local.get 3
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
                      i32.const 5
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
                      local.tee 3
                      global.set $__stack_pointer
                      local.get 0
                      i32.const 24
                      i32.add
                      local.get 5
                      i64.store
                      local.get 0
                      local.get 10
                      i64.store offset=16
                      local.get 0
                      local.get 9
                      i64.store offset=8
                      local.get 0
                      local.get 6
                      i64.store
                      i32.const 0
                      local.get 0
                      call $wrapper_mstore_u256
                      i32.const 32
                      local.get 2
                      call $wrapper_mstore_bytes32
                      local.get 3
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
                      local.tee 3
                      global.set $__stack_pointer
                      local.get 2
                      local.get 0
                      call $wrapper_sload_u256_using_little_endian_hostapi
                      local.get 0
                      i64.load
                      local.set 7
                      local.get 0
                      i32.const 8
                      i32.add
                      i64.load
                      local.set 8
                      local.get 0
                      i32.const 16
                      i32.add
                      i64.load
                      local.set 16
                      local.get 0
                      i32.const 24
                      i32.add
                      i64.load
                      local.set 17
                      local.get 3
                      i32.const -32
                      i32.add
                      local.tee 0
                      local.tee 3
                      global.set $__stack_pointer
                      local.get 0
                      i32.const 24
                      i32.add
                      local.get 17
                      i64.store
                      local.get 0
                      local.get 16
                      i64.store offset=16
                      local.get 0
                      local.get 8
                      i64.store offset=8
                      local.get 0
                      local.get 7
                      i64.const -256
                      i64.and
                      local.get 4
                      i64.extend_i32_u
                      i64.or
                      i64.store
                      local.get 2
                      local.get 0
                      call $wrapper_sstore_u256_using_little_endian_hostapi
                      local.get 3
                      i32.const -32
                      i32.add
                      local.tee 0
                      local.tee 2
                      global.set $__stack_pointer
                      i32.const 64
                      local.get 0
                      call $wrapper_mload_bytes32
                      local.get 0
                      call $i32_from_big_endian_bytes32
                      local.tee 3
                      local.get 4
                      call $wrapper_mstore_u32
                      local.get 2
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
                      local.tee 4
                      global.set $__stack_pointer
                      local.get 0
                      i32.const 24
                      i32.add
                      local.get 5
                      i64.store
                      local.get 0
                      local.get 10
                      i64.store offset=16
                      local.get 0
                      local.get 9
                      i64.store offset=8
                      local.get 0
                      local.get 6
                      i64.store
                      local.get 4
                      i32.const -32
                      i32.add
                      local.tee 4
                      global.set $__stack_pointer
                      local.get 0
                      local.get 4
                      call $u256_to_big_endian_bytes
                      local.get 3
                      i32.const 32
                      i32.const 66240
                      local.get 2
                      local.get 4
                      call $wrapper_log3
                      i32.const 0
                      i32.const 0
                      call $wrapper_return
                      br 8 (;@1;)
                    end
                    block  ;; label = @9
                      call $wrapper_callvalue_not_zero
                      i32.eqz
                      br_if 0 (;@9;)
                      i32.const 0
                      i32.const 0
                      call $wrapper_revert
                    end
                    block  ;; label = @9
                      call $wrapper_calldata_size_minus_4
                      i32.const 31
                      i32.gt_u
                      br_if 0 (;@9;)
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
                    local.tee 4
                    global.set $__stack_pointer
                    local.get 2
                    local.get 0
                    call $u256_from_big_endian_bytes
                    local.get 1
                    i32.const 352
                    i32.add
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
                    call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_requireOwned
                    local.get 4
                    i32.const -32
                    i32.add
                    local.tee 2
                    local.tee 0
                    global.set $__stack_pointer
                    i32.const 64
                    local.get 2
                    call $wrapper_mload_bytes32
                    local.get 0
                    i32.const -32
                    i32.add
                    local.tee 0
                    local.tee 4
                    global.set $__stack_pointer
                    local.get 2
                    local.get 0
                    call $u256_from_big_endian_bytes
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
                    call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation_17595
                    local.get 2
                    call $i32_from_big_endian_bytes32
                    i32.const 0
                    call $wrapper_mstore_u32
                    local.get 4
                    i32.const -32
                    i32.add
                    local.tee 2
                    local.tee 0
                    global.set $__stack_pointer
                    i32.const 64
                    local.get 2
                    call $wrapper_mload_bytes32
                    local.get 0
                    i32.const -32
                    i32.add
                    local.tee 0
                    local.tee 4
                    global.set $__stack_pointer
                    local.get 2
                    local.get 0
                    call $u256_from_big_endian_bytes
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
                    call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation_17595
                    local.get 2
                    call $i32_from_big_endian_bytes32
                    i32.const 0
                    call $wrapper_mstore_u32
                    local.get 4
                    i32.const -32
                    i32.add
                    local.tee 0
                    local.tee 4
                    global.set $__stack_pointer
                    i32.const 64
                    local.get 0
                    call $wrapper_mload_bytes32
                    local.get 0
                    call $i32_from_big_endian_bytes32
                    local.tee 3
                    i32.const 32
                    call $wrapper_mstore_u32
                    local.get 4
                    i32.const -32
                    i32.add
                    local.tee 4
                    local.tee 15
                    global.set $__stack_pointer
                    local.get 2
                    local.get 4
                    call $u256_from_big_endian_bytes
                    local.get 4
                    i32.load
                    local.set 2
                    local.get 15
                    i32.const -32
                    i32.add
                    local.tee 4
                    local.tee 15
                    global.set $__stack_pointer
                    local.get 0
                    local.get 4
                    call $u256_from_big_endian_bytes
                    local.get 4
                    i64.load
                    local.set 5
                    local.get 2
                    local.get 1
                    i32.const 384
                    i32.add
                    call $wrapper_mload_bytes32
                    local.get 5
                    i64.const 32
                    i64.add
                    local.tee 10
                    i32.wrap_i64
                    local.tee 4
                    local.get 1
                    i32.const 384
                    i32.add
                    call $wrapper_mstore_bytes32
                    local.get 4
                    i32.const 32
                    i32.add
                    local.get 2
                    i32.const 32
                    i32.add
                    local.get 1
                    i32.const 384
                    i32.add
                    call $i32_from_big_endian_bytes32
                    call $wrapper_data_copy
                    local.get 1
                    i32.const 384
                    i32.add
                    local.get 1
                    i32.const 576
                    i32.add
                    call $u256_from_big_endian_bytes
                    local.get 1
                    i64.load offset=576
                    local.get 10
                    i64.add
                    i32.wrap_i64
                    i32.const 32
                    i32.add
                    i32.const 0
                    call $wrapper_mstore_u32
                    local.get 1
                    i32.const 384
                    i32.add
                    local.get 1
                    i32.const 544
                    i32.add
                    call $u256_from_big_endian_bytes
                    local.get 1
                    i64.load offset=544
                    local.set 10
                    local.get 15
                    i32.const -32
                    i32.add
                    local.tee 2
                    global.set $__stack_pointer
                    local.get 0
                    local.get 2
                    call $u256_from_big_endian_bytes
                    local.get 3
                    local.get 5
                    local.get 10
                    i64.const 31
                    i64.add
                    i64.const 4294967264
                    i64.and
                    i64.add
                    local.get 2
                    i64.load
                    i64.sub
                    i32.wrap_i64
                    i32.const 64
                    i32.add
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
                  block  ;; label = @8
                    call $wrapper_calldata_size_minus_4
                    i32.const 31
                    i32.gt_u
                    br_if 0 (;@8;)
                    i32.const 0
                    i32.const 0
                    call $wrapper_revert
                  end
                  i32.const 4
                  local.get 1
                  i32.const 384
                  i32.add
                  call $wrapper_calldataload_bytes32
                  local.get 1
                  i32.const 384
                  i32.add
                  local.get 1
                  i32.const 576
                  i32.add
                  call $u256_from_big_endian_bytes
                  local.get 1
                  i32.const 576
                  i32.add
                  i32.const 16
                  i32.add
                  i64.load32_u
                  local.set 5
                  local.get 1
                  i64.load offset=576
                  local.set 10
                  local.get 1
                  i32.const 576
                  i32.add
                  i32.const 8
                  i32.add
                  i64.load
                  local.set 9
                  call $MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOwner
                  block  ;; label = @8
                    local.get 9
                    local.get 10
                    local.get 5
                    i64.or
                    i64.or
                    i64.const 0
                    i64.ne
                    br_if 0 (;@8;)
                    local.get 0
                    i32.const -32
                    i32.add
                    local.tee 2
                    local.tee 0
                    global.set $__stack_pointer
                    i32.const 64
                    local.get 2
                    call $wrapper_mload_bytes32
                    local.get 2
                    call $i32_from_big_endian_bytes32
                    local.set 4
                    local.get 0
                    i32.const -32
                    i32.add
                    local.tee 0
                    local.tee 3
                    global.set $__stack_pointer
                    local.get 0
                    i32.const 24
                    i32.add
                    i64.const 2184173212852551680
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
                    local.get 4
                    local.get 0
                    call $wrapper_mstore_u256
                    local.get 3
                    i32.const -32
                    i32.add
                    local.tee 3
                    local.tee 0
                    global.set $__stack_pointer
                    local.get 2
                    local.get 3
                    call $u256_from_big_endian_bytes
                    local.get 3
                    i32.load
                    i32.const 4
                    i32.add
                    i32.const 0
                    call $wrapper_mstore_u32
                    local.get 4
                    i32.const 36
                    call $wrapper_revert
                  end
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
                  i64.const 6
                  i64.store
                  local.get 2
                  i32.const -32
                  i32.add
                  local.tee 2
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 0
                  local.get 2
                  call $u256_to_big_endian_bytes
                  local.get 4
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 2
                  local.get 0
                  call $wrapper_sload_u256_using_little_endian_hostapi
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
                  local.set 8
                  local.get 0
                  i32.const 24
                  i32.add
                  i64.load
                  local.set 16
                  local.get 4
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 2
                  global.set $__stack_pointer
                  local.get 2
                  i32.const -32
                  i32.add
                  local.tee 2
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 2
                  i32.const 24
                  i32.add
                  i32.const 66304
                  i32.const 24
                  i32.add
                  i64.load
                  i64.store align=1
                  local.get 2
                  i32.const 16
                  i32.add
                  i32.const 66304
                  i32.const 16
                  i32.add
                  i64.load
                  i64.store align=1
                  local.get 2
                  i32.const 8
                  i32.add
                  i32.const 66304
                  i32.const 8
                  i32.add
                  i64.load
                  i64.store align=1
                  local.get 2
                  i32.const 0
                  i64.load offset=66304
                  i64.store align=1
                  local.get 2
                  local.get 0
                  call $u256_from_big_endian_bytes
                  local.get 0
                  i64.load
                  local.set 17
                  local.get 0
                  i32.const 8
                  i32.add
                  i64.load
                  local.set 14
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
                  local.get 4
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 2
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
                  local.get 14
                  i64.store offset=8
                  local.get 0
                  local.get 17
                  i64.store
                  local.get 2
                  i32.const -32
                  i32.add
                  local.tee 2
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 0
                  i32.const 160
                  local.get 2
                  call $wrapper_u256_shl
                  local.get 2
                  i64.load
                  local.set 17
                  local.get 2
                  i32.const 8
                  i32.add
                  i64.load
                  local.set 14
                  local.get 2
                  i32.const 16
                  i32.add
                  i64.load
                  local.set 19
                  local.get 2
                  i32.const 24
                  i32.add
                  i64.load
                  local.set 20
                  local.get 4
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
                  i64.const 6
                  i64.store
                  local.get 2
                  i32.const -32
                  i32.add
                  local.tee 2
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 0
                  local.get 2
                  call $u256_to_big_endian_bytes
                  local.get 4
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 0
                  i32.const 24
                  i32.add
                  local.get 20
                  local.get 16
                  i64.and
                  i64.store
                  local.get 0
                  local.get 19
                  local.get 8
                  i64.and
                  local.get 5
                  i64.or
                  i64.store offset=16
                  local.get 0
                  local.get 14
                  local.get 7
                  i64.and
                  local.get 9
                  i64.or
                  i64.store offset=8
                  local.get 0
                  local.get 17
                  local.get 6
                  i64.and
                  local.get 10
                  i64.or
                  i64.store
                  local.get 2
                  local.get 0
                  call $wrapper_sstore_u256_using_little_endian_hostapi
                  local.get 4
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
                  local.get 8
                  i64.const 4294967295
                  i64.and
                  i64.store offset=16
                  local.get 0
                  local.get 7
                  i64.store offset=8
                  local.get 0
                  local.get 6
                  i64.store
                  local.get 2
                  i32.const -32
                  i32.add
                  local.tee 2
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 0
                  local.get 2
                  call $u256_to_big_endian_bytes
                  local.get 4
                  i32.const -32
                  i32.add
                  local.tee 0
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 0
                  i32.const 24
                  i32.add
                  i64.const 0
                  i64.store
                  local.get 0
                  local.get 5
                  i64.store offset=16
                  local.get 0
                  local.get 9
                  i64.store offset=8
                  local.get 0
                  local.get 10
                  i64.store
                  local.get 4
                  i32.const -32
                  i32.add
                  local.tee 4
                  global.set $__stack_pointer
                  local.get 0
                  local.get 4
                  call $u256_to_big_endian_bytes
                  i32.const 0
                  i32.const 0
                  i32.const 66336
                  local.get 2
                  local.get 4
                  call $wrapper_log3
                  i32.const 0
                  i32.const 0
                  call $wrapper_return
                  br 6 (;@1;)
                end
                local.get 1
                i32.const 288
                i32.add
                call $wrapper_returndata_size
                local.tee 4
                i64.extend_i32_u
                i64.const 0
                i64.const 0
                i64.const 0
                call $MyERC721_48598_deployed.MyERC721_48598_deployed.array_allocation_size_bytes
                local.get 1
                i32.const 288
                i32.add
                i32.const 24
                i32.add
                i64.load
                local.set 17
                local.get 1
                i32.const 288
                i32.add
                i32.const 16
                i32.add
                i64.load
                local.set 14
                local.get 1
                i32.const 288
                i32.add
                i32.const 8
                i32.add
                i64.load
                local.set 19
                local.get 1
                i64.load offset=288
                local.set 20
                local.get 15
                i32.const -32
                i32.add
                local.tee 0
                local.tee 2
                global.set $__stack_pointer
                i32.const 64
                local.get 0
                call $wrapper_mload_bytes32
                local.get 2
                i32.const -32
                i32.add
                local.tee 2
                local.tee 3
                global.set $__stack_pointer
                local.get 0
                local.get 2
                call $u256_from_big_endian_bytes
                local.get 2
                i64.load
                local.get 2
                i32.const 8
                i32.add
                i64.load
                local.get 2
                i32.const 16
                i32.add
                i64.load
                local.get 2
                i32.const 24
                i32.add
                i64.load
                local.get 20
                local.get 19
                local.get 14
                local.get 17
                call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation
                local.get 0
                call $i32_from_big_endian_bytes32
                local.get 4
                call $wrapper_mstore_u32
                local.get 3
                i32.const -32
                i32.add
                local.tee 2
                local.tee 3
                global.set $__stack_pointer
                local.get 0
                local.get 2
                call $u256_from_big_endian_bytes
                local.get 2
                i32.load
                local.set 4
                local.get 3
                i32.const -32
                i32.add
                local.tee 2
                local.tee 15
                global.set $__stack_pointer
                local.get 0
                local.get 2
                call $u256_from_big_endian_bytes
                local.get 2
                i32.load
                i32.const 32
                i32.add
                i32.const 0
                call $wrapper_returndata_size
                call $wrapper_returndata_copy
                local.get 4
                i32.const 32
                i32.add
                local.set 22
              end
              local.get 15
              i32.const -32
              i32.add
              local.tee 0
              local.tee 2
              global.set $__stack_pointer
              local.get 4
              local.get 0
              call $wrapper_mload_bytes32
              block  ;; label = @6
                local.get 0
                call $wrapper_bytes32_iszero
                br_if 0 (;@6;)
                local.get 22
                local.get 0
                call $i32_from_big_endian_bytes32
                call $wrapper_revert
                br 2 (;@4;)
              end
              local.get 2
              i32.const -32
              i32.add
              local.tee 2
              local.tee 0
              global.set $__stack_pointer
              i32.const 64
              local.get 2
              call $wrapper_mload_bytes32
              local.get 2
              call $i32_from_big_endian_bytes32
              local.set 4
              local.get 0
              i32.const -32
              i32.add
              local.tee 0
              local.tee 3
              global.set $__stack_pointer
              local.get 0
              i32.const 24
              i32.add
              i64.const 7250987342154956800
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
              local.get 4
              local.get 0
              call $wrapper_mstore_u256
              local.get 3
              i32.const -32
              i32.add
              local.tee 0
              local.tee 3
              global.set $__stack_pointer
              local.get 2
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 0
              i32.load
              local.set 15
              local.get 3
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
              local.get 16
              i64.store offset=16
              local.get 0
              local.get 7
              i64.store offset=8
              local.get 0
              local.get 8
              i64.store
              local.get 15
              i32.const 4
              i32.add
              local.get 0
              call $wrapper_mstore_u256
              local.get 4
              i32.const 36
              call $wrapper_revert
              br 1 (;@4;)
            end
            local.get 3
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
            global.set $__stack_pointer
            local.get 4
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.set 17
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.set 14
            local.get 0
            i64.load
            local.set 19
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.set 20
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
            local.tee 4
            global.set $__stack_pointer
            local.get 2
            i32.const 24
            i32.add
            i32.const 66144
            i32.const 24
            i32.add
            i64.load
            i64.store align=1
            local.get 2
            i32.const 16
            i32.add
            i32.const 66144
            i32.const 16
            i32.add
            i64.load
            i64.store align=1
            local.get 2
            i32.const 8
            i32.add
            i32.const 66144
            i32.const 8
            i32.add
            i64.load
            i64.store align=1
            local.get 2
            i32.const 0
            i64.load offset=66144
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
            local.set 21
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
            local.get 4
            i32.const -32
            i32.add
            local.tee 0
            local.tee 2
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
            local.get 21
            i64.store offset=8
            local.get 0
            local.get 18
            i64.store
            local.get 2
            i32.const -32
            i32.add
            local.tee 4
            local.tee 2
            global.set $__stack_pointer
            local.get 0
            i32.const 224
            local.get 4
            call $wrapper_u256_shl
            local.get 19
            local.get 4
            i64.load
            i64.and
            local.get 20
            local.get 4
            i32.const 16
            i32.add
            i64.load
            i64.and
            i64.or
            local.get 14
            local.get 4
            i32.const 8
            i32.add
            i64.load
            i64.and
            local.get 17
            local.get 4
            i32.const 24
            i32.add
            i64.load
            i64.and
            i64.const 1516439848548827136
            i64.xor
            i64.or
            i64.or
            i64.eqz
            br_if 0 (;@4;)
            local.get 2
            i32.const -32
            i32.add
            local.tee 2
            local.tee 0
            global.set $__stack_pointer
            i32.const 64
            local.get 2
            call $wrapper_mload_bytes32
            local.get 2
            call $i32_from_big_endian_bytes32
            local.set 4
            local.get 0
            i32.const -32
            i32.add
            local.tee 0
            local.tee 3
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            i64.const 7250987342154956800
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
            local.get 4
            local.get 0
            call $wrapper_mstore_u256
            local.get 3
            i32.const -32
            i32.add
            local.tee 0
            local.tee 3
            global.set $__stack_pointer
            local.get 2
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i32.load
            local.set 15
            local.get 3
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
            local.get 16
            i64.store offset=16
            local.get 0
            local.get 7
            i64.store offset=8
            local.get 0
            local.get 8
            i64.store
            local.get 15
            i32.const 4
            i32.add
            local.get 0
            call $wrapper_mstore_u256
            local.get 4
            i32.const 36
            call $wrapper_revert
          end
          local.get 2
          i32.const -32
          i32.add
          local.tee 0
          local.tee 4
          global.set $__stack_pointer
          i32.const 64
          local.get 0
          call $wrapper_mload_bytes32
          local.get 0
          call $i32_from_big_endian_bytes32
          local.set 2
          local.get 4
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
          local.get 10
          i64.store offset=16
          local.get 0
          local.get 9
          i64.store offset=8
          local.get 0
          local.get 5
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
        local.get 3
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 16
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 17
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 14
        local.get 0
        i64.load
        local.set 19
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 3
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 19
        local.get 14
        local.get 17
        local.get 16
        local.get 8
        local.get 0
        i64.load
        local.tee 20
        i64.sub
        local.tee 10
        i64.const 32
        i64.add
        local.tee 9
        local.get 5
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.tee 6
        i64.sub
        local.get 8
        local.get 20
        i64.lt_u
        local.tee 4
        i64.extend_i32_u
        i64.sub
        local.tee 8
        local.get 9
        local.get 10
        i64.lt_u
        local.tee 15
        i64.extend_i32_u
        i64.add
        local.tee 20
        local.get 7
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.tee 18
        i64.sub
        local.tee 21
        local.get 4
        local.get 5
        local.get 6
        i64.lt_u
        local.get 5
        local.get 6
        i64.eq
        select
        i64.extend_i32_u
        local.tee 5
        i64.sub
        local.tee 6
        local.get 15
        local.get 20
        local.get 8
        i64.lt_u
        local.get 9
        local.get 10
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 10
        local.get 12
        local.get 0
        i32.const 24
        i32.add
        i64.load
        i64.sub
        local.get 7
        local.get 18
        i64.lt_u
        i64.extend_i32_u
        i64.sub
        local.get 21
        local.get 5
        i64.lt_u
        i64.extend_i32_u
        i64.sub
        local.get 10
        local.get 6
        i64.lt_u
        i64.extend_i32_u
        i64.add
        call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 0
        global.set $__stack_pointer
        i32.const 64
        local.get 2
        call $wrapper_mload_bytes32
        local.get 2
        call $i32_from_big_endian_bytes32
        local.set 4
        local.get 0
        i32.const -32
        i32.add
        local.tee 0
        local.tee 15
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
        i64.const 32
        i64.store
        local.get 4
        local.get 0
        call $wrapper_mstore_u256
        local.get 15
        i32.const -32
        i32.add
        local.tee 0
        local.tee 15
        global.set $__stack_pointer
        local.get 3
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.load
        local.set 0
        local.get 15
        i32.const -32
        i32.add
        local.tee 3
        local.tee 15
        global.set $__stack_pointer
        local.get 2
        local.get 3
        call $u256_from_big_endian_bytes
        local.get 3
        i64.load
        local.set 5
        local.get 0
        local.get 1
        i32.const 384
        i32.add
        call $wrapper_mload_bytes32
        local.get 5
        i64.const 32
        i64.add
        local.tee 10
        i32.wrap_i64
        local.tee 3
        local.get 1
        i32.const 384
        i32.add
        call $wrapper_mstore_bytes32
        local.get 3
        i32.const 32
        i32.add
        local.get 0
        i32.const 32
        i32.add
        local.get 1
        i32.const 384
        i32.add
        call $i32_from_big_endian_bytes32
        call $wrapper_data_copy
        local.get 1
        i32.const 384
        i32.add
        local.get 1
        i32.const 576
        i32.add
        call $u256_from_big_endian_bytes
        local.get 1
        i64.load offset=576
        local.get 10
        i64.add
        i32.wrap_i64
        i32.const 32
        i32.add
        i32.const 0
        call $wrapper_mstore_u32
        local.get 1
        i32.const 384
        i32.add
        local.get 1
        i32.const 544
        i32.add
        call $u256_from_big_endian_bytes
        local.get 1
        i64.load offset=544
        local.set 10
        local.get 15
        i32.const -32
        i32.add
        local.tee 0
        global.set $__stack_pointer
        local.get 2
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 4
        local.get 5
        local.get 10
        i64.const 31
        i64.add
        i64.const 4294967264
        i64.and
        i64.add
        local.get 0
        i64.load
        i64.sub
        i32.wrap_i64
        i32.const 64
        i32.add
        call $wrapper_return
        br 1 (;@1;)
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 3
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 16
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 17
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 14
      local.get 0
      i64.load
      local.set 19
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 3
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 19
      local.get 14
      local.get 17
      local.get 16
      local.get 8
      local.get 0
      i64.load
      local.tee 20
      i64.sub
      local.tee 10
      i64.const 32
      i64.add
      local.tee 9
      local.get 5
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.tee 6
      i64.sub
      local.get 8
      local.get 20
      i64.lt_u
      local.tee 4
      i64.extend_i32_u
      i64.sub
      local.tee 8
      local.get 9
      local.get 10
      i64.lt_u
      local.tee 15
      i64.extend_i32_u
      i64.add
      local.tee 20
      local.get 7
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.tee 18
      i64.sub
      local.tee 21
      local.get 4
      local.get 5
      local.get 6
      i64.lt_u
      local.get 5
      local.get 6
      i64.eq
      select
      i64.extend_i32_u
      local.tee 5
      i64.sub
      local.tee 6
      local.get 15
      local.get 20
      local.get 8
      i64.lt_u
      local.get 9
      local.get 10
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 10
      local.get 12
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.sub
      local.get 7
      local.get 18
      i64.lt_u
      i64.extend_i32_u
      i64.sub
      local.get 21
      local.get 5
      i64.lt_u
      i64.extend_i32_u
      i64.sub
      local.get 10
      local.get 6
      i64.lt_u
      i64.extend_i32_u
      i64.add
      call $MyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 0
      global.set $__stack_pointer
      i32.const 64
      local.get 2
      call $wrapper_mload_bytes32
      local.get 2
      call $i32_from_big_endian_bytes32
      local.set 4
      local.get 0
      i32.const -32
      i32.add
      local.tee 0
      local.tee 15
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
      i64.const 32
      i64.store
      local.get 4
      local.get 0
      call $wrapper_mstore_u256
      local.get 15
      i32.const -32
      i32.add
      local.tee 0
      local.tee 15
      global.set $__stack_pointer
      local.get 3
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i32.load
      local.set 0
      local.get 15
      i32.const -32
      i32.add
      local.tee 3
      local.tee 15
      global.set $__stack_pointer
      local.get 2
      local.get 3
      call $u256_from_big_endian_bytes
      local.get 3
      i64.load
      local.set 5
      local.get 0
      local.get 1
      i32.const 384
      i32.add
      call $wrapper_mload_bytes32
      local.get 5
      i64.const 32
      i64.add
      local.tee 10
      i32.wrap_i64
      local.tee 3
      local.get 1
      i32.const 384
      i32.add
      call $wrapper_mstore_bytes32
      local.get 3
      i32.const 32
      i32.add
      local.get 0
      i32.const 32
      i32.add
      local.get 1
      i32.const 384
      i32.add
      call $i32_from_big_endian_bytes32
      call $wrapper_data_copy
      local.get 1
      i32.const 384
      i32.add
      local.get 1
      i32.const 576
      i32.add
      call $u256_from_big_endian_bytes
      local.get 1
      i64.load offset=576
      local.get 10
      i64.add
      i32.wrap_i64
      i32.const 32
      i32.add
      i32.const 0
      call $wrapper_mstore_u32
      local.get 1
      i32.const 384
      i32.add
      local.get 1
      i32.const 544
      i32.add
      call $u256_from_big_endian_bytes
      local.get 1
      i64.load offset=544
      local.set 10
      local.get 15
      i32.const -32
      i32.add
      local.tee 0
      global.set $__stack_pointer
      local.get 2
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 4
      local.get 5
      local.get 10
      i64.const 31
      i64.add
      i64.const 4294967264
      i64.and
      i64.add
      local.get 0
      i64.load
      i64.sub
      i32.wrap_i64
      i32.const 64
      i32.add
      call $wrapper_return
    end
    i32.const 0
    i32.const 0
    call $wrapper_revert
    local.get 1
    i32.const 608
    i32.add
    global.set $__stack_pointer)
  (func $call (type 8)
    call $MyERC721_48598_deployed.MyERC721_48598_deployed.init)
  (func $_start (type 8)
    call $__init_evm_heap)
  (func $MyERC721_48598.MyERC721_48598.init (type 8)
    (local i32 i32 i32 i32 i64 i64 i64 i64 i64 i32 i64 i32 i64 i32 i64 i64 i64 i64 i64 i32 i64 i64 i32 i32)
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
    i64.const 160
    i64.store
    i32.const 64
    local.get 0
    call $wrapper_mstore_u256
    i32.const 96
    i32.const 5
    call $wrapper_mstore_u32
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 5582579277066403840
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
    i32.const 128
    local.get 0
    call $wrapper_mstore_u256
    local.get 2
    i32.const -32
    i32.add
    local.tee 3
    local.tee 0
    global.set $__stack_pointer
    i32.const 64
    local.get 3
    call $wrapper_mload_bytes32
    local.get 0
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 3
    local.get 0
    call $u256_from_big_endian_bytes
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
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 3
    local.get 0
    call $u256_from_big_endian_bytes
    block  ;; label = @1
      block  ;; label = @2
        local.get 6
        local.get 7
        i64.const 64
        i64.add
        local.tee 8
        local.get 7
        i64.lt_u
        local.tee 9
        i64.extend_i32_u
        i64.add
        local.tee 10
        i64.const 0
        i64.ne
        local.get 5
        local.get 9
        local.get 10
        local.get 6
        i64.lt_u
        local.get 8
        local.get 7
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 6
        i64.const 0
        i64.ne
        local.get 4
        local.get 6
        local.get 5
        i64.lt_u
        i64.extend_i32_u
        i64.add
        local.tee 7
        i64.const 0
        i64.ne
        local.get 7
        i64.eqz
        select
        local.get 6
        local.get 7
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
        local.get 8
        local.get 0
        i64.load
        i64.ge_u
        local.get 10
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.tee 5
        i64.ge_u
        local.get 10
        local.get 5
        i64.eq
        select
        local.get 6
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.tee 4
        i64.ge_u
        local.get 7
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.tee 5
        i64.ge_u
        local.get 7
        local.get 5
        i64.eq
        select
        local.get 6
        local.get 4
        i64.xor
        local.get 7
        local.get 5
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 1 (;@1;)
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
    local.get 7
    i64.store
    local.get 0
    local.get 6
    i64.store offset=16
    local.get 0
    local.get 10
    i64.store offset=8
    local.get 0
    local.get 8
    i64.store
    i32.const 64
    local.get 0
    call $wrapper_mstore_u256
    local.get 3
    call $i32_from_big_endian_bytes32
    local.set 9
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
    local.get 9
    local.get 0
    call $wrapper_mstore_u256
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 3
    local.get 0
    call $u256_from_big_endian_bytes
    local.get 0
    i32.load
    local.set 9
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    i64.const 5570467115695079424
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
    i32.const 32
    i32.add
    local.get 0
    call $wrapper_mstore_u256
    local.get 2
    i32.const -32
    i32.add
    local.tee 11
    local.tee 0
    global.set $__stack_pointer
    i32.const 96
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
    i64.const 0
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 9
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const -32
    i32.add
    local.tee 0
    local.tee 9
    global.set $__stack_pointer
    local.get 2
    local.get 0
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 0
    i64.load
    local.set 7
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
    local.set 8
    local.get 9
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 0
    local.get 10
    i64.store offset=16
    local.get 0
    local.get 6
    i64.store offset=8
    local.get 0
    local.get 7
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 9
    global.set $__stack_pointer
    local.get 0
    i32.const 1
    local.get 2
    call $wrapper_u256_shr
    block  ;; label = @1
      local.get 7
      i32.wrap_i64
      i32.const 1
      i32.and
      local.get 2
      i64.load
      local.tee 6
      i64.const 127
      i64.and
      local.get 6
      local.get 7
      i64.const 1
      i64.and
      local.tee 7
      i64.eqz
      select
      local.tee 5
      i64.const 31
      i64.gt_u
      i64.const 0
      local.get 7
      i64.sub
      local.tee 7
      local.get 2
      i32.const 8
      i32.add
      i64.load
      i64.and
      local.tee 12
      i64.const 0
      i64.ne
      local.get 12
      i64.eqz
      local.tee 13
      select
      local.get 7
      local.get 2
      i32.const 16
      i32.add
      i64.load
      i64.and
      local.tee 14
      i64.const 0
      i64.ne
      local.get 7
      local.get 2
      i32.const 24
      i32.add
      i64.load
      i64.and
      local.tee 4
      i64.const 0
      i64.ne
      local.get 4
      i64.eqz
      select
      local.get 14
      local.get 4
      i64.or
      i64.eqz
      local.tee 2
      select
      i32.eq
      br_if 0 (;@1;)
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 9
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
      local.get 5
      i64.const 32
      i64.lt_u
      i32.const 0
      local.get 13
      select
      i32.const 0
      local.get 2
      select
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      call $wrapper_mstore_u32
      local.get 9
      i32.const -32
      i32.add
      local.tee 13
      local.tee 0
      global.set $__stack_pointer
      i32.const 0
      i32.const 32
      local.get 13
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
      local.set 7
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 6
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 15
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 10
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 6
      local.get 7
      i64.const 31
      i64.add
      local.tee 8
      local.get 7
      i64.lt_u
      local.tee 9
      i64.extend_i32_u
      i64.add
      local.tee 16
      i64.store offset=8
      local.get 0
      local.get 8
      i64.store
      local.get 0
      local.get 10
      local.get 9
      local.get 16
      local.get 6
      i64.lt_u
      local.get 8
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
      local.get 15
      local.get 7
      local.get 10
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 8
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 15
      local.get 2
      i64.load
      local.set 16
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 17
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 13
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 6
      local.get 0
      i64.load
      local.set 10
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 7
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
          local.get 18
          local.get 8
          i64.add
          local.get 6
          local.get 15
          i64.add
          local.tee 15
          local.get 6
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 15
          local.get 10
          local.get 16
          i64.add
          local.tee 6
          local.get 10
          i64.lt_u
          local.tee 0
          local.get 7
          local.get 17
          i64.add
          local.get 0
          i64.extend_i32_u
          i64.add
          local.tee 10
          local.get 7
          i64.lt_u
          local.get 10
          local.get 7
          i64.eq
          select
          i64.extend_i32_u
          i64.add
          local.tee 8
          local.get 15
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.set 7
          br 1 (;@2;)
        end
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 13
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 7
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 8
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 10
        local.get 0
        i64.load
        local.set 6
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 12
      local.get 5
      i64.const 31
      i64.add
      local.tee 15
      local.get 5
      i64.lt_u
      local.tee 9
      i64.extend_i32_u
      i64.add
      local.tee 16
      i64.store offset=8
      local.get 0
      local.get 15
      i64.store
      local.get 0
      local.get 14
      local.get 9
      local.get 16
      local.get 12
      i64.lt_u
      local.get 15
      local.get 5
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 5
      i64.store offset=16
      local.get 0
      i32.const 24
      i32.add
      local.get 4
      local.get 5
      local.get 14
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 12
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 2
      i64.load
      local.set 5
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 14
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 9
      global.set $__stack_pointer
      local.get 13
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 6
      local.get 5
      local.get 0
      i64.load
      local.tee 15
      i64.add
      local.tee 17
      i64.ge_u
      local.get 10
      local.get 14
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.tee 5
      i64.add
      local.get 17
      local.get 15
      i64.lt_u
      local.tee 2
      i64.extend_i32_u
      i64.add
      local.tee 15
      i64.ge_u
      local.get 10
      local.get 15
      i64.eq
      select
      local.get 8
      local.get 4
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.tee 14
      i64.add
      local.tee 4
      local.get 2
      local.get 15
      local.get 5
      i64.lt_u
      local.get 15
      local.get 5
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 16
      i64.ge_u
      local.get 7
      local.get 12
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.add
      local.get 4
      local.get 14
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 16
      local.get 4
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 14
      i64.ge_u
      local.get 7
      local.get 14
      i64.eq
      select
      local.get 8
      local.get 16
      i64.xor
      local.get 7
      local.get 14
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 9
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 7
        i64.store
        local.get 0
        local.get 8
        i64.store offset=16
        local.get 0
        local.get 10
        i64.store offset=8
        local.get 0
        local.get 6
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 9
        global.set $__stack_pointer
        local.get 0
        local.get 2
        call $u256_to_big_endian_bytes
        local.get 9
        i32.const -32
        i32.add
        local.tee 0
        local.tee 9
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
        local.get 8
        local.get 6
        i64.const 1
        i64.add
        local.tee 5
        local.get 6
        i64.lt_u
        local.tee 0
        local.get 10
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 4
        local.get 10
        i64.lt_u
        local.get 5
        local.get 6
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 8
        i64.lt_u
        local.set 0
        local.get 5
        local.set 6
        local.get 4
        local.set 10
        local.get 12
        local.set 8
        local.get 5
        local.get 17
        i64.lt_u
        local.get 4
        local.get 15
        i64.lt_u
        local.get 4
        local.get 15
        i64.eq
        select
        local.get 12
        local.get 16
        i64.lt_u
        local.get 7
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 7
        local.get 14
        i64.lt_u
        local.get 7
        local.get 14
        i64.eq
        select
        local.get 12
        local.get 16
        i64.xor
        local.get 7
        local.get 14
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
      end
    end
    local.get 9
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
    local.set 7
    i64.const 0
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
    local.set 10
    local.get 0
    i64.load
    local.set 8
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                local.get 8
                i64.const 31
                i64.gt_u
                local.get 10
                i64.const 0
                i64.ne
                local.get 10
                i64.eqz
                select
                local.get 6
                i64.const 0
                i64.ne
                local.get 7
                i64.const 0
                i64.ne
                local.get 7
                i64.eqz
                select
                local.get 6
                local.get 7
                i64.or
                i64.eqz
                select
                i32.eqz
                br_if 0 (;@6;)
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
                local.tee 9
                global.set $__stack_pointer
                local.get 0
                local.get 2
                call $u256_to_big_endian_bytes
                local.get 9
                i32.const -32
                i32.add
                local.tee 19
                local.tee 0
                global.set $__stack_pointer
                local.get 11
                local.get 2
                local.get 19
                call $wrapper_bytes32_and
                i32.const 0
                i32.const 0
                call $wrapper_mstore_u32
                local.get 0
                i32.const -32
                i32.add
                local.tee 2
                local.tee 0
                global.set $__stack_pointer
                i32.const 0
                i32.const 32
                local.get 2
                call $wrapper_keccak256
                local.get 0
                i32.const -32
                i32.add
                local.tee 0
                local.tee 9
                global.set $__stack_pointer
                local.get 19
                local.get 0
                call $u256_from_big_endian_bytes
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
                br_if 1 (;@5;)
                i32.const 128
                local.set 13
                br 2 (;@4;)
              end
              local.get 2
              i32.const -32
              i32.add
              local.tee 2
              local.tee 9
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
              br_if 2 (;@3;)
              i64.const 0
              local.set 7
              i64.const 0
              local.set 6
              i64.const 0
              local.set 10
              br 3 (;@2;)
            end
            i64.const 0
            local.set 6
            i64.const 0
            local.set 14
            i64.const 0
            local.set 15
            i64.const 0
            local.set 10
            i64.const 32
            local.set 7
            i64.const 0
            local.set 16
            i64.const 0
            local.set 17
            i64.const 0
            local.set 18
            loop  ;; label = @5
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 7
              i32.wrap_i64
              i32.const 96
              i32.add
              local.get 0
              call $wrapper_mload_u256
              local.get 0
              i64.load
              local.set 8
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
              local.set 12
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 0
              i32.const 24
              i32.add
              local.get 12
              i64.store
              local.get 0
              local.get 4
              i64.store offset=16
              local.get 0
              local.get 5
              i64.store offset=8
              local.get 0
              local.get 8
              i64.store
              local.get 2
              local.get 0
              call $wrapper_sstore_u256_using_little_endian_hostapi
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 2
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 0
              i64.load
              local.set 8
              local.get 0
              i32.const 8
              i32.add
              i64.load
              local.set 5
              local.get 0
              i32.const 24
              i32.add
              i64.load
              local.set 20
              local.get 0
              i32.const 16
              i32.add
              i64.load
              local.set 4
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 2
              global.set $__stack_pointer
              local.get 0
              local.get 5
              local.get 8
              i64.const 1
              i64.add
              local.tee 12
              local.get 8
              i64.lt_u
              local.tee 9
              i64.extend_i32_u
              i64.add
              local.tee 21
              i64.store offset=8
              local.get 0
              local.get 12
              i64.store
              local.get 0
              local.get 4
              local.get 9
              local.get 21
              local.get 5
              i64.lt_u
              local.get 12
              local.get 8
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 8
              i64.store offset=16
              local.get 0
              i32.const 24
              i32.add
              local.get 20
              local.get 8
              local.get 4
              i64.lt_u
              i64.extend_i32_u
              i64.add
              i64.store
              local.get 2
              i32.const -32
              i32.add
              local.tee 2
              local.tee 9
              global.set $__stack_pointer
              local.get 0
              local.get 2
              call $u256_to_big_endian_bytes
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 19
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 15
              local.get 6
              i64.const 32
              i64.add
              local.tee 8
              local.get 6
              i64.lt_u
              local.tee 13
              local.get 14
              local.get 13
              i64.extend_i32_u
              i64.add
              local.tee 5
              local.get 14
              i64.lt_u
              local.get 8
              local.get 6
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 4
              local.get 15
              i64.lt_u
              local.set 13
              local.get 18
              local.get 17
              local.get 7
              i64.const 32
              i64.add
              local.tee 12
              local.get 7
              i64.lt_u
              local.tee 22
              local.get 16
              local.get 22
              i64.extend_i32_u
              i64.add
              local.tee 20
              local.get 16
              i64.lt_u
              local.get 12
              local.get 7
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 21
              local.get 17
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.set 18
              local.get 8
              local.set 6
              local.get 5
              local.set 14
              local.get 4
              local.set 15
              local.get 12
              local.set 7
              local.get 20
              local.set 16
              local.get 21
              local.set 17
              local.get 8
              local.get 0
              i64.load
              i64.lt_u
              local.get 5
              local.get 0
              i32.const 8
              i32.add
              i64.load
              local.tee 8
              i64.lt_u
              local.get 5
              local.get 8
              i64.eq
              select
              local.get 4
              local.get 0
              i32.const 16
              i32.add
              i64.load
              local.tee 5
              i64.lt_u
              local.get 10
              local.get 13
              i64.extend_i32_u
              i64.add
              local.tee 10
              local.get 0
              i32.const 24
              i32.add
              i64.load
              local.tee 8
              i64.lt_u
              local.get 10
              local.get 8
              i64.eq
              select
              local.get 4
              local.get 5
              i64.xor
              local.get 10
              local.get 8
              i64.xor
              i64.or
              i64.eqz
              select
              br_if 0 (;@5;)
            end
            local.get 12
            i32.wrap_i64
            i32.const 96
            i32.add
            local.set 13
          end
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 9
          global.set $__stack_pointer
          local.get 19
          local.get 0
          call $u256_from_big_endian_bytes
          local.get 0
          i64.load
          local.set 8
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
          local.set 7
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 9
          global.set $__stack_pointer
          local.get 11
          local.get 0
          call $u256_from_big_endian_bytes
          block  ;; label = @4
            local.get 8
            local.get 0
            i64.load
            i64.ge_u
            local.get 6
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.tee 8
            i64.ge_u
            local.get 6
            local.get 8
            i64.eq
            select
            local.get 10
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.tee 8
            i64.ge_u
            local.get 7
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.tee 6
            i64.ge_u
            local.get 7
            local.get 6
            i64.eq
            select
            local.get 10
            local.get 8
            i64.xor
            local.get 7
            local.get 6
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
            local.get 9
            i32.const -32
            i32.add
            local.tee 22
            local.tee 0
            global.set $__stack_pointer
            local.get 13
            local.get 22
            call $wrapper_mload_bytes32
            local.get 0
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 13
            global.set $__stack_pointer
            local.get 9
            i32.const 24
            i32.add
            local.get 11
            i32.const 24
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 9
            i32.const 16
            i32.add
            local.get 11
            i32.const 16
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 9
            i32.const 8
            i32.add
            local.get 11
            i32.const 8
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 9
            local.get 11
            i64.load align=1
            i64.store align=1
            local.get 9
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i64.load
            local.set 7
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
            local.set 8
            local.get 13
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 8
            i64.store
            local.get 0
            local.get 10
            i64.store offset=16
            local.get 0
            local.get 6
            i64.store offset=8
            local.get 0
            local.get 7
            i64.store
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 13
            global.set $__stack_pointer
            local.get 0
            i32.const 3
            local.get 9
            call $wrapper_u256_shl
            local.get 9
            i32.load
            local.set 19
            local.get 13
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
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
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 13
            global.set $__stack_pointer
            local.get 0
            local.get 19
            i32.const 248
            i32.and
            local.get 9
            call $wrapper_u256_shr
            local.get 9
            i64.load
            local.set 7
            local.get 9
            i32.const 8
            i32.add
            i64.load
            local.set 6
            local.get 9
            i32.const 16
            i32.add
            i64.load
            local.set 10
            local.get 9
            i32.const 24
            i32.add
            i64.load
            local.set 8
            local.get 13
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 8
            i64.const -1
            i64.xor
            i64.store
            local.get 0
            local.get 10
            i64.const -1
            i64.xor
            i64.store offset=16
            local.get 0
            local.get 6
            i64.const -1
            i64.xor
            i64.store offset=8
            local.get 0
            local.get 7
            i64.const -1
            i64.xor
            i64.store
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 13
            global.set $__stack_pointer
            local.get 0
            local.get 9
            call $u256_to_big_endian_bytes
            local.get 13
            i32.const -32
            i32.add
            local.tee 0
            local.tee 13
            global.set $__stack_pointer
            local.get 22
            local.get 9
            local.get 0
            call $wrapper_bytes32_and
            local.get 13
            i32.const -32
            i32.add
            local.tee 9
            local.tee 13
            global.set $__stack_pointer
            local.get 13
            i32.const -32
            i32.add
            local.tee 13
            local.tee 22
            global.set $__stack_pointer
            local.get 13
            i32.const 24
            i32.add
            local.get 0
            i32.const 24
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 13
            i32.const 16
            i32.add
            local.get 0
            i32.const 16
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 13
            i32.const 8
            i32.add
            local.get 0
            i32.const 8
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 13
            local.get 0
            i64.load align=1
            i64.store align=1
            local.get 13
            local.get 9
            call $u256_from_big_endian_bytes
            local.get 9
            i64.load
            local.set 7
            local.get 9
            i32.const 8
            i32.add
            i64.load
            local.set 6
            local.get 9
            i32.const 16
            i32.add
            i64.load
            local.set 10
            local.get 9
            i32.const 24
            i32.add
            i64.load
            local.set 8
            local.get 22
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 8
            i64.store
            local.get 0
            local.get 10
            i64.store offset=16
            local.get 0
            local.get 6
            i64.store offset=8
            local.get 0
            local.get 7
            i64.store
            local.get 2
            local.get 0
            call $wrapper_sstore_u256_using_little_endian_hostapi
          end
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 2
          global.set $__stack_pointer
          local.get 2
          i32.const -32
          i32.add
          local.tee 2
          local.tee 9
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
          local.set 7
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
          local.set 8
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 2
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 8
          i64.store
          local.get 0
          local.get 10
          i64.store offset=16
          local.get 0
          local.get 6
          i64.store offset=8
          local.get 0
          local.get 7
          i64.store
          local.get 2
          i32.const -32
          i32.add
          local.tee 2
          local.tee 9
          global.set $__stack_pointer
          local.get 0
          i32.const 1
          local.get 2
          call $wrapper_u256_shl
          local.get 2
          i32.const 24
          i32.add
          i64.load
          local.set 5
          local.get 2
          i32.const 16
          i32.add
          i64.load
          local.set 6
          local.get 2
          i32.const 8
          i32.add
          i64.load
          local.set 10
          local.get 2
          i64.load
          local.set 7
          local.get 9
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
          local.tee 9
          local.tee 2
          global.set $__stack_pointer
          local.get 0
          local.get 9
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
          local.get 5
          local.get 6
          local.get 7
          i64.const 1
          i64.add
          local.tee 8
          local.get 7
          i64.lt_u
          local.tee 13
          local.get 10
          local.get 13
          i64.extend_i32_u
          i64.add
          local.tee 4
          local.get 10
          i64.lt_u
          local.get 8
          local.get 7
          i64.ge_u
          select
          i64.extend_i32_u
          i64.add
          local.tee 7
          local.get 6
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.store
          local.get 0
          local.get 7
          i64.store offset=16
          local.get 0
          local.get 4
          i64.store offset=8
          local.get 0
          local.get 8
          i64.store
          local.get 9
          local.get 0
          call $wrapper_sstore_u256_using_little_endian_hostapi
          br 2 (;@1;)
        end
        local.get 9
        i32.const -32
        i32.add
        local.tee 0
        local.tee 9
        global.set $__stack_pointer
        i32.const 128
        local.get 0
        call $wrapper_mload_u256
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 10
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 6
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 7
        local.get 0
        i64.load
        local.set 5
      end
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 11
      i32.const 24
      i32.add
      local.tee 13
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 11
      i32.const 16
      i32.add
      local.tee 22
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 11
      i32.const 8
      i32.add
      local.tee 19
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
      local.set 8
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
      local.set 14
      local.get 9
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
      local.get 4
      i64.store offset=8
      local.get 0
      local.get 8
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 3
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i32.load
      local.set 23
      local.get 9
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
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      local.get 23
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i64.load
      local.set 8
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 4
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 12
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 14
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 13
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 22
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 19
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
      local.set 15
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
      local.set 18
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 18
      i64.store
      local.get 0
      local.get 17
      i64.store offset=16
      local.get 0
      local.get 16
      i64.store offset=8
      local.get 0
      local.get 15
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 1
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i64.load
      local.set 15
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 16
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 17
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 9
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
      local.tee 9
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 9
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
      local.get 18
      local.get 10
      local.get 14
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 0
      local.get 17
      local.get 6
      local.get 12
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=16
      local.get 0
      local.get 16
      local.get 7
      local.get 4
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=8
      local.get 0
      local.get 15
      local.get 5
      local.get 8
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 9
      local.get 0
      call $wrapper_sstore_u256_using_little_endian_hostapi
    end
    local.get 3
    call $i32_from_big_endian_bytes32
    local.set 0
    local.get 2
    i32.const -32
    i32.add
    local.tee 11
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    local.get 11
    call $wrapper_mload_bytes32
    local.get 2
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
      local.tee 6
      i64.const 0
      i64.ne
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.tee 7
      i64.const 0
      i64.ne
      local.get 7
      i64.eqz
      select
      local.get 6
      local.get 7
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
    i64.const 1
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 9
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const -32
    i32.add
    local.tee 0
    local.tee 9
    global.set $__stack_pointer
    local.get 2
    local.get 0
    call $wrapper_sload_u256_using_little_endian_hostapi
    local.get 0
    i64.load
    local.set 7
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
    local.set 8
    local.get 9
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    local.get 8
    i64.store
    local.get 0
    local.get 10
    i64.store offset=16
    local.get 0
    local.get 6
    i64.store offset=8
    local.get 0
    local.get 7
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 9
    global.set $__stack_pointer
    local.get 0
    i32.const 1
    local.get 2
    call $wrapper_u256_shr
    block  ;; label = @1
      local.get 2
      i64.load
      local.tee 6
      i64.const 127
      i64.and
      local.get 6
      local.get 7
      i64.const 1
      i64.and
      local.tee 10
      i64.eqz
      select
      local.tee 5
      i64.const 31
      i64.gt_u
      i64.const 0
      local.get 10
      i64.sub
      local.tee 6
      local.get 2
      i32.const 8
      i32.add
      i64.load
      i64.and
      local.tee 12
      i64.const 0
      i64.ne
      local.get 12
      i64.eqz
      local.tee 13
      select
      local.get 6
      local.get 2
      i32.const 16
      i32.add
      i64.load
      i64.and
      local.tee 14
      i64.const 0
      i64.ne
      local.get 6
      local.get 2
      i32.const 24
      i32.add
      i64.load
      i64.and
      local.tee 4
      i64.const 0
      i64.ne
      local.get 4
      i64.eqz
      select
      local.get 14
      local.get 4
      i64.or
      i64.eqz
      local.tee 2
      select
      local.get 7
      i32.wrap_i64
      i32.const 1
      i32.and
      i32.eq
      br_if 0 (;@1;)
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 9
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
      local.get 5
      i64.const 32
      i64.lt_u
      i32.const 0
      local.get 13
      select
      i32.const 0
      local.get 2
      select
      br_if 0 (;@1;)
      local.get 9
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
      i64.const 1
      i64.store
      i32.const 0
      local.get 0
      call $wrapper_mstore_u256
      local.get 2
      i32.const -32
      i32.add
      local.tee 13
      local.tee 0
      global.set $__stack_pointer
      i32.const 0
      i32.const 32
      local.get 13
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
      local.set 7
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 6
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 15
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 10
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 6
      local.get 7
      i64.const 31
      i64.add
      local.tee 8
      local.get 7
      i64.lt_u
      local.tee 9
      i64.extend_i32_u
      i64.add
      local.tee 16
      i64.store offset=8
      local.get 0
      local.get 8
      i64.store
      local.get 0
      local.get 10
      local.get 9
      local.get 16
      local.get 6
      i64.lt_u
      local.get 8
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
      local.get 15
      local.get 7
      local.get 10
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 8
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 15
      local.get 2
      i64.load
      local.set 16
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 17
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 13
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 0
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.set 6
      local.get 0
      i64.load
      local.set 10
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.set 7
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
          local.get 18
          local.get 8
          i64.add
          local.get 6
          local.get 15
          i64.add
          local.tee 15
          local.get 6
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.get 15
          local.get 10
          local.get 16
          i64.add
          local.tee 6
          local.get 10
          i64.lt_u
          local.tee 0
          local.get 7
          local.get 17
          i64.add
          local.get 0
          i64.extend_i32_u
          i64.add
          local.tee 10
          local.get 7
          i64.lt_u
          local.get 10
          local.get 7
          i64.eq
          select
          i64.extend_i32_u
          i64.add
          local.tee 8
          local.get 15
          i64.lt_u
          i64.extend_i32_u
          i64.add
          local.set 7
          br 1 (;@2;)
        end
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 13
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.const 24
        i32.add
        i64.load
        local.set 7
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 8
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 10
        local.get 0
        i64.load
        local.set 6
      end
      local.get 2
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 12
      local.get 5
      i64.const 31
      i64.add
      local.tee 15
      local.get 5
      i64.lt_u
      local.tee 9
      i64.extend_i32_u
      i64.add
      local.tee 16
      i64.store offset=8
      local.get 0
      local.get 15
      i64.store
      local.get 0
      local.get 14
      local.get 9
      local.get 16
      local.get 12
      i64.lt_u
      local.get 15
      local.get 5
      i64.ge_u
      select
      i64.extend_i32_u
      i64.add
      local.tee 5
      i64.store offset=16
      local.get 0
      i32.const 24
      i32.add
      local.get 4
      local.get 5
      local.get 14
      i64.lt_u
      i64.extend_i32_u
      i64.add
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 5
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 12
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 4
      local.get 2
      i64.load
      local.set 5
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 14
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 9
      global.set $__stack_pointer
      local.get 13
      local.get 0
      call $u256_from_big_endian_bytes
      local.get 6
      local.get 5
      local.get 0
      i64.load
      local.tee 15
      i64.add
      local.tee 17
      i64.ge_u
      local.get 10
      local.get 14
      local.get 0
      i32.const 8
      i32.add
      i64.load
      local.tee 5
      i64.add
      local.get 17
      local.get 15
      i64.lt_u
      local.tee 2
      i64.extend_i32_u
      i64.add
      local.tee 15
      i64.ge_u
      local.get 10
      local.get 15
      i64.eq
      select
      local.get 8
      local.get 4
      local.get 0
      i32.const 16
      i32.add
      i64.load
      local.tee 14
      i64.add
      local.tee 4
      local.get 2
      local.get 15
      local.get 5
      i64.lt_u
      local.get 15
      local.get 5
      i64.eq
      select
      i64.extend_i32_u
      i64.add
      local.tee 16
      i64.ge_u
      local.get 7
      local.get 12
      local.get 0
      i32.const 24
      i32.add
      i64.load
      i64.add
      local.get 4
      local.get 14
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.get 16
      local.get 4
      i64.lt_u
      i64.extend_i32_u
      i64.add
      local.tee 14
      i64.ge_u
      local.get 7
      local.get 14
      i64.eq
      select
      local.get 8
      local.get 16
      i64.xor
      local.get 7
      local.get 14
      i64.xor
      i64.or
      i64.eqz
      select
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 9
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 0
        i32.const 24
        i32.add
        local.get 7
        i64.store
        local.get 0
        local.get 8
        i64.store offset=16
        local.get 0
        local.get 10
        i64.store offset=8
        local.get 0
        local.get 6
        i64.store
        local.get 2
        i32.const -32
        i32.add
        local.tee 2
        local.tee 9
        global.set $__stack_pointer
        local.get 0
        local.get 2
        call $u256_to_big_endian_bytes
        local.get 9
        i32.const -32
        i32.add
        local.tee 0
        local.tee 9
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
        local.get 8
        local.get 6
        i64.const 1
        i64.add
        local.tee 5
        local.get 6
        i64.lt_u
        local.tee 0
        local.get 10
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 4
        local.get 10
        i64.lt_u
        local.get 5
        local.get 6
        i64.ge_u
        select
        i64.extend_i32_u
        i64.add
        local.tee 12
        local.get 8
        i64.lt_u
        local.set 0
        local.get 5
        local.set 6
        local.get 4
        local.set 10
        local.get 12
        local.set 8
        local.get 5
        local.get 17
        i64.lt_u
        local.get 4
        local.get 15
        i64.lt_u
        local.get 4
        local.get 15
        i64.eq
        select
        local.get 12
        local.get 16
        i64.lt_u
        local.get 7
        local.get 0
        i64.extend_i32_u
        i64.add
        local.tee 7
        local.get 14
        i64.lt_u
        local.get 7
        local.get 14
        i64.eq
        select
        local.get 12
        local.get 16
        i64.xor
        local.get 7
        local.get 14
        i64.xor
        i64.or
        i64.eqz
        select
        br_if 0 (;@2;)
      end
    end
    local.get 9
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
    local.set 7
    i64.const 0
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
    local.set 10
    local.get 0
    i64.load
    local.set 8
    local.get 2
    i32.const -32
    i32.add
    local.tee 0
    local.tee 2
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                local.get 8
                i64.const 31
                i64.gt_u
                local.get 10
                i64.const 0
                i64.ne
                local.get 10
                i64.eqz
                select
                local.get 6
                i64.const 0
                i64.ne
                local.get 7
                i64.const 0
                i64.ne
                local.get 7
                i64.eqz
                select
                local.get 6
                local.get 7
                i64.or
                i64.eqz
                select
                i32.eqz
                br_if 0 (;@6;)
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
                local.tee 9
                global.set $__stack_pointer
                local.get 0
                local.get 2
                call $u256_to_big_endian_bytes
                local.get 9
                i32.const -32
                i32.add
                local.tee 19
                local.tee 0
                global.set $__stack_pointer
                local.get 11
                local.get 2
                local.get 19
                call $wrapper_bytes32_and
                local.get 0
                i32.const -32
                i32.add
                local.tee 0
                local.tee 2
                global.set $__stack_pointer
                i64.const 0
                local.set 6
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
                i64.const 1
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
                i32.const 0
                i32.const 32
                local.get 2
                call $wrapper_keccak256
                local.get 0
                i32.const -32
                i32.add
                local.tee 0
                local.tee 9
                global.set $__stack_pointer
                local.get 19
                local.get 0
                call $u256_from_big_endian_bytes
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
                br_if 1 (;@5;)
                i64.const 32
                local.set 12
                br 2 (;@4;)
              end
              local.get 2
              i32.const -32
              i32.add
              local.tee 2
              local.tee 9
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
              br_if 2 (;@3;)
              i64.const 0
              local.set 7
              i64.const 0
              local.set 6
              i64.const 0
              local.set 10
              br 3 (;@2;)
            end
            i64.const 0
            local.set 14
            i64.const 0
            local.set 15
            i64.const 0
            local.set 10
            i64.const 32
            local.set 7
            i64.const 0
            local.set 16
            i64.const 0
            local.set 17
            i64.const 0
            local.set 18
            loop  ;; label = @5
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 3
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 0
              i64.load
              local.set 8
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 8
              local.get 7
              i64.add
              i32.wrap_i64
              local.get 0
              call $wrapper_mload_u256
              local.get 0
              i64.load
              local.set 8
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
              local.set 12
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 0
              i32.const 24
              i32.add
              local.get 12
              i64.store
              local.get 0
              local.get 4
              i64.store offset=16
              local.get 0
              local.get 5
              i64.store offset=8
              local.get 0
              local.get 8
              i64.store
              local.get 2
              local.get 0
              call $wrapper_sstore_u256_using_little_endian_hostapi
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 2
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 0
              i64.load
              local.set 8
              local.get 0
              i32.const 8
              i32.add
              i64.load
              local.set 5
              local.get 0
              i32.const 24
              i32.add
              i64.load
              local.set 20
              local.get 0
              i32.const 16
              i32.add
              i64.load
              local.set 4
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 2
              global.set $__stack_pointer
              local.get 0
              local.get 5
              local.get 8
              i64.const 1
              i64.add
              local.tee 12
              local.get 8
              i64.lt_u
              local.tee 9
              i64.extend_i32_u
              i64.add
              local.tee 21
              i64.store offset=8
              local.get 0
              local.get 12
              i64.store
              local.get 0
              local.get 4
              local.get 9
              local.get 21
              local.get 5
              i64.lt_u
              local.get 12
              local.get 8
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 8
              i64.store offset=16
              local.get 0
              i32.const 24
              i32.add
              local.get 20
              local.get 8
              local.get 4
              i64.lt_u
              i64.extend_i32_u
              i64.add
              i64.store
              local.get 2
              i32.const -32
              i32.add
              local.tee 2
              local.tee 9
              global.set $__stack_pointer
              local.get 0
              local.get 2
              call $u256_to_big_endian_bytes
              local.get 9
              i32.const -32
              i32.add
              local.tee 0
              local.tee 9
              global.set $__stack_pointer
              local.get 19
              local.get 0
              call $u256_from_big_endian_bytes
              local.get 15
              local.get 6
              i64.const 32
              i64.add
              local.tee 8
              local.get 6
              i64.lt_u
              local.tee 13
              local.get 14
              local.get 13
              i64.extend_i32_u
              i64.add
              local.tee 5
              local.get 14
              i64.lt_u
              local.get 8
              local.get 6
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 4
              local.get 15
              i64.lt_u
              local.set 13
              local.get 18
              local.get 17
              local.get 7
              i64.const 32
              i64.add
              local.tee 12
              local.get 7
              i64.lt_u
              local.tee 22
              local.get 16
              local.get 22
              i64.extend_i32_u
              i64.add
              local.tee 20
              local.get 16
              i64.lt_u
              local.get 12
              local.get 7
              i64.ge_u
              select
              i64.extend_i32_u
              i64.add
              local.tee 21
              local.get 17
              i64.lt_u
              i64.extend_i32_u
              i64.add
              local.set 18
              local.get 8
              local.set 6
              local.get 5
              local.set 14
              local.get 4
              local.set 15
              local.get 12
              local.set 7
              local.get 20
              local.set 16
              local.get 21
              local.set 17
              local.get 8
              local.get 0
              i64.load
              i64.lt_u
              local.get 5
              local.get 0
              i32.const 8
              i32.add
              i64.load
              local.tee 8
              i64.lt_u
              local.get 5
              local.get 8
              i64.eq
              select
              local.get 4
              local.get 0
              i32.const 16
              i32.add
              i64.load
              local.tee 5
              i64.lt_u
              local.get 10
              local.get 13
              i64.extend_i32_u
              i64.add
              local.tee 10
              local.get 0
              i32.const 24
              i32.add
              i64.load
              local.tee 8
              i64.lt_u
              local.get 10
              local.get 8
              i64.eq
              select
              local.get 4
              local.get 5
              i64.xor
              local.get 10
              local.get 8
              i64.xor
              i64.or
              i64.eqz
              select
              br_if 0 (;@5;)
            end
          end
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 9
          global.set $__stack_pointer
          local.get 19
          local.get 0
          call $u256_from_big_endian_bytes
          local.get 0
          i64.load
          local.set 8
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
          local.set 7
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 9
          global.set $__stack_pointer
          local.get 11
          local.get 0
          call $u256_from_big_endian_bytes
          block  ;; label = @4
            local.get 8
            local.get 0
            i64.load
            i64.ge_u
            local.get 6
            local.get 0
            i32.const 8
            i32.add
            i64.load
            local.tee 8
            i64.ge_u
            local.get 6
            local.get 8
            i64.eq
            select
            local.get 10
            local.get 0
            i32.const 16
            i32.add
            i64.load
            local.tee 8
            i64.ge_u
            local.get 7
            local.get 0
            i32.const 24
            i32.add
            i64.load
            local.tee 6
            i64.ge_u
            local.get 7
            local.get 6
            i64.eq
            select
            local.get 10
            local.get 8
            i64.xor
            local.get 7
            local.get 6
            i64.xor
            i64.or
            i64.eqz
            select
            br_if 0 (;@4;)
            local.get 9
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 3
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i64.load
            local.set 7
            local.get 9
            i32.const -32
            i32.add
            local.tee 13
            local.tee 0
            global.set $__stack_pointer
            local.get 7
            local.get 12
            i64.add
            i32.wrap_i64
            local.get 13
            call $wrapper_mload_bytes32
            local.get 0
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 22
            global.set $__stack_pointer
            local.get 9
            i32.const 24
            i32.add
            local.get 11
            i32.const 24
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 9
            i32.const 16
            i32.add
            local.get 11
            i32.const 16
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 9
            i32.const 8
            i32.add
            local.get 11
            i32.const 8
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 9
            local.get 11
            i64.load align=1
            i64.store align=1
            local.get 9
            local.get 0
            call $u256_from_big_endian_bytes
            local.get 0
            i64.load
            local.set 7
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
            local.set 8
            local.get 22
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 8
            i64.store
            local.get 0
            local.get 10
            i64.store offset=16
            local.get 0
            local.get 6
            i64.store offset=8
            local.get 0
            local.get 7
            i64.store
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 22
            global.set $__stack_pointer
            local.get 0
            i32.const 3
            local.get 9
            call $wrapper_u256_shl
            local.get 9
            i32.load
            local.set 3
            local.get 22
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
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
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 22
            global.set $__stack_pointer
            local.get 0
            local.get 3
            i32.const 248
            i32.and
            local.get 9
            call $wrapper_u256_shr
            local.get 9
            i64.load
            local.set 7
            local.get 9
            i32.const 8
            i32.add
            i64.load
            local.set 6
            local.get 9
            i32.const 16
            i32.add
            i64.load
            local.set 10
            local.get 9
            i32.const 24
            i32.add
            i64.load
            local.set 8
            local.get 22
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 8
            i64.const -1
            i64.xor
            i64.store
            local.get 0
            local.get 10
            i64.const -1
            i64.xor
            i64.store offset=16
            local.get 0
            local.get 6
            i64.const -1
            i64.xor
            i64.store offset=8
            local.get 0
            local.get 7
            i64.const -1
            i64.xor
            i64.store
            local.get 9
            i32.const -32
            i32.add
            local.tee 9
            local.tee 22
            global.set $__stack_pointer
            local.get 0
            local.get 9
            call $u256_to_big_endian_bytes
            local.get 22
            i32.const -32
            i32.add
            local.tee 0
            local.tee 22
            global.set $__stack_pointer
            local.get 13
            local.get 9
            local.get 0
            call $wrapper_bytes32_and
            local.get 22
            i32.const -32
            i32.add
            local.tee 9
            local.tee 13
            global.set $__stack_pointer
            local.get 13
            i32.const -32
            i32.add
            local.tee 13
            local.tee 22
            global.set $__stack_pointer
            local.get 13
            i32.const 24
            i32.add
            local.get 0
            i32.const 24
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 13
            i32.const 16
            i32.add
            local.get 0
            i32.const 16
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 13
            i32.const 8
            i32.add
            local.get 0
            i32.const 8
            i32.add
            i64.load align=1
            i64.store align=1
            local.get 13
            local.get 0
            i64.load align=1
            i64.store align=1
            local.get 13
            local.get 9
            call $u256_from_big_endian_bytes
            local.get 9
            i64.load
            local.set 7
            local.get 9
            i32.const 8
            i32.add
            i64.load
            local.set 6
            local.get 9
            i32.const 16
            i32.add
            i64.load
            local.set 10
            local.get 9
            i32.const 24
            i32.add
            i64.load
            local.set 8
            local.get 22
            i32.const -32
            i32.add
            local.tee 0
            local.tee 9
            global.set $__stack_pointer
            local.get 0
            i32.const 24
            i32.add
            local.get 8
            i64.store
            local.get 0
            local.get 10
            i64.store offset=16
            local.get 0
            local.get 6
            i64.store offset=8
            local.get 0
            local.get 7
            i64.store
            local.get 2
            local.get 0
            call $wrapper_sstore_u256_using_little_endian_hostapi
          end
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 2
          global.set $__stack_pointer
          local.get 2
          i32.const -32
          i32.add
          local.tee 2
          local.tee 9
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
          local.set 7
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
          local.set 8
          local.get 9
          i32.const -32
          i32.add
          local.tee 0
          local.tee 2
          global.set $__stack_pointer
          local.get 0
          i32.const 24
          i32.add
          local.get 8
          i64.store
          local.get 0
          local.get 10
          i64.store offset=16
          local.get 0
          local.get 6
          i64.store offset=8
          local.get 0
          local.get 7
          i64.store
          local.get 2
          i32.const -32
          i32.add
          local.tee 2
          local.tee 9
          global.set $__stack_pointer
          local.get 0
          i32.const 1
          local.get 2
          call $wrapper_u256_shl
          local.get 2
          i32.const 24
          i32.add
          i64.load
          local.set 5
          local.get 2
          i32.const 16
          i32.add
          i64.load
          local.set 6
          local.get 2
          i32.const 8
          i32.add
          i64.load
          local.set 10
          local.get 2
          i64.load
          local.set 7
          local.get 9
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
          i64.const 1
          i64.store
          local.get 2
          i32.const -32
          i32.add
          local.tee 9
          local.tee 2
          global.set $__stack_pointer
          local.get 0
          local.get 9
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
          local.get 5
          local.get 6
          local.get 7
          i64.const 1
          i64.add
          local.tee 8
          local.get 7
          i64.lt_u
          local.tee 13
          local.get 10
          local.get 13
          i64.extend_i32_u
          i64.add
          local.tee 4
          local.get 10
          i64.lt_u
          local.get 8
          local.get 7
          i64.ge_u
          select
          i64.extend_i32_u
          i64.add
          local.tee 7
          local.get 6
          i64.lt_u
          i64.extend_i32_u
          i64.add
          i64.store
          local.get 0
          local.get 7
          i64.store offset=16
          local.get 0
          local.get 4
          i64.store offset=8
          local.get 0
          local.get 8
          i64.store
          local.get 9
          local.get 0
          call $wrapper_sstore_u256_using_little_endian_hostapi
          br 2 (;@1;)
        end
        local.get 9
        i32.const -32
        i32.add
        local.tee 0
        local.tee 2
        global.set $__stack_pointer
        local.get 3
        local.get 0
        call $u256_from_big_endian_bytes
        local.get 0
        i32.load
        local.set 13
        local.get 2
        i32.const -32
        i32.add
        local.tee 0
        local.tee 9
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
        local.set 10
        local.get 0
        i32.const 16
        i32.add
        i64.load
        local.set 6
        local.get 0
        i32.const 8
        i32.add
        i64.load
        local.set 7
        local.get 0
        i64.load
        local.set 5
      end
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 11
      i32.const 24
      i32.add
      local.tee 13
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 11
      i32.const 16
      i32.add
      local.tee 22
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 11
      i32.const 8
      i32.add
      local.tee 3
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
      local.set 8
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
      local.set 14
      local.get 9
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
      local.get 4
      i64.store offset=8
      local.get 0
      local.get 8
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 3
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i32.load
      local.set 19
      local.get 9
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
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      local.get 19
      local.get 2
      call $wrapper_u256_shr
      local.get 2
      i64.load
      local.set 8
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 4
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 12
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 14
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 2
      i32.const 24
      i32.add
      local.get 13
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 16
      i32.add
      local.get 22
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 3
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
      local.set 15
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
      local.set 18
      local.get 9
      i32.const -32
      i32.add
      local.tee 0
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      local.get 18
      i64.store
      local.get 0
      local.get 17
      i64.store offset=16
      local.get 0
      local.get 16
      i64.store offset=8
      local.get 0
      local.get 15
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 2
      local.tee 9
      global.set $__stack_pointer
      local.get 0
      i32.const 1
      local.get 2
      call $wrapper_u256_shl
      local.get 2
      i64.load
      local.set 15
      local.get 2
      i32.const 8
      i32.add
      i64.load
      local.set 16
      local.get 2
      i32.const 16
      i32.add
      i64.load
      local.set 17
      local.get 2
      i32.const 24
      i32.add
      i64.load
      local.set 18
      local.get 9
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
      i64.const 1
      i64.store
      local.get 2
      i32.const -32
      i32.add
      local.tee 9
      local.tee 2
      global.set $__stack_pointer
      local.get 0
      local.get 9
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
      local.get 18
      local.get 10
      local.get 14
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 0
      local.get 17
      local.get 6
      local.get 12
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=16
      local.get 0
      local.get 16
      local.get 7
      local.get 4
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store offset=8
      local.get 0
      local.get 15
      local.get 5
      local.get 8
      i64.const -1
      i64.xor
      i64.and
      i64.or
      i64.store
      local.get 9
      local.get 0
      call $wrapper_sstore_u256_using_little_endian_hostapi
    end
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 0
    global.set $__stack_pointer
    local.get 2
    call $wrapper_caller
    block  ;; label = @1
      local.get 2
      call $wrapper_bytes32_iszero
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.const -32
      i32.add
      local.tee 2
      local.tee 0
      global.set $__stack_pointer
      i32.const 64
      local.get 2
      call $wrapper_mload_bytes32
      local.get 2
      call $i32_from_big_endian_bytes32
      local.set 9
      local.get 0
      i32.const -32
      i32.add
      local.tee 0
      local.tee 13
      global.set $__stack_pointer
      local.get 0
      i32.const 24
      i32.add
      i64.const 2184173212852551680
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
      local.get 13
      i32.const -32
      i32.add
      local.tee 13
      local.tee 0
      global.set $__stack_pointer
      local.get 2
      local.get 13
      call $u256_from_big_endian_bytes
      local.get 13
      i32.load
      i32.const 4
      i32.add
      i32.const 0
      call $wrapper_mstore_u32
      local.get 9
      i32.const 36
      call $wrapper_revert
    end
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
    i64.const 6
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 9
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const -32
    i32.add
    local.tee 0
    local.tee 9
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
    local.set 8
    local.get 0
    i32.const 16
    i32.add
    i64.load
    local.set 7
    local.get 0
    i32.const 24
    i32.add
    i64.load
    local.set 6
    local.get 9
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
    local.tee 9
    global.set $__stack_pointer
    local.get 2
    local.get 0
    call $u256_from_big_endian_bytes
    local.get 0
    i64.load
    local.set 5
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
    local.set 14
    local.get 9
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
    i64.const 6
    i64.store
    local.get 2
    i32.const -32
    i32.add
    local.tee 2
    local.tee 9
    global.set $__stack_pointer
    local.get 0
    local.get 2
    call $u256_to_big_endian_bytes
    local.get 9
    i32.const -32
    i32.add
    local.tee 0
    local.tee 9
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    local.get 14
    local.get 6
    i64.or
    i64.store
    local.get 0
    local.get 12
    local.get 7
    i64.const -4294967296
    i64.and
    i64.or
    i64.store offset=16
    local.get 0
    local.get 4
    i64.store offset=8
    local.get 0
    local.get 5
    i64.store
    local.get 2
    local.get 0
    call $wrapper_sstore_u256_using_little_endian_hostapi
    local.get 9
    i32.const -32
    i32.add
    local.tee 2
    local.tee 0
    global.set $__stack_pointer
    i32.const 64
    local.get 2
    call $wrapper_mload_bytes32
    local.get 0
    i32.const -32
    i32.add
    local.tee 9
    local.tee 0
    global.set $__stack_pointer
    local.get 9
    call $wrapper_caller
    local.get 0
    i32.const -32
    i32.add
    local.tee 0
    local.tee 13
    global.set $__stack_pointer
    local.get 0
    i32.const 24
    i32.add
    local.get 6
    i64.store
    local.get 0
    local.get 7
    i64.store offset=16
    local.get 0
    local.get 8
    i64.store offset=8
    local.get 0
    local.get 10
    i64.store
    local.get 13
    i32.const -32
    i32.add
    local.tee 13
    global.set $__stack_pointer
    local.get 0
    local.get 13
    call $u256_to_big_endian_bytes
    i32.const 0
    i32.const 0
    i32.const 66368
    local.get 13
    local.get 9
    call $wrapper_log3
    i32.const 0
    call $evm_get_memory_addr
    local.set 0
    local.get 2
    call $i32_from_big_endian_bytes32
    local.tee 2
    i32.const 83952
    local.get 0
    i32.sub
    i32.const 4
    call $wrapper_codecopy
    local.get 2
    i32.const 4
    call $wrapper_return
    local.get 1
    global.set $__stack_pointer)
  (func $deploy (type 8)
    call $set_is_deploying_tx
    call $MyERC721_48598.MyERC721_48598.init)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 3)
  (global $__stack_pointer (mut i32) (i32.const 65536))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "call" (func $call))
  (export "deploy" (func $deploy))
  (data $.rodata (i32.const 65536) "out length is not enough\00call contract failed\00call failed with no revert data\00\00\00\ff\ff\ff\ff")
  (data $.data (i32.const 65656) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;2;) (i32.const 65688) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;3;) (i32.const 65720) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;4;) (i32.const 65748) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\dd\f2R\ad\1b\e2\c8\9bi\c2\b0h\fc7\8d\aa\95+\a7\f1c\c4\a1\16(\f5ZM\f5#\b3\ef")
  (data (;5;) (i32.const 65820) "\ff\ff\ff\ff")
  (data (;6;) (i32.const 65852) "\ff\ff\ff\ff")
  (data (;7;) (i32.const 65876) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;8;) (i32.const 65916) "\ff\ff\ff\ff")
  (data (;9;) (i32.const 65948) "\80\acX\cd")
  (data (;10;) (i32.const 65980) "\a9\fb\f5\1f\8c[\e1\e5\eb\ec}[\d1OqB}\1e\84\f3\dd\03\14\c0\f7\b2)\1e[ \0a\c8\c7\c3\b9%")
  (data (;11;) (i32.const 66036) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;12;) (i32.const 66068) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\dd\f2R\ad\1b\e2\c8\9bi\c2\b0h\fc7\8d\aa\95+\a7\f1c\c4\a1\16(\f5ZM\f5#\b3\ef")
  (data (;13;) (i32.const 66140) "\ff\ff\ff\ff")
  (data (;14;) (i32.const 66172) "\ff\ff\ff\ff")
  (data (;15;) (i32.const 66196) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\8b\e0\07\9cS\16Y\14\13D\cd\1f\d0\a4\f2\84\19I\7f\97\22\a3\da\af\e3\b4\18okdW\e0\170~\ab9\aba\07\e8\89\98E\ad=Y\bd\96S\f2\00\f2 \92\04\89\ca+Y7il1")
  (data (;16;) (i32.const 66296) "\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (;17;) (i32.const 66324) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\8b\e0\07\9cS\16Y\14\13D\cd\1f\d0\a4\f2\84\19I\7f\97\22\a3\da\af\e3\b4\18okdW\e0\8b\e0\07\9cS\16Y\14\13D\cd\1f\d0\a4\f2\84\19I\7f\97\22\a3\da\af\e3\b4\18okdW\e0")
  (data (;18;) (i32.const 67544) "\01")
  (data (;19;) (i32.const 67550) "\02\00\00\00\03")
  (data (;20;) (i32.const 67562) "\01")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "producers" "\02\08language\01\03C99\00\0cprocessed-by\02\05clangV11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\0eHomebrew clang\0616.0.6")
  (@custom "name" "\01\f7\0eH\00\0fgetCallDataSize\01\0ccallDataCopy\02\09getCaller\03\0cgetCallValue\04\06revert\05\06finish\06\0bgetCodeSize\07\08codeCopy\08\18storageStoreLittleEndian\09\17storageLoadLittleEndian\0a\09keccak256\0b\0cemitLogEvent\0c\11getReturnDataSize\0d\0ereturnDataCopy\0e\0ccallContract\0f\0agetGasLeft\10\13getExternalCodeSize\11\11__wasm_call_ctors\12\1au256_from_big_endian_bytes\13\18u256_to_big_endian_bytes\14\1fi32_to_bytes32_big_endian_bytes\15\1bi32_from_big_endian_bytes32\16\1cwrapper_calldataload_bytes32\17\1ewrapper_calldata_load_selector\18\15wrapper_calldata_size\19\0ewrapper_caller\1a\1awrapper_callvalue_not_zero\1b\0ewrapper_revert\1c\13evm_get_memory_addr\1d\10wrapper_codecopy\1e\14wrapper_memory_guard\1f\16wrapper_mstore_bytes32 \13wrapper_mstore_u256!\12wrapper_mstore_u32\22\12wrapper_mload_u256#\15wrapper_mload_bytes32$/wrapper_sstore_u256_using_little_endian_hostapi%.wrapper_sload_u256_using_little_endian_hostapi&\11wrapper_keccak256'\0ewrapper_return(\0cwrapper_log3)\0cwrapper_log4*\0fwrite_call_data+\17wrapper_returndata_copy,\15wrapper_call_contract-\0bwrapper_gas.\17wrapper_returndata_size/\15wrapper_calldata_copy0\13set_is_deploying_tx1\14wrapper_extcode_size2\11wrapper_data_copy3\1dwrapper_calldata_size_minus_44\0f__init_evm_heap5\12wrapper_bytes32_eq6\16wrapper_bytes32_iszero7\13wrapper_bytes32_and8\10wrapper_u256_shl9\10wrapper_u256_shr:\13wrapper_bytes32_add;TMyERC721_48598_deployed.MyERC721_48598_deployed.abi_decode_addresst_addresst_uint256<IMyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation_17595=CMyERC721_48598_deployed.MyERC721_48598_deployed.finalize_allocation>KMyERC721_48598_deployed.MyERC721_48598_deployed.array_allocation_size_bytes?@MyERC721_48598_deployed.MyERC721_48598_deployed.fun_transferFrom@@MyERC721_48598_deployed.MyERC721_48598_deployed.fun_requireOwnedA>MyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOwnerBIMyERC721_48598_deployed.MyERC721_48598_deployed.fun_checkOnERC721ReceivedC4MyERC721_48598_deployed.MyERC721_48598_deployed.initD\04callE\06_startF\22MyERC721_48598.MyERC721_48598.initG\06deploy\07\12\01\00\0f__stack_pointer\09\11\02\00\07.rodata\01\05.data")
  (@custom ".debug_str" "y\00x\00low\00wasisdk://v12.0/build/compiler-rt\00du_int\00ti_int\00di_int\00long long int\00long long unsigned int\00uint64_t\00twords\00r\00all\00lower_mask\00high\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins/multi3.c\00b\00a\00__int128\00__multi3\00__mulddi3\00bits_in_dword_2\00clang version 11.0.0 (https://github.com/llvm/llvm-project 176249bd6732a8044d457092ed932768724a6f06)\00")
  (@custom ".debug_line" "M\01\00\00\04\00\c2\00\00\00\01\01\01\fb\0e\0d\00\01\01\01\01\00\00\00\01\00\00\01wasisdk://v12.0/build/install/opt/wasi-sdk/share/wasi-sysroot/include/bits\00wasisdk://v12.0/src/llvm-project/compiler-rt/lib/builtins\00\00alltypes.h\00\01\00\00int_types.h\00\02\00\00multi3.c\00\02\00\00\00\04\03\00\05\02\ff\ff\ff\ff\03'\01\05\03\0aD\05,-\05\18\06X\05\0c\06\03rX\05\0b\1eo\05&`\05\0c\06<\05#\06\03u \05\10\06\ac\05\1e\90\03i<\05\16\06\03\18J\05\1f\22\05\05\06X\03f \05\10\06\03\1cJ\05\22\03\13 \05\0f\03n \05\1f\92\05\05\06X\03a \05\11\06\03!J\05\0c\03\0e \05\03!\05\1f\03pX\05\0b\03yX\97\05\03\03\10 \02\04\00\01\01")
  (@custom ".debug_abbrev" "\01\11\01%\0e\13\05\03\0e\10\17\1b\0e\11\01\12\06\00\00\02$\00\03\0e>\0b\0b\0b\00\00\03\16\00I\13\03\0e:\0b;\0b\00\00\04.\01\03\0e:\0b;\0b'\19I\13 \0b\00\00\05\05\00\03\0e:\0b;\0bI\13\00\00\064\00\03\0e:\0b;\0bI\13\00\00\07\17\01\0b\0b:\0b;\0b\00\00\08\0d\00\03\0eI\13:\0b;\0b8\0b\00\00\09\13\01\0b\0b:\0b;\0b\00\00\0a&\00I\13\00\00\0b.\01\11\01\12\06@\18\97B\19\03\0e:\0b;\0b'\19I\13?\19\00\00\0c\05\00\02\17\03\0e:\0b;\0bI\13\00\00\0d4\00\02\17\03\0e:\0b;\0bI\13\00\00\0e\1d\011\13U\17X\0bY\0bW\0b\00\00\0f\05\001\13\00\00\104\00\02\171\13\00\00\114\00\1c\0d1\13\00\00\124\00\1c\0f1\13\00\00\00")
  (@custom ".debug_ranges" "\0f\00\00\00G\00\00\00H\00\00\00\5c\00\00\00b\00\00\00q\00\00\00\00\00\00\00\00\00\00\00")
  (@custom ".debug_loc" "\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\007\00\00\009\00\00\00\06\00\ed\02\02\9f\93\089\00\00\00G\00\00\00\06\00\ed\00\05\9f\93\08G\00\00\00H\00\00\00\0c\00\ed\00\05\9f\93\08\ed\02\02\9f\93\08H\00\00\00p\00\00\00\06\00\ed\00\05\9f\93\08p\00\00\00q\00\00\00\06\00\ed\02\02\9f\93\08q\00\00\00t\00\00\00\06\00\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00\00\00\00\00u\00\00\00\02\00\93\08\00\00\00\00\00\00\00\00]\00\00\00`\00\00\00\08\00\93\08\ed\02\01\9f\93\08\00\00\00\00\00\00\00\00<\00\00\00B\00\00\00\04\00\ed\02\02\9fQ\00\00\00Y\00\00\00\04\00\ed\02\02\9fY\00\00\00u\00\00\00\04\00\ed\00\03\9f\00\00\00\00\00\00\00\00")
  (@custom ".debug_info" "\b4\01\00\00\04\00\00\00\00\00\04\01\fd\00\00\00\0c\00\8a\00\00\00\00\00\00\00\08\00\00\00\ff\ff\ff\ffu\00\00\00\02`\00\00\00\05\04\038\00\00\00*\00\00\00\02&\03C\00\00\00d\00\00\00\01\aa\02M\00\00\00\07\08\04\e3\00\00\00\03\13\99\00\00\00\01\05\cf\00\00\00\03\13-\00\00\00\05\cd\00\00\00\03\13-\00\00\00\06t\00\00\00\03\14\ab\00\00\00\06\ed\00\00\00\03\15\0d\01\00\00\06z\00\00\00\03\16\12\01\00\00\06k\00\00\00\03\18-\00\00\00\00\03\a4\00\00\001\00\00\00\02O\02\d1\00\00\00\05\10\03\b6\00\00\00m\00\00\00\02]\07\10\02R\08v\00\00\00\99\00\00\00\02S\00\08r\00\00\00\d2\00\00\00\02\5c\00\09\10\02T\08\04\00\00\00-\00\00\00\02V\00\08\85\00\00\00\f0\00\00\00\02W\08\00\00\03\fb\00\00\008\00\00\00\02%\03\06\01\00\00e\00\00\00\01\91\02?\00\00\00\05\08\0a&\00\00\00\0a-\00\00\00\0b\ff\ff\ff\ffu\00\00\00\07\ed\03\00\00\00\00\9f\da\00\00\00\03(\99\00\00\00\0c\00\00\00\00\cf\00\00\00\03(\99\00\00\00\0c\14\00\00\00\cd\00\00\00\03(\99\00\00\00\0d(\00\00\00\00\00\00\00\03+\ab\00\00\00\0d\aa\00\00\00\02\00\00\00\03)\ab\00\00\00\0d\be\00\00\00t\00\00\00\03-\ab\00\00\00\0eJ\00\00\00\00\00\00\00\03.\0b\0fV\00\00\00\0fa\00\00\00\10<\00\00\00l\00\00\00\11 w\00\00\00\12\ff\ff\ff\ff\0f\82\00\00\00\10\d8\00\00\00\8d\00\00\00\00\00\00"))
