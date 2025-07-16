(assert_invalid
  (module
    (func $add_v128 (param $a v128) (param $b v128) (result v128)
      local.get $a
      local.get $b
      i32x4.add
    )

    (func (export "test")
      (local $vec1 v128)
      (local $vec2 v128)
      (local $result_vec v128)

      (local.set $vec1 (v128.const i32x4 0x01000000 0x02000000 0x03000000 0x04000000))
      (local.set $vec2 (v128.const i32x4 0x05000000 0x06000000 0x07000000 0x08000000))

      local.get $vec1
      local.get $vec2
      call $add_v128
      local.set $result_vec
    )
  )
  "load error: invalid value type"
)
