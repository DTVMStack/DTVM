(module
  (memory 1 1024)
  (data (i32.const 0) "\2a")
  (data (i32.const 65532) "\ef\be\ad\de")
  (func (export "grow") (param i32) (result i32)
    (memory.grow (local.get 0)))
  (func (export "read") (param i32) (result i32)
    (i32.load8_u (local.get 0)))
  (func (export "write") (param i32 i32)
    (i32.store8 (local.get 0) (local.get 1)))
  (func (export "scan") (param $p i32) (param $end i32) (result i32)
    (local $bits i32)
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $p) (local.get $end)))
        (local.set $bits (i32.or (local.get $bits) (i32.load8_u (local.get $p))))
        (local.set $p (i32.add (local.get $p) (i32.const 1)))
        (br $next)))
    (local.get $bits)))
