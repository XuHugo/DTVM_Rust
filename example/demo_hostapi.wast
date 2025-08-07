(module
  (type (func (param i32)))
  (import "env" "get_host_number" (func $get_host_number (param i32 i32) (result i32)))
  (func $test (export "test") (param i32) (param i32) (result i32)
    (call $get_host_number (local.get 0) (local.get 1))
  )
  (memory 1)
  (data (i32.const 0) "a")
    )
