(module
  (import "host" "fs_read" (func $fs_read (param i32 i32) (result i64)))
  (memory (export "memory") 1)
  (func (export "run") (param i32 i32) (result i64)
    local.get 0
    local.get 1
    call $fs_read
  )
)

