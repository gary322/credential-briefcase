(module
  (import "host" "http_request" (func $http_request (param i32 i32) (result i64)))
  (memory (export "memory") 1)
  (func (export "run") (param i32 i32) (result i64)
    local.get 0
    local.get 1
    call $http_request
  )
)

