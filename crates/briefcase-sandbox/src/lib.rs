use anyhow::Context as _;
use base64::Engine as _;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use url::Url;
use wasmtime::{
    AsContext, AsContextMut, Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

const WASM_PAGE_SIZE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    allowed_hosts: HashSet<String>,
    allowed_fs_path_prefixes: Vec<PathBuf>,
}

impl SandboxPolicy {
    pub fn deny_all() -> Self {
        Self {
            allowed_hosts: HashSet::new(),
            allowed_fs_path_prefixes: Vec::new(),
        }
    }

    pub fn allow_hosts(hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed_hosts: hosts.into_iter().map(|s| s.into()).collect(),
            allowed_fs_path_prefixes: Vec::new(),
        }
    }

    pub fn with_fs_paths(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.allowed_fs_path_prefixes = paths
            .into_iter()
            .filter_map(|p| std::fs::canonicalize(p.into()).ok())
            .collect();
        self
    }

    pub fn allows_url(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        self.allowed_hosts.contains(host)
    }

    pub fn allows_fs_path(&self, path: &Path) -> bool {
        self.allowed_fs_path_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }
}

#[derive(Debug, Clone)]
pub struct SandboxLimits {
    pub max_memory_bytes: usize,
    pub max_fuel: u64,
    pub max_output_bytes: usize,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            max_fuel: 50_000_000,
            max_output_bytes: 1024 * 1024,
        }
    }
}

pub trait HttpHandler: Send + Sync {
    fn handle(&self, request_json: &str) -> anyhow::Result<String>;
}

#[derive(Debug, Default)]
pub struct DeterministicHttpHandler;

impl HttpHandler for DeterministicHttpHandler {
    fn handle(&self, request_json: &str) -> anyhow::Result<String> {
        // Minimal placeholder: return a deterministic JSON response. Production deployments
        // provide a handler that performs real connector I/O.
        Ok(serde_json::json!({
            "ok": true,
            "request": request_json,
        })
        .to_string())
    }
}

struct HostState {
    policy: SandboxPolicy,
    limits: SandboxLimits,
    output_offset: u32,
    http: Arc<dyn HttpHandler>,
    store_limits: StoreLimits,
}

pub struct WasmSandbox {
    engine: Engine,
    module: Module,
}

impl WasmSandbox {
    pub fn new(wasm_bytes: &[u8]) -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).context("create wasmtime engine")?;
        let module = Module::new(&engine, wasm_bytes).context("compile wasm module")?;
        Ok(Self { engine, module })
    }

    pub fn execute(
        &self,
        policy: &SandboxPolicy,
        limits: &SandboxLimits,
        http: Arc<dyn HttpHandler>,
        input: &str,
    ) -> anyhow::Result<String> {
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .build();
        let host_state = HostState {
            policy: policy.clone(),
            limits: limits.clone(),
            output_offset: 0x2000,
            http,
            store_limits,
        };
        let mut store = Store::new(&self.engine, host_state);
        store
            .set_fuel(limits.max_fuel)
            .context("configure sandbox fuel limit")?;
        store.limiter(|st| &mut st.store_limits);

        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "host",
            "http_request",
            |mut caller: Caller<'_, HostState>,
             req_ptr: i32,
             req_len: i32|
             -> anyhow::Result<i64> {
                let memory = get_memory(&mut caller)?;

                let req = read_utf8(&mut caller, &memory, req_ptr as u32, req_len as u32)
                    .context("read request")?;

                // If the request contains a URL, enforce host allowlist before dispatch.
                // More complex connector requests (provider-bound calls, remote MCP calls) may omit
                // `url` and enforce allowlists inside the handler.
                let v: serde_json::Value =
                    serde_json::from_str(&req).context("parse request json")?;
                if let Some(url) = v.get("url").and_then(|u| u.as_str()) {
                    let parsed = Url::parse(url).context("parse url")?;
                    if !caller.data().policy.allows_url(&parsed) {
                        anyhow::bail!("egress denied: host not allowed");
                    }
                }

                let resp = caller.data().http.handle(&req).context("http handler")?;
                write_output(&mut caller, &memory, resp)
            },
        )?;

        linker.func_wrap(
            "host",
            "fs_read",
            |mut caller: Caller<'_, HostState>,
             path_ptr: i32,
             path_len: i32|
             -> anyhow::Result<i64> {
                let memory = get_memory(&mut caller)?;
                let path_s = read_utf8(&mut caller, &memory, path_ptr as u32, path_len as u32)
                    .context("read path")?;
                let path = PathBuf::from(path_s);
                if !path.is_absolute() {
                    anyhow::bail!("fs denied: path must be absolute");
                }

                let canon = std::fs::canonicalize(&path).context("canonicalize path")?;
                if !caller.data().policy.allows_fs_path(&canon) {
                    anyhow::bail!("fs denied: path not allowed");
                }

                let bytes = std::fs::read(&canon).context("read file")?;
                if bytes.len() > caller.data().limits.max_output_bytes {
                    anyhow::bail!("fs denied: file too large");
                }

                let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
                let resp = serde_json::json!({
                    "ok": true,
                    "bytes": bytes.len(),
                    "data_b64": b64,
                })
                .to_string();
                write_output(&mut caller, &memory, resp)
            },
        )?;

        linker.func_wrap(
            "host",
            "fs_write",
            |mut caller: Caller<'_, HostState>,
             req_ptr: i32,
             req_len: i32|
             -> anyhow::Result<i64> {
                let memory = get_memory(&mut caller)?;
                let req = read_utf8(&mut caller, &memory, req_ptr as u32, req_len as u32)
                    .context("read request")?;
                let v: serde_json::Value =
                    serde_json::from_str(&req).context("parse request json")?;
                let path_s = v
                    .get("path")
                    .and_then(|x| x.as_str())
                    .context("missing path")?;
                let data_b64 = v
                    .get("data_b64")
                    .and_then(|x| x.as_str())
                    .context("missing data_b64")?;

                let path = PathBuf::from(path_s);
                if !path.is_absolute() {
                    anyhow::bail!("fs denied: path must be absolute");
                }

                let parent = path.parent().context("missing parent")?;
                let parent_canon = std::fs::canonicalize(parent).context("canonicalize parent")?;
                if !caller.data().policy.allows_fs_path(&parent_canon) {
                    anyhow::bail!("fs denied: path not allowed");
                }

                let file_name = path.file_name().context("missing file name")?;
                let target = parent_canon.join(file_name);

                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(data_b64)
                    .context("decode data_b64")?;
                if bytes.len() > caller.data().limits.max_output_bytes {
                    anyhow::bail!("fs denied: write too large");
                }

                std::fs::write(&target, bytes).context("write file")?;
                let resp = serde_json::json!({ "ok": true }).to_string();
                write_output(&mut caller, &memory, resp)
            },
        )?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .context("instantiate wasm")?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .context("wasm module missing export memory")?;
        let run = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "run")
            .context("wasm module missing export run(i32,i32)->i64")?;

        let input_offset: u32 = 0x1000;
        write_bytes(&mut store, &memory, input_offset, input.as_bytes()).context("write input")?;

        let packed = run
            .call(&mut store, (input_offset as i32, input.len() as i32))
            .context("call run")?;
        let (out_ptr, out_len) = unpack_ptr_len(packed);

        let out = read_utf8(&mut store, &memory, out_ptr, out_len).context("read output")?;
        Ok(out)
    }
}

pub fn pack_ptr_len(ptr: u32, len: u32) -> i64 {
    ((len as i64) << 32) | (ptr as i64)
}

pub fn unpack_ptr_len(x: i64) -> (u32, u32) {
    let ptr = (x & 0xffff_ffff) as u32;
    let len = ((x >> 32) & 0xffff_ffff) as u32;
    (ptr, len)
}

pub fn get_memory<T>(caller: &mut Caller<'_, T>) -> anyhow::Result<Memory> {
    let Some(export) = caller.get_export("memory") else {
        anyhow::bail!("missing memory export");
    };
    export
        .into_memory()
        .context("memory export is not a memory")
}

fn write_output(
    caller: &mut Caller<'_, HostState>,
    memory: &Memory,
    resp: String,
) -> anyhow::Result<i64> {
    if resp.len() > caller.data().limits.max_output_bytes {
        anyhow::bail!("response too large");
    }

    let out_ptr = caller.data().output_offset;
    write_bytes(caller, memory, out_ptr, resp.as_bytes()).context("write response")?;

    // Bump the output offset for subsequent host calls.
    let next = out_ptr
        .checked_add(resp.len() as u32)
        .context("output offset overflow")?
        .checked_add(8)
        .context("output offset overflow")?;
    caller.data_mut().output_offset = next;

    Ok(pack_ptr_len(out_ptr, resp.len() as u32))
}

fn ensure_memory_capacity(
    ctx: &mut impl AsContextMut,
    memory: &Memory,
    end_offset: u32,
) -> anyhow::Result<()> {
    let needed = end_offset as usize;
    let current = memory.data_size(ctx.as_context());
    if needed <= current {
        return Ok(());
    }
    let missing = needed - current;
    let additional_pages = missing.div_ceil(WASM_PAGE_SIZE_BYTES);
    memory
        .grow(&mut *ctx, additional_pages as u64)
        .context("grow wasm memory")?;
    Ok(())
}

fn ensure_memory_readable(
    ctx: impl AsContext,
    memory: &Memory,
    end_offset: u32,
) -> anyhow::Result<()> {
    let needed = end_offset as usize;
    let current = memory.data_size(ctx);
    if needed > current {
        anyhow::bail!("out of bounds memory read");
    }
    Ok(())
}

pub fn write_bytes(
    ctx: &mut impl AsContextMut,
    memory: &Memory,
    offset: u32,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let end = offset
        .checked_add(bytes.len() as u32)
        .context("offset overflow")?;
    ensure_memory_capacity(ctx, memory, end)?;
    memory
        .write(&mut *ctx, offset as usize, bytes)
        .context("write wasm memory")?;
    Ok(())
}

pub fn read_utf8(
    ctx: &mut impl AsContextMut,
    memory: &Memory,
    offset: u32,
    len: u32,
) -> anyhow::Result<String> {
    let end = offset.checked_add(len).context("offset overflow")?;
    ensure_memory_readable(ctx.as_context(), memory, end)?;

    let mut buf = vec![0u8; len as usize];
    memory
        .read(ctx.as_context(), offset as usize, &mut buf)
        .context("read wasm memory")?;
    String::from_utf8(buf).context("invalid utf-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sandbox_enforces_allowlist() -> anyhow::Result<()> {
        let wasm = wat::parse_str(
            r#"
            (module
              (import "host" "http_request" (func $http_request (param i32 i32) (result i64)))
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64)
                local.get 0
                local.get 1
                call $http_request
              )
            )
            "#,
        )?;

        let sandbox = WasmSandbox::new(&wasm)?;

        let allowed = SandboxPolicy::allow_hosts(["example.com"]);
        let ok = sandbox.execute(
            &allowed,
            &SandboxLimits::default(),
            Arc::new(DeterministicHttpHandler),
            r#"{"url":"https://example.com/"}"#,
        )?;
        assert!(ok.contains("\"ok\":true"));

        let denied = SandboxPolicy::deny_all();
        let err = sandbox
            .execute(
                &denied,
                &SandboxLimits::default(),
                Arc::new(DeterministicHttpHandler),
                r#"{"url":"https://example.com/"}"#,
            )
            .unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains("egress denied"), "err={s}");

        Ok(())
    }

    #[test]
    fn sandbox_fuel_limits_infinite_loop() -> anyhow::Result<()> {
        let wasm = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64)
                (local $x i64)
                (loop $l
                  local.get $x
                  i64.const 1
                  i64.add
                  local.set $x
                  br $l
                )
                local.get $x
              )
            )
            "#,
        )?;
        let sandbox = WasmSandbox::new(&wasm)?;

        let limits = SandboxLimits {
            max_fuel: 10_000,
            ..SandboxLimits::default()
        };

        let err = sandbox
            .execute(
                &SandboxPolicy::deny_all(),
                &limits,
                Arc::new(DeterministicHttpHandler),
                r#"{"url":"https://example.com/"}"#,
            )
            .unwrap_err();
        let s = format!("{err:#}");
        assert!(
            s.contains("all fuel consumed") || s.contains("fuel") || s.contains("out of fuel"),
            "err={s}"
        );
        Ok(())
    }

    #[test]
    fn sandbox_fs_read_enforces_allowlist() -> anyhow::Result<()> {
        let wasm = wat::parse_str(
            r#"
            (module
              (import "host" "fs_read" (func $fs_read (param i32 i32) (result i64)))
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64)
                local.get 0
                local.get 1
                call $fs_read
              )
            )
            "#,
        )?;

        let dir = tempdir()?;
        let file_path = dir.path().join("hello.txt");
        std::fs::write(&file_path, b"hello")?;
        let file_path = std::fs::canonicalize(file_path)?;

        let sandbox = WasmSandbox::new(&wasm)?;

        let denied = SandboxPolicy::deny_all();
        let err = sandbox
            .execute(
                &denied,
                &SandboxLimits::default(),
                Arc::new(DeterministicHttpHandler),
                file_path.to_string_lossy().as_ref(),
            )
            .unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains("fs denied"), "err={s}");

        let allowed = SandboxPolicy::deny_all().with_fs_paths([dir.path().to_path_buf()]);
        let ok = sandbox.execute(
            &allowed,
            &SandboxLimits::default(),
            Arc::new(DeterministicHttpHandler),
            file_path.to_string_lossy().as_ref(),
        )?;
        assert!(ok.contains("\"ok\":true"));
        assert!(ok.contains("data_b64"));

        Ok(())
    }
}
