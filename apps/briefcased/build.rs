use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    compile_wat(
        &manifest_dir.join("wasm").join("forward_http_request.wat"),
        &out_dir.join("forward_http_request.wasm"),
    );
    compile_wat(
        &manifest_dir.join("wasm").join("forward_fs_read.wat"),
        &out_dir.join("forward_fs_read.wasm"),
    );
}

fn compile_wat(wat_path: &PathBuf, out_path: &PathBuf) {
    println!("cargo:rerun-if-changed={}", wat_path.display());
    let wat_src = std::fs::read(wat_path).expect("read wat");
    let wasm = wat::parse_bytes(&wat_src).expect("compile wat");
    std::fs::write(out_path, wasm).expect("write wasm");
}
