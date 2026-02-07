fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only generate LND gRPC bindings when the feature is enabled. This keeps
    // builds that don't care about Lightning (e.g. default CI paths) leaner.
    if std::env::var("CARGO_FEATURE_L402_LND").is_ok() {
        let protoc = protoc_bin_vendored::protoc_bin_path()
            .map_err(|e| format!("locate vendored protoc: {e}"))?;
        // Rust 2024 makes mutating the process environment unsafe.
        unsafe { std::env::set_var("PROTOC", protoc) };

        println!("cargo:rerun-if-changed=proto/lnd/lightning.proto");
        tonic_prost_build::configure()
            .build_server(false)
            .compile_protos(&["proto/lnd/lightning.proto"], &["proto/lnd"])?;
    }

    Ok(())
}
