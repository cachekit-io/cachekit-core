fn main() {
    // Only generate C headers when ffi feature is enabled
    if std::env::var("CARGO_FEATURE_FFI").is_ok() {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let output_file = std::path::PathBuf::from(&crate_dir)
            .join("include")
            .join("cachekit.h");

        // Ensure include directory exists
        std::fs::create_dir_all(output_file.parent().unwrap()).ok();

        // Build configuration with features
        let mut config = cbindgen::Config::from_file("cbindgen.toml").unwrap();

        // Set default includes
        if config.sys_includes.is_empty() {
            config.sys_includes = vec![
                "stdint.h".to_string(),
                "stddef.h".to_string(),
                "stdbool.h".to_string(),
            ];
        }

        // Run cbindgen
        let result = cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(config)
            .generate();

        match result {
            Ok(bindings) => {
                let _ = bindings.write_to_file(&output_file);
            }
            Err(e) => {
                eprintln!("Warning: cbindgen failed: {}", e);
                // Don't fail the build, just warn
            }
        }
    }

    // Rerun if FFI source files change
    println!("cargo:rerun-if-changed=src/ffi/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
