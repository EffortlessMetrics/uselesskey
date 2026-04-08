use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=uselesskey-fixtures.toml");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let manifest_path = manifest_dir.join("uselesskey-fixtures.toml");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("out dir"));
    let module_path = out_dir.join("fixtures.rs");

    let manifest =
        uselesskey_cli::load_materialize_manifest(&manifest_path).expect("materialize manifest");
    uselesskey_cli::materialize_manifest_to_dir(&manifest, &out_dir, false)
        .expect("materialize fixtures");
    uselesskey_cli::emit_include_bytes_module(&manifest, &out_dir, &module_path)
        .expect("emit include_bytes module");
}
