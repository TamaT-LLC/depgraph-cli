fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("observed.rs"), b"pub const OBSERVED: bool = true;\n").unwrap();
    let secret = ["RUST", "BUILD", "FIXTURE", "SECRET"].join("_");
    println!("cargo:rustc-env=API_TOKEN={secret}");
}
