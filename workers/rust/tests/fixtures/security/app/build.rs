fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("fixture app has a workspace parent");
    std::fs::write(root.join("BUILD_SCRIPT_EXECUTED"), "unsafe").unwrap();
}
