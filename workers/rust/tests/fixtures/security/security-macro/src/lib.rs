extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro]
pub fn touch(_input: TokenStream) -> TokenStream {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("fixture macro has a workspace parent");
    std::fs::write(root.join("PROC_MACRO_EXECUTED"), "unsafe").unwrap();
    "const _: () = ();".parse().unwrap()
}
