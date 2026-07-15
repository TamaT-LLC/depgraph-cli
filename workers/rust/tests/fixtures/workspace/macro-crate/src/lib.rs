extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro]
pub fn fixture(_input: TokenStream) -> TokenStream {
    std::fs::write("PROC_MACRO_EXECUTED", "unsafe").unwrap();
    TokenStream::new()
}
