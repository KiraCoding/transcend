use proc_macro::TokenStream;
use quote::quote;

#[proc_macro]
pub fn sig(input: TokenStream) -> TokenStream {
    let input = input.to_string().replace("??", "FF");

    let bytes: Vec<u8> = input
        .split_ascii_whitespace()
        .map(|hex| u8::from_str_radix(hex, 16).unwrap())
        .collect();

    quote! {
        &[#(#bytes),*]
    }
    .into()
}
