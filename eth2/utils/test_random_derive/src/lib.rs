extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn;
use syn::DeriveInput;

#[proc_macro_derive(TestRandom)]
pub fn test_random_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();

    impl_test_random(&ast)
}

fn impl_test_random(ast: &DeriveInput) -> TokenStream {}
