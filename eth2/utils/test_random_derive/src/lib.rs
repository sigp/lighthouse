extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(TestRandom)]
pub fn test_random_derive(input: TokenStream) -> TokenStream {
    let derived_input = parse_macro_input!(input as DeriveInput);
    let name = &derived_input.ident;

    let struct_data = match &derived_input.data {
        syn::Data::Struct(s) => s,
        _ => panic!("test_random_derive only supports structs."),
    };

    let field_names = get_named_field_idents(&struct_data);

    let output = quote! {
        impl<T: RngCore> TestRandom<T> for #name {
            fn random_for_test(rng: &mut T) -> Self {
               Self {
                    #(
                        #field_names: <_>::random_for_test(rng),
                    )*
               }
            }
        }
    };

    output.into()
}

fn get_named_field_idents(struct_data: &syn::DataStruct) -> Vec<(&syn::Ident)> {
    struct_data
        .fields
        .iter()
        .map(|f| match &f.ident {
            Some(ref ident) => ident,
            _ => panic!("test_random_derive only supports named struct fields."),
        })
        .collect()
}
