extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Returns true if some field has an attribute declaring it should be generated from default (not
/// randomized).
///
/// The field attribute is: `#[test_random(default)]`
fn should_use_default(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path.is_ident("test_random") && attr.tts.to_string().replace(" ", "") == "(default)"
    })
}

#[proc_macro_derive(TestRandom, attributes(test_random))]
pub fn test_random_derive(input: TokenStream) -> TokenStream {
    let derived_input = parse_macro_input!(input as DeriveInput);
    let name = &derived_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derived_input.generics.split_for_impl();

    let struct_data = match &derived_input.data {
        syn::Data::Struct(s) => s,
        _ => panic!("test_random_derive only supports structs."),
    };

    // Build quotes for fields that should be generated and those that should be built from
    // `Default`.
    let mut quotes = vec![];
    for field in &struct_data.fields {
        match &field.ident {
            Some(ref ident) => {
                if should_use_default(field) {
                    quotes.push(quote! {
                        #ident: <_>::default(),
                    });
                } else {
                    quotes.push(quote! {
                        #ident: <_>::random_for_test(rng),
                    });
                }
            }
            _ => panic!("test_random_derive only supports named struct fields."),
        };
    }

    let output = quote! {
        impl #impl_generics TestRandom for #name #ty_generics #where_clause {
            fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
               Self {
                    #(
                        #quotes
                    )*
               }
            }
        }
    };

    output.into()
}
