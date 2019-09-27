#![recursion_limit = "256"]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

fn is_slice(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path.is_ident("compare_fields")
            && attr.tts.to_string().replace(" ", "") == "(as_slice)"
    })
}

#[proc_macro_derive(CompareFields, attributes(compare_fields))]
pub fn compare_fields_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("compare_fields_derive only supports structs."),
    };

    let mut quotes = vec![];

    for field in struct_data.fields.iter() {
        let ident_a = match &field.ident {
            Some(ref ident) => ident,
            _ => panic!("compare_fields_derive only supports named struct fields."),
        };

        let field_name = format!("{:}", ident_a);
        let ident_b = ident_a.clone();

        let quote = if is_slice(field) {
            quote! {
                comparisons.push(compare_fields::Comparison::from_slice(
                        #field_name.to_string(),
                        &self.#ident_a,
                        &b.#ident_b)
                );
            }
        } else {
            quote! {
                comparisons.push(
                    compare_fields::Comparison::child(
                        #field_name.to_string(),
                        &self.#ident_a,
                        &b.#ident_b
                    )
                );
            }
        };

        quotes.push(quote);
    }

    let output = quote! {
        impl #impl_generics compare_fields::CompareFields for #name #ty_generics #where_clause {
            fn compare_fields(&self, b: &Self) -> Vec<compare_fields::Comparison> {
                let mut comparisons = vec![];

                #(
                    #quotes
                )*

                comparisons
            }
        }
    };
    output.into()
}
