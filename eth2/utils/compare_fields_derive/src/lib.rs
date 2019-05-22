#![recursion_limit = "256"]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(CompareFields)]
pub fn compare_fields_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("compare_fields_derive only supports structs."),
    };

    let mut idents_a = vec![];
    let mut field_names = vec![];

    for field in struct_data.fields.iter() {
        let ident = match &field.ident {
            Some(ref ident) => ident,
            _ => panic!("compare_fields_derive only supports named struct fields."),
        };

        field_names.push(format!("{:}", ident));
        idents_a.push(ident);
    }

    let idents_b = idents_a.clone();
    let idents_c = idents_a.clone();
    let idents_d = idents_a.clone();

    let output = quote! {
        impl #impl_generics compare_fields::CompareFields for #name #ty_generics #where_clause {
            fn compare_fields(&self, b: &Self) -> Vec<compare_fields::FieldComparison> {
                let mut comparisons = vec![];

                #(
                    comparisons.push(
                        compare_fields::FieldComparison {
                            equal: self.#idents_a == b.#idents_b,
                            field_name: #field_names.to_string(),
                            a: format!("{:?}", self.#idents_c),
                            b: format!("{:?}", b.#idents_d),
                        }
                    );
                )*

                comparisons
            }
        }
    };
    output.into()
}
