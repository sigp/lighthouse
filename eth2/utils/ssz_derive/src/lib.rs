extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

fn get_named_field_idents<'a>(struct_data: &'a syn::DataStruct) -> Vec<&'a syn::Ident> {
    struct_data.fields.iter().map(|f| {
        match &f.ident {
            Some(ref ident) => ident,
            _ => panic!("ssz_derive only supports named struct fields.")
        }
    }).collect()
}

#[proc_macro_derive(Encode)]
pub fn ssz_encode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs.")
    };

    let field_idents = get_named_field_idents(&struct_data);

    let output = quote! {
        impl Encodable for #name {
            fn ssz_append(&self, s: &mut SszStream) {
                #(
                    s.append(&self.#field_idents);
                )*
            }
        }
    };
    output.into()
}

#[proc_macro_derive(Decode)]
pub fn ssz_decode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs.")
    };

    let field_idents = get_named_field_idents(&struct_data);

    // Using a var in an iteration always consumes the var, therefore we must make a `fields_a` and
    // a `fields_b` in order to perform two loops.
    //
    // https://github.com/dtolnay/quote/issues/8
    let field_idents_a = &field_idents;
    let field_idents_b = &field_idents;

    let output = quote! {
        impl Decodable for #name {
            fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
                #(
                    let (#field_idents_a, i) = <_>::ssz_decode(bytes, i)?;
                )*

                Ok((
                    Self {
                        #(
                            #field_idents_b,
                        )*
                    },
                    i
                ))
            }
        }
    };
    output.into()
}
