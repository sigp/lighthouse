//! Provides the following procedural derive macros:
//!
//! - `#[derive(Encode)]`
//! - `#[derive(Decode)]`
//! - `#[derive(TreeHash)]`
//!
//! These macros provide SSZ encoding/decoding for a `struct`. Fields are encoded/decoded in the
//! order they are defined.
//!
//! Presently, only `structs` with named fields are supported. `enum`s and tuple-structs are
//! unsupported.
//!
//! Example:
//! ```
//! use ssz::{ssz_encode, Decodable};
//! use ssz_derive::{Encode, Decode};
//!
//! #[derive(Encode, Decode)]
//! struct Foo {
//!     pub bar: bool,
//!     pub baz: u64,
//! }
//!
//! fn main() {
//!     let foo = Foo {
//!         bar: true,
//!         baz: 42,
//!     };
//!
//!     let bytes = ssz_encode(&foo);
//!
//!     let (decoded_foo, _i) = Foo::ssz_decode(&bytes, 0).unwrap();
//!
//!     assert_eq!(foo.baz, decoded_foo.baz);
//! }
//! ```

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Returns a Vec of `syn::Ident` for each named field in the struct.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_named_field_idents<'a>(struct_data: &'a syn::DataStruct) -> Vec<&'a syn::Ident> {
    struct_data
        .fields
        .iter()
        .map(|f| match &f.ident {
            Some(ref ident) => ident,
            _ => panic!("ssz_derive only supports named struct fields."),
        })
        .collect()
}

/// Implements `ssz::Encodable` for some `struct`.
///
/// Fields are encoded in the order they are defined.
#[proc_macro_derive(Encode)]
pub fn ssz_encode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let field_idents = get_named_field_idents(&struct_data);

    let output = quote! {
        impl ssz::Encodable for #name {
            fn ssz_append(&self, s: &mut ssz::SszStream) {
                #(
                    s.append(&self.#field_idents);
                )*
            }
        }
    };
    output.into()
}

/// Implements `ssz::Decodable` for some `struct`.
///
/// Fields are decoded in the order they are defined.
#[proc_macro_derive(Decode)]
pub fn ssz_decode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let field_idents = get_named_field_idents(&struct_data);

    // Using a var in an iteration always consumes the var, therefore we must make a `fields_a` and
    // a `fields_b` in order to perform two loops.
    //
    // https://github.com/dtolnay/quote/issues/8
    let field_idents_a = &field_idents;
    let field_idents_b = &field_idents;

    let output = quote! {
        impl ssz::Decodable for #name {
            fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), ssz::DecodeError> {
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

/// Implements `ssz::TreeHash` for some `struct`.
///
/// Fields are processed in the order they are defined.
#[proc_macro_derive(TreeHash)]
pub fn ssz_tree_hash_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let field_idents = get_named_field_idents(&struct_data);

    let output = quote! {
        impl ssz::TreeHash for #name {
            fn hash_tree_root_internal(&self) -> Vec<u8> {
                let mut list: Vec<Vec<u8>> = Vec::new();
                #(
                    list.push(self.#field_idents.hash_tree_root_internal());
                )*

                ssz::merkle_hash(&mut list)
            }
        }
    };
    output.into()
}
