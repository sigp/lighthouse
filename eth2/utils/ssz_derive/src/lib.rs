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

/// Returns a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be serialized.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_serializable_named_field_idents<'a>(
    struct_data: &'a syn::DataStruct,
) -> Vec<&'a syn::Ident> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_serializing(&f) {
                None
            } else {
                Some(match &f.ident {
                    Some(ref ident) => ident,
                    _ => panic!("ssz_derive only supports named struct fields."),
                })
            }
        })
        .collect()
}

/// Returns true if some field has an attribute declaring it should not be serialized.
///
/// The field attribute is: `#[ssz(skip_serializing)]`
fn should_skip_serializing(field: &syn::Field) -> bool {
    for attr in &field.attrs {
        if attr.tts.to_string() == "( skip_serializing )" {
            return true;
        }
    }
    false
}

/// Implements `ssz::Encodable` for some `struct`.
///
/// Fields are encoded in the order they are defined.
#[proc_macro_derive(Encode, attributes(ssz))]
pub fn ssz_encode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let field_idents = get_serializable_named_field_idents(&struct_data);

    let output = quote! {
        impl #impl_generics ssz::Encodable for #name #ty_generics #where_clause {
            fn ssz_append(&self, s: &mut ssz::SszStream) {
                #(
                    s.append(&self.#field_idents);
                )*
            }
        }
    };
    output.into()
}

/// Returns true if some field has an attribute declaring it should not be deserialized.
///
/// The field attribute is: `#[ssz(skip_deserializing)]`
fn should_skip_deserializing(field: &syn::Field) -> bool {
    for attr in &field.attrs {
        if attr.tts.to_string() == "( skip_deserializing )" {
            return true;
        }
    }
    false
}

/// Implements `ssz::Decodable` for some `struct`.
///
/// Fields are decoded in the order they are defined.
#[proc_macro_derive(Decode)]
pub fn ssz_decode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let all_idents = get_named_field_idents(&struct_data);

    // Build quotes for fields that should be deserialized and those that should be built from
    // `Default`.
    let mut quotes = vec![];
    for field in &struct_data.fields {
        match &field.ident {
            Some(ref ident) => {
                if should_skip_deserializing(field) {
                    quotes.push(quote! {
                        let #ident = <_>::default();
                    });
                } else {
                    quotes.push(quote! {
                        let (#ident, i) = <_>::ssz_decode(bytes, i)?;
                    });
                }
            }
            _ => panic!("ssz_derive only supports named struct fields."),
        };
    }

    let output = quote! {
        impl #impl_generics ssz::Decodable for #name #ty_generics #where_clause {
            fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), ssz::DecodeError> {
                #(
                    #quotes
                )*

                Ok((
                    Self {
                        #(
                            #all_idents,
                        )*
                    },
                    i
                ))
            }
        }
    };
    output.into()
}
