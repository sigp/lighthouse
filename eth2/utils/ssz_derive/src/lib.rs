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

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let field_idents = get_serializable_named_field_idents(&struct_data);

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
        impl ssz::Decodable for #name {
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

/// Returns a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be tree hashed.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_tree_hashable_named_field_idents<'a>(
    struct_data: &'a syn::DataStruct,
) -> Vec<&'a syn::Ident> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_tree_hash(&f) {
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

/// Returns true if some field has an attribute declaring it should not be tree-hashed.
///
/// The field attribute is: `#[tree_hash(skip_hashing)]`
fn should_skip_tree_hash(field: &syn::Field) -> bool {
    for attr in &field.attrs {
        if attr.tts.to_string() == "( skip_hashing )" {
            return true;
        }
    }
    false
}

/// Implements `ssz::TreeHash` for some `struct`.
///
/// Fields are processed in the order they are defined.
#[proc_macro_derive(TreeHash, attributes(tree_hash))]
pub fn ssz_tree_hash_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let field_idents = get_tree_hashable_named_field_idents(&struct_data);

    let output = quote! {
        impl ssz::TreeHash for #name {
            fn hash_tree_root(&self) -> Vec<u8> {
                let mut list: Vec<Vec<u8>> = Vec::new();
                #(
                    list.push(self.#field_idents.hash_tree_root());
                )*

                ssz::merkle_hash(&mut list)
            }
        }
    };
    output.into()
}

/// Returns `true` if some `Ident` should be considered to be a signature type.
fn type_ident_is_signature(ident: &syn::Ident) -> bool {
    match ident.to_string().as_ref() {
        "Signature" => true,
        "AggregateSignature" => true,
        _ => false,
    }
}

/// Takes a `Field` where the type (`ty`) portion is a path (e.g., `types::Signature`) and returns
/// the final `Ident` in that path.
///
/// E.g., for `types::Signature` returns `Signature`.
fn final_type_ident(field: &syn::Field) -> &syn::Ident {
    match &field.ty {
        syn::Type::Path(path) => &path.path.segments.last().unwrap().value().ident,
        _ => panic!("ssz_derive only supports Path types."),
    }
}

/// Implements `ssz::TreeHash` for some `struct`, whilst excluding any fields following and
/// including a field that is of type "Signature" or "AggregateSignature".
///
/// See:
/// https://github.com/ethereum/eth2.0-specs/blob/master/specs/simple-serialize.md#signed-roots
///
/// This is a rather horrendous macro, it will read the type of the object as a string and decide
/// if it's a signature by matching that string against "Signature" or "AggregateSignature". So,
/// it's important that you use those exact words as your type -- don't alias it to something else.
///
/// If you can think of a better way to do this, please make an issue!
///
/// Fields are processed in the order they are defined.
#[proc_macro_derive(SignedRoot)]
pub fn ssz_signed_root_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let mut field_idents: Vec<&syn::Ident> = vec![];

    for field in struct_data.fields.iter() {
        let final_type_ident = final_type_ident(&field);

        if type_ident_is_signature(final_type_ident) {
            break;
        } else {
            let ident = field
                .ident
                .as_ref()
                .expect("ssz_derive only supports named_struct fields.");
            field_idents.push(ident);
        }
    }

    let output = quote! {
        impl ssz::SignedRoot for #name {
            fn signed_root(&self) -> Vec<u8> {
                let mut list: Vec<Vec<u8>> = Vec::new();
                #(
                    list.push(self.#field_idents.hash_tree_root());
                )*

                ssz::merkle_hash(&mut list)
            }
        }
    };
    output.into()
}
