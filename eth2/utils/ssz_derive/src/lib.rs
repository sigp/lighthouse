#![recursion_limit="128"]

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

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

/// Returns a Vec of `syn::Type` for each named field in the struct, whilst filtering out fields
/// that should not be serialized.
fn get_serializable_field_types<'a>(struct_data: &'a syn::DataStruct) -> Vec<&'a syn::Type> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_serializing(&f) {
                None
            } else {
                Some(&f.ty)
                /*
                Some(match &f.ident {
                    Some(ref ident) => ident,
                    _ => panic!("ssz_derive only supports named struct fields."),
                })
                */
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
    let field_types_a = get_serializable_field_types(&struct_data);
    let field_types_b = field_types_a.clone();

    let output = quote! {
        impl ssz::Encodable for #name {
            fn is_ssz_fixed_len() -> bool {
                #(
                    <#field_types_a as ssz::Encodable>::is_ssz_fixed_len() &&
                )*
                    true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as Encodable>::is_ssz_fixed_len() {
                    #(
                        <#field_types_b as ssz::Encodable>::ssz_fixed_len() +
                    )*
                        0
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn as_ssz_bytes(&self) -> Vec<u8> {
                let mut stream = ssz::SszStream::new();

                #(
                    stream.append(&self.#field_idents);
                )*

                stream.drain()
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

    let mut register_types = vec![];
    let mut decodes = vec![];
    let mut is_fixed_lens = vec![];
    let mut fixed_lens = vec![];

    // Build quotes for fields that should be deserialized and those that should be built from
    // `Default`.
    for field in &struct_data.fields {
        match &field.ident {
            Some(ref ident) => {
                if should_skip_deserializing(field) {
                    // Field should not be deserialized; use a `Default` impl to instantiate.
                    decodes.push(quote! {
                        #ident: <_>::default(),
                    });
                } else {
                    let ty = &field.ty;

                    register_types.push(quote! {
                        builder.register_type::<#ty>()?;
                    });

                    decodes.push(quote! {
                        #ident: decoder.decode_next()?
                    });

                    is_fixed_lens.push(quote! {
                        <#ty as ssz::Decodable>::is_ssz_fixed_len()
                    });

                    fixed_lens.push(quote! {
                        <#ty as ssz::Decodable>::ssz_fixed_len()
                    });
                }
            }
            _ => panic!("ssz_derive only supports named struct fields."),
        };
    }

    let output = quote! {
        impl ssz::Decodable for #name {
            fn is_ssz_fixed_len() -> bool {
                #(
                    #is_fixed_lens &&
                )*
                    true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as ssz::Decodable>::is_ssz_fixed_len() {
                    #(
                        #fixed_lens +
                    )*
                        0
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                let mut builder = ssz::SszDecoderBuilder::new(bytes);

                #(
                    #register_types
                )*

                let mut decoder = builder.build()?;

                Ok(Self {
                    #(
                        #decodes,
                    )*
                })
            }
        }
    };
    output.into()
}
