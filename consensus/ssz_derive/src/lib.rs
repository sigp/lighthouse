#![recursion_limit = "256"]
//! Provides procedural derive macros for the `Encode` and `Decode` traits of the `eth2_ssz` crate.
//!
//! Supports field attributes, see each derive macro for more information.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Returns a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be serialized.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_serializable_named_field_idents(struct_data: &syn::DataStruct) -> Vec<&syn::Ident> {
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
fn get_serializable_field_types(struct_data: &syn::DataStruct) -> Vec<&syn::Type> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_serializing(&f) {
                None
            } else {
                Some(&f.ty)
            }
        })
        .collect()
}

/// Returns true if some field has an attribute declaring it should not be serialized.
///
/// The field attribute is: `#[ssz(skip_serializing)]`
fn should_skip_serializing(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path.is_ident("ssz")
            && attr.tokens.to_string().replace(" ", "") == "(skip_serializing)"
    })
}

/// Implements `ssz::Encode` for some `struct`.
///
/// Fields are encoded in the order they are defined.
///
/// ## Field attributes
///
/// - `#[ssz(skip_serializing)]`: the field will not be serialized.
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
    let field_idents_a = get_serializable_named_field_idents(&struct_data);
    let field_types_a = get_serializable_field_types(&struct_data);
    let field_types_b = field_types_a.clone();
    let field_types_d = field_types_a.clone();
    let field_types_e = field_types_a.clone();
    let field_types_f = field_types_a.clone();

    let output = quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                #(
                    <#field_types_a as ssz::Encode>::is_ssz_fixed_len() &&
                )*
                    true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as ssz::Encode>::is_ssz_fixed_len() {
                    let mut len: usize = 0;
                    #(
                        len = len
                            .checked_add(<#field_types_b as ssz::Encode>::ssz_fixed_len())
                            .expect("encode ssz_fixed_len length overflow");
                    )*
                    len
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn ssz_bytes_len(&self) -> usize {
                if <Self as ssz::Encode>::is_ssz_fixed_len() {
                    <Self as ssz::Encode>::ssz_fixed_len()
                } else {
                    let mut len: usize = 0;
                    #(
                        if <#field_types_d as ssz::Encode>::is_ssz_fixed_len() {
                            len = len
                                .checked_add(<#field_types_e as ssz::Encode>::ssz_fixed_len())
                                .expect("encode ssz_bytes_len length overflow");
                        } else {
                            len = len
                                .checked_add(ssz::BYTES_PER_LENGTH_OFFSET)
                                .expect("encode ssz_bytes_len length overflow for offset");
                            len = len
                                .checked_add(self.#field_idents_a.ssz_bytes_len())
                                .expect("encode ssz_bytes_len length overflow for bytes");
                        }
                    )*

                    len
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                let mut offset: usize = 0;
                #(
                    offset = offset
                        .checked_add(<#field_types_f as ssz::Encode>::ssz_fixed_len())
                        .expect("encode ssz_append offset overflow");
                )*

                let mut encoder = ssz::SszEncoder::container(buf, offset);

                #(
                    encoder.append(&self.#field_idents);
                )*

                encoder.finalize();
            }
        }
    };
    output.into()
}

/// Returns true if some field has an attribute declaring it should not be deserialized.
///
/// The field attribute is: `#[ssz(skip_deserializing)]`
fn should_skip_deserializing(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path.is_ident("ssz")
            && attr.tokens.to_string().replace(" ", "") == "(skip_deserializing)"
    })
}

/// Implements `ssz::Decode` for some `struct`.
///
/// Fields are decoded in the order they are defined.
///
/// ## Field attributes
///
/// - `#[ssz(skip_deserializing)]`: during de-serialization the field will be instantiated from a
/// `Default` implementation. The decoder will assume that the field was not serialized at all
/// (e.g., if it has been serialized, an error will be raised instead of `Default` overriding it).
#[proc_macro_derive(Decode)]
pub fn ssz_decode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("ssz_derive only supports structs."),
    };

    let mut register_types = vec![];
    let mut field_names = vec![];
    let mut fixed_decodes = vec![];
    let mut decodes = vec![];
    let mut is_fixed_lens = vec![];
    let mut fixed_lens = vec![];

    // Build quotes for fields that should be deserialized and those that should be built from
    // `Default`.
    for field in &struct_data.fields {
        match &field.ident {
            Some(ref ident) => {
                field_names.push(quote! {
                    #ident
                });

                if should_skip_deserializing(field) {
                    // Field should not be deserialized; use a `Default` impl to instantiate.
                    decodes.push(quote! {
                        let #ident = <_>::default();
                    });

                    fixed_decodes.push(quote! {
                        let #ident = <_>::default();
                    });
                } else {
                    let ty = &field.ty;

                    register_types.push(quote! {
                        builder.register_type::<#ty>()?;
                    });

                    decodes.push(quote! {
                        let #ident = decoder.decode_next()?;
                    });

                    fixed_decodes.push(quote! {
                        let #ident = decode_field!(#ty);
                    });

                    is_fixed_lens.push(quote! {
                        <#ty as ssz::Decode>::is_ssz_fixed_len()
                    });

                    fixed_lens.push(quote! {
                        <#ty as ssz::Decode>::ssz_fixed_len()
                    });
                }
            }
            _ => panic!("ssz_derive only supports named struct fields."),
        };
    }

    let output = quote! {
        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                #(
                    #is_fixed_lens &&
                )*
                    true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as ssz::Decode>::is_ssz_fixed_len() {
                    let mut len: usize = 0;
                    #(
                        len = len
                            .checked_add(#fixed_lens)
                            .expect("decode ssz_fixed_len overflow");
                    )*
                    len
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn from_ssz_bytes(bytes: &[u8]) -> std::result::Result<Self, ssz::DecodeError> {
                if <Self as ssz::Decode>::is_ssz_fixed_len() {
                    if bytes.len() != <Self as ssz::Decode>::ssz_fixed_len() {
                        return Err(ssz::DecodeError::InvalidByteLength {
                            len: bytes.len(),
                            expected: <Self as ssz::Decode>::ssz_fixed_len(),
                        });
                    }

                    let mut start: usize = 0;
                    let mut end = start;

                    macro_rules! decode_field {
                        ($type: ty) => {{
                            start = end;
                            end = end
                                .checked_add(<$type as ssz::Decode>::ssz_fixed_len())
                                .ok_or_else(|| ssz::DecodeError::OutOfBoundsByte {
                                    i: usize::max_value()
                                })?;
                            let slice = bytes.get(start..end)
                                .ok_or_else(|| ssz::DecodeError::InvalidByteLength {
                                    len: bytes.len(),
                                    expected: end
                                })?;
                            <$type as ssz::Decode>::from_ssz_bytes(slice)?
                        }};
                    }

                    #(
                        #fixed_decodes
                    )*

                    Ok(Self {
                        #(
                            #field_names,
                        )*
                    })
                } else {
                    let mut builder = ssz::SszDecoderBuilder::new(bytes);

                    #(
                        #register_types
                    )*

                    let mut decoder = builder.build()?;

                    #(
                        #decodes
                    )*


                    Ok(Self {
                        #(
                            #field_names,
                        )*
                    })
                }
            }
        }
    };
    output.into()
}
