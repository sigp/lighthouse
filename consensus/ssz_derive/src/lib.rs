#![recursion_limit = "256"]
//! Provides procedural derive macros for the `Encode` and `Decode` traits of the `eth2_ssz` crate.
//!
//! Supports field attributes, see each derive macro for more information.

use darling::FromDeriveInput;
use proc_macro::TokenStream;
use quote::quote;
use std::convert::TryInto;
use syn::{parse_macro_input, DataEnum, DataStruct, DeriveInput};

/// The highest possible union selector value (higher values are reserved for backwards compatible
/// extensions).
const MAX_UNION_SELECTOR: u8 = 127;

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(ssz))]
struct StructOpts {
    #[darling(default)]
    enum_behaviour: Option<String>,
}

const ENUM_TRANSPARENT: &str = "transparent";
const ENUM_UNION: &str = "union";
const ENUM_VARIANTS: &[&str] = &[ENUM_TRANSPARENT, ENUM_UNION];
const NO_ENUM_BEHAVIOUR_ERROR: &str = "enums require an \"enum_behaviour\" attribute, \
    e.g., #[ssz(enum_behaviour = \"transparent\")]";

enum EnumBehaviour {
    Transparent,
    Union,
}

impl EnumBehaviour {
    pub fn new(s: Option<String>) -> Option<Self> {
        s.map(|s| match s.as_ref() {
            ENUM_TRANSPARENT => EnumBehaviour::Transparent,
            ENUM_UNION => EnumBehaviour::Union,
            other => panic!(
                "{} is an invalid enum_behaviour, use either {:?}",
                other, ENUM_VARIANTS
            ),
        })
    }
}

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
            if should_skip_serializing(f) {
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
            if should_skip_serializing(f) {
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

/// Implements `ssz::Encode` for some `struct` or `enum`.
#[proc_macro_derive(Encode, attributes(ssz))]
pub fn ssz_encode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let opts = StructOpts::from_derive_input(&item).unwrap();
    let enum_opt = EnumBehaviour::new(opts.enum_behaviour);

    match &item.data {
        syn::Data::Struct(s) => {
            if enum_opt.is_some() {
                panic!("enum_behaviour is invalid for structs");
            }
            ssz_encode_derive_struct(&item, s)
        }
        syn::Data::Enum(s) => match enum_opt.expect(NO_ENUM_BEHAVIOUR_ERROR) {
            EnumBehaviour::Transparent => ssz_encode_derive_enum_transparent(&item, s),
            EnumBehaviour::Union => ssz_encode_derive_enum_union(&item, s),
        },
        _ => panic!("ssz_derive only supports structs and enums"),
    }
}

/// Derive `ssz::Encode` for a struct.
///
/// Fields are encoded in the order they are defined.
///
/// ## Field attributes
///
/// - `#[ssz(skip_serializing)]`: the field will not be serialized.
fn ssz_encode_derive_struct(derive_input: &DeriveInput, struct_data: &DataStruct) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let field_idents = get_serializable_named_field_idents(struct_data);
    let field_idents_a = get_serializable_named_field_idents(struct_data);
    let field_types_a = get_serializable_field_types(struct_data);
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

/// Derive `ssz::Encode` for an enum in the "transparent" method.
///
/// The "transparent" method is distinct from the "union" method specified in the SSZ specification.
/// When using "transparent", the enum will be ignored and the contained field will be serialized as
/// if the enum does not exist. Since an union variant "selector" is not serialized, it is not
/// possible to reliably decode an enum that is serialized transparently.
///
/// ## Limitations
///
/// Only supports:
/// - Enums with a single field per variant, where
///     - All fields are variably sized from an SSZ-perspective (not fixed size).
///
/// ## Panics
///
/// Will panic at compile-time if the single field requirement isn't met, but will panic *at run
/// time* if the variable-size requirement isn't met.
fn ssz_encode_derive_enum_transparent(
    derive_input: &DeriveInput,
    enum_data: &DataEnum,
) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let (patterns, assert_exprs): (Vec<_>, Vec<_>) = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("ssz::Encode can only be derived for enums with 1 field per variant");
            }

            let pattern = quote! {
                #name::#variant_name(ref inner)
            };

            let ty = &(&variant.fields).into_iter().next().unwrap().ty;
            let type_assert = quote! {
                !<#ty as ssz::Encode>::is_ssz_fixed_len()
            };
            (pattern, type_assert)
        })
        .unzip();

    let output = quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                assert!(
                    #(
                        #assert_exprs &&
                    )* true,
                    "not all enum variants are variably-sized"
                );
                false
            }

            fn ssz_bytes_len(&self) -> usize {
                match self {
                    #(
                        #patterns => inner.ssz_bytes_len(),
                    )*
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                match self {
                    #(
                        #patterns => inner.ssz_append(buf),
                    )*
                }
            }
        }
    };
    output.into()
}

/// Derive `ssz::Encode` for an `enum` following the "union" SSZ spec.
///
/// The union selector will be determined based upon the order in which the enum variants are
/// defined. E.g., the top-most variant in the enum will have a selector of `0`, the variant
/// beneath it will have a selector of `1` and so on.
///
/// # Limitations
///
/// Only supports enums where each variant has a single field.
fn ssz_encode_derive_enum_union(derive_input: &DeriveInput, enum_data: &DataEnum) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let patterns: Vec<_> = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("ssz::Encode can only be derived for enums with 1 field per variant");
            }

            let pattern = quote! {
                #name::#variant_name(ref inner)
            };
            pattern
        })
        .collect();

    let union_selectors = compute_union_selectors(patterns.len());

    let output = quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn ssz_bytes_len(&self) -> usize {
                match self {
                    #(
                        #patterns => inner.ssz_bytes_len() + 1,
                    )*
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                match self {
                    #(
                        #patterns => {
                            let union_selector: u8 = #union_selectors;
                            debug_assert!(union_selector <= ssz::MAX_UNION_SELECTOR);
                            buf.push(union_selector);
                            inner.ssz_append(buf)
                        },
                    )*
                }
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

/// Derive `ssz::Decode` for a struct or enum.
#[proc_macro_derive(Decode, attributes(ssz))]
pub fn ssz_decode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let opts = StructOpts::from_derive_input(&item).unwrap();
    let enum_opt = EnumBehaviour::new(opts.enum_behaviour);

    match &item.data {
        syn::Data::Struct(s) => {
            if enum_opt.is_some() {
                panic!("enum_behaviour is invalid for structs");
            }
            ssz_decode_derive_struct(&item, s)
        }
        syn::Data::Enum(s) => match enum_opt.expect(NO_ENUM_BEHAVIOUR_ERROR) {
            EnumBehaviour::Transparent => panic!(
                "Decode cannot be derived for enum_behaviour \"{}\", only \"{}\" is valid.",
                ENUM_TRANSPARENT, ENUM_UNION
            ),
            EnumBehaviour::Union => ssz_decode_derive_enum_union(&item, s),
        },
        _ => panic!("ssz_derive only supports structs and enums"),
    }
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
fn ssz_decode_derive_struct(item: &DeriveInput, struct_data: &DataStruct) -> TokenStream {
    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

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

/// Derive `ssz::Decode` for an `enum` following the "union" SSZ spec.
fn ssz_decode_derive_enum_union(derive_input: &DeriveInput, enum_data: &DataEnum) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let (constructors, var_types): (Vec<_>, Vec<_>) = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("ssz::Encode can only be derived for enums with 1 field per variant");
            }

            let constructor = quote! {
                #name::#variant_name
            };

            let ty = &(&variant.fields).into_iter().next().unwrap().ty;
            (constructor, ty)
        })
        .unzip();

    let union_selectors = compute_union_selectors(constructors.len());

    let output = quote! {
        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                // Sanity check to ensure the definition here does not drift from the one defined in
                // `ssz`.
                debug_assert_eq!(#MAX_UNION_SELECTOR, ssz::MAX_UNION_SELECTOR);

                let (selector, body) = ssz::split_union_bytes(bytes)?;

                match selector.into() {
                    #(
                        #union_selectors => {
                            #var_types::from_ssz_bytes(body).map(#constructors)
                        },
                    )*
                    other => Err(ssz::DecodeError::UnionSelectorInvalid(other))
                }
            }
        }
    };
    output.into()
}

fn compute_union_selectors(num_variants: usize) -> Vec<u8> {
    let union_selectors = (0..num_variants)
        .map(|i| {
            i.try_into()
                .expect("union selector exceeds u8::max_value, union has too many variants")
        })
        .collect::<Vec<u8>>();

    let highest_selector = union_selectors
        .last()
        .copied()
        .expect("0-variant union is not permitted");

    assert!(
        highest_selector <= MAX_UNION_SELECTOR,
        "union selector {} exceeds limit of {}, enum has too many variants",
        highest_selector,
        MAX_UNION_SELECTOR
    );

    union_selectors
}
