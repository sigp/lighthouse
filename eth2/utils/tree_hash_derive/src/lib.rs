#![recursion_limit = "256"]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use std::collections::HashMap;
use syn::{parse_macro_input, Attribute, DeriveInput, Meta};

/// Return a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be hashed.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_hashable_fields<'a>(struct_data: &'a syn::DataStruct) -> Vec<&'a syn::Ident> {
    get_hashable_fields_and_their_caches(struct_data)
        .into_iter()
        .map(|(ident, _, _)| ident)
        .collect()
}

/// Return a Vec of the hashable fields of a struct, and each field's type and optional cache field.
fn get_hashable_fields_and_their_caches<'a>(
    struct_data: &'a syn::DataStruct,
) -> Vec<(&'a syn::Ident, syn::Type, Option<syn::Ident>)> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_hashing(&f) {
                None
            } else {
                let ident = f
                    .ident
                    .as_ref()
                    .expect("tree_hash_derive only supports named struct fields");
                let opt_cache_field = get_cache_field_for(&f);
                Some((ident, f.ty.clone(), opt_cache_field))
            }
        })
        .collect()
}

/// Parse the cached_tree_hash attribute for a field.
///
/// Extract the cache field name from `#[cached_tree_hash(cache_field_name)]`
///
/// Return `Some(cache_field_name)` if the field has a cached tree hash attribute,
/// or `None` otherwise.
fn get_cache_field_for<'a>(field: &'a syn::Field) -> Option<syn::Ident> {
    use syn::{MetaList, NestedMeta};

    let parsed_attrs = cached_tree_hash_attr_metas(&field.attrs);
    if let [Meta::List(MetaList { nested, .. })] = &parsed_attrs[..] {
        nested.iter().find_map(|x| match x {
            NestedMeta::Meta(Meta::Word(cache_field_ident)) => Some(cache_field_ident.clone()),
            _ => None,
        })
    } else {
        None
    }
}

/// Process the `cached_tree_hash` attributes from a list of attributes into structured `Meta`s.
fn cached_tree_hash_attr_metas(attrs: &[Attribute]) -> Vec<Meta> {
    attrs
        .iter()
        .filter(|attr| attr.path.is_ident("cached_tree_hash"))
        .flat_map(|attr| attr.parse_meta())
        .collect()
}

/// Parse the top-level cached_tree_hash struct attribute.
///
/// Return the type from `#[cached_tree_hash(type = "T")]`.
///
/// **Panics** if the attribute is missing or the type is malformed.
fn parse_cached_tree_hash_struct_attrs(attrs: &[Attribute]) -> syn::Type {
    use syn::{Lit, MetaList, MetaNameValue, NestedMeta};

    let parsed_attrs = cached_tree_hash_attr_metas(attrs);
    if let [Meta::List(MetaList { nested, .. })] = &parsed_attrs[..] {
        let eqns = nested
            .iter()
            .flat_map(|x| match x {
                NestedMeta::Meta(Meta::NameValue(MetaNameValue {
                    ident,
                    lit: Lit::Str(lit_str),
                    ..
                })) => Some((ident.to_string(), lit_str.clone())),
                _ => None,
            })
            .collect::<HashMap<_, _>>();

        eqns["type"]
            .clone()
            .parse()
            .expect("valid type required for cache")
    } else {
        panic!("missing attribute `#[cached_tree_hash(type = ...)` on struct");
    }
}

/// Returns true if some field has an attribute declaring it should not be hashed.
///
/// The field attribute is: `#[tree_hash(skip_hashing)]`
fn should_skip_hashing(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path.is_ident("tree_hash") && attr.tts.to_string().replace(" ", "") == "(skip_hashing)"
    })
}

/// Implements `tree_hash::TreeHash` for some `struct`.
///
/// Fields are hashed in the order they are defined.
#[proc_macro_derive(TreeHash, attributes(tree_hash))]
pub fn tree_hash_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("tree_hash_derive only supports structs."),
    };

    let idents = get_hashable_fields(&struct_data);

    let output = quote! {
        impl #impl_generics tree_hash::TreeHash for #name #ty_generics #where_clause {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::Container
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("Struct should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Struct should never be packed.")
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                let mut leaves = Vec::with_capacity(4 * tree_hash::HASHSIZE);

                #(
                    leaves.append(&mut self.#idents.tree_hash_root());
                )*

                tree_hash::merkle_root(&leaves, 0)
            }
        }
    };
    output.into()
}

#[proc_macro_derive(SignedRoot, attributes(signed_root))]
pub fn tree_hash_signed_root_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("tree_hash_derive only supports structs."),
    };

    let idents = get_signed_root_named_field_idents(&struct_data);
    let num_elems = idents.len();

    let output = quote! {
        impl #impl_generics tree_hash::SignedRoot for #name #ty_generics #where_clause {
            fn signed_root(&self) -> Vec<u8> {
                let mut leaves = Vec::with_capacity(#num_elems * tree_hash::HASHSIZE);

                #(
                    leaves.append(&mut self.#idents.tree_hash_root());
                )*

                tree_hash::merkle_root(&leaves, 0)
            }
        }
    };
    output.into()
}

/// Derive the `CachedTreeHash` trait for a type.
///
/// Requires two attributes:
/// * `#[cached_tree_hash(type = "T")]` on the struct, declaring
///   that the type `T` should be used as the tree hash cache.
/// * `#[cached_tree_hash(f)]` on each struct field that makes use
///   of the cache, which declares that the sub-cache for that field
///   can be found in the field `cache.f` of the struct's cache.
#[proc_macro_derive(CachedTreeHash, attributes(cached_tree_hash))]
pub fn cached_tree_hash_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let cache_type = parse_cached_tree_hash_struct_attrs(&item.attrs);

    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("tree_hash_derive only supports structs."),
    };

    let fields = get_hashable_fields_and_their_caches(&struct_data);
    let caching_field_ty = fields
        .iter()
        .filter(|(_, _, cache_field)| cache_field.is_some())
        .map(|(_, ty, _)| ty);
    let caching_field_cache_field = fields
        .iter()
        .flat_map(|(_, _, cache_field)| cache_field.as_ref());

    let tree_hash_root_expr = fields
        .iter()
        .map(|(field, _, caching_field)| match caching_field {
            None => quote! {
                self.#field.tree_hash_root()
            },
            Some(caching_field) => quote! {
                self.#field
                    .recalculate_tree_hash_root(&mut cache.#caching_field)?
                    .as_bytes()
                    .to_vec()
            },
        });

    let output = quote! {
        impl #impl_generics cached_tree_hash::CachedTreeHash<#cache_type> for #name #ty_generics #where_clause {
            fn new_tree_hash_cache() -> #cache_type {
                // Call new cache for each sub type
                #cache_type {
                    initialized: true,
                    #(
                        #caching_field_cache_field: <#caching_field_ty>::new_tree_hash_cache()
                    ),*
                }
            }

            fn recalculate_tree_hash_root(
                &self,
                cache: &mut #cache_type)
            -> std::result::Result<Hash256, cached_tree_hash::Error>
            {
                let mut leaves = vec![];

                #(
                    leaves.append(&mut #tree_hash_root_expr);
                )*

                Ok(Hash256::from_slice(&tree_hash::merkle_root(&leaves, 0)))
            }
        }
    };
    output.into()
}

fn get_signed_root_named_field_idents(struct_data: &syn::DataStruct) -> Vec<&syn::Ident> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_signed_root(&f) {
                None
            } else {
                Some(match &f.ident {
                    Some(ref ident) => ident,
                    _ => panic!("tree_hash_derive only supports named struct fields"),
                })
            }
        })
        .collect()
}

fn should_skip_signed_root(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path.is_ident("signed_root")
            && attr.tts.to_string().replace(" ", "") == "(skip_hashing)"
    })
}
