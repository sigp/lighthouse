#![recursion_limit = "256"]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
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
fn get_cache_field_for(field: &syn::Field) -> Option<syn::Ident> {
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
