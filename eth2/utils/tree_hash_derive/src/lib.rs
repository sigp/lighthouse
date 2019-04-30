#![recursion_limit = "256"]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, DeriveInput};

/// Returns a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be hashed.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_hashable_named_field_idents<'a>(struct_data: &'a syn::DataStruct) -> Vec<&'a syn::Ident> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_hashing(&f) {
                None
            } else {
                Some(match &f.ident {
                    Some(ref ident) => ident,
                    _ => panic!("tree_hash_derive only supports named struct fields."),
                })
            }
        })
        .collect()
}

/// Returns true if some field has an attribute declaring it should not be hashedd.
///
/// The field attribute is: `#[tree_hash(skip_hashing)]`
fn should_skip_hashing(field: &syn::Field) -> bool {
    field
        .attrs
        .iter()
        .any(|attr| attr.into_token_stream().to_string() == "# [ tree_hash ( skip_hashing ) ]")
}

/// Implements `tree_hash::CachedTreeHash` for some `struct`.
///
/// Fields are hashed in the order they are defined.
#[proc_macro_derive(CachedTreeHash, attributes(tree_hash))]
pub fn subtree_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("tree_hash_derive only supports structs."),
    };

    let idents_a = get_hashable_named_field_idents(&struct_data);
    let idents_b = idents_a.clone();
    let idents_c = idents_a.clone();

    let output = quote! {
        impl cached_tree_hash::CachedTreeHash for #name {
            fn new_tree_hash_cache(&self, depth: usize) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
                let tree = cached_tree_hash::TreeHashCache::from_subtrees(
                    self,
                    vec![
                        #(
                            self.#idents_a.new_tree_hash_cache(depth)?,
                        )*
                    ],
                    depth
                )?;

                Ok(tree)
            }

            fn num_tree_hash_cache_chunks(&self) -> usize {
                cached_tree_hash::BTreeOverlay::new(self, 0, 0).num_chunks()
            }

            fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
                let mut lengths = vec![];

                #(
                    lengths.push(self.#idents_b.num_tree_hash_cache_chunks());
                )*

                cached_tree_hash::BTreeSchema::from_lengths(depth, lengths)
            }

            fn update_tree_hash_cache(&self, cache: &mut cached_tree_hash::TreeHashCache) -> Result<(), cached_tree_hash::Error> {
                let overlay = cached_tree_hash::BTreeOverlay::new(self, cache.chunk_index, 0);


                // Skip the chunk index to the first leaf node of this struct.
                cache.chunk_index = overlay.first_leaf_node();
                // Skip the overlay index to the first leaf node of this struct.
                // cache.overlay_index += 1;

                // Recurse into the struct items, updating their caches.
                #(
                    self.#idents_c.update_tree_hash_cache(cache)?;
                )*

                // Iterate through the internal nodes, updating them if their children have changed.
                cache.update_internal_nodes(&overlay)?;

                cache.chunk_index = overlay.next_node();

                Ok(())
            }
        }
    };
    output.into()
}

/// Implements `tree_hash::TreeHash` for some `struct`.
///
/// Fields are hashed in the order they are defined.
#[proc_macro_derive(TreeHash, attributes(tree_hash))]
pub fn tree_hash_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("tree_hash_derive only supports structs."),
    };

    let idents = get_hashable_named_field_idents(&struct_data);

    let output = quote! {
        impl tree_hash::TreeHash for #name {
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

                tree_hash::merkleize::merkle_root(&leaves)
            }
        }
    };
    output.into()
}

#[proc_macro_derive(SignedRoot, attributes(signed_root))]
pub fn tree_hash_signed_root_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("tree_hash_derive only supports structs."),
    };

    let idents = get_signed_root_named_field_idents(&struct_data);
    let num_elems = idents.len();

    let output = quote! {
        impl tree_hash::SignedRoot for #name {
            fn signed_root(&self) -> Vec<u8> {
                let mut leaves = Vec::with_capacity(#num_elems * tree_hash::HASHSIZE);

                #(
                    leaves.append(&mut self.#idents.tree_hash_root());
                )*

                tree_hash::merkleize::merkle_root(&leaves)
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
    field
        .attrs
        .iter()
        .any(|attr| attr.into_token_stream().to_string() == "# [ signed_root ( skip_hashing ) ]")
}
