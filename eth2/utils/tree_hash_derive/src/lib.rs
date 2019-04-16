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
    for attr in &field.attrs {
        if attr.tts.to_string() == "( skip_hashing )" {
            return true;
        }
    }
    false
}

/// Implements `tree_hash::CachedTreeHashSubTree` for some `struct`.
///
/// Fields are hashed in the order they are defined.
#[proc_macro_derive(CachedTreeHashSubTree, attributes(tree_hash))]
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
    let idents_d = idents_a.clone();

    let output = quote! {
        impl tree_hash::CachedTreeHashSubTree<#name> for #name {
            fn new_tree_hash_cache(&self) -> Result<tree_hash::TreeHashCache, tree_hash::Error> {
                let tree = tree_hash::TreeHashCache::from_leaves_and_subtrees(
                    self,
                    vec![
                        #(
                            self.#idents_a.new_tree_hash_cache()?,
                        )*
                    ],
                )?;

                Ok(tree)
            }

            fn tree_hash_cache_overlay(&self, chunk_offset: usize) -> Result<tree_hash::BTreeOverlay, tree_hash::Error> {
                let mut lengths = vec![];

                #(
                    lengths.push(tree_hash::BTreeOverlay::new(&self.#idents_b, 0)?.total_nodes());
                )*

                tree_hash::BTreeOverlay::from_lengths(chunk_offset, lengths)
            }

            fn update_tree_hash_cache(
                &self,
                other: &Self,
                cache: &mut tree_hash::TreeHashCache,
                chunk: usize,
            ) -> Result<usize, tree_hash::Error> {
                let offset_handler = tree_hash::BTreeOverlay::new(self, chunk)?;

                // Skip past the internal nodes and update any changed leaf nodes.
                {
                    let chunk = offset_handler.first_leaf_node()?;
                    #(
                        let chunk = self.#idents_c.update_tree_hash_cache(&other.#idents_d, cache, chunk)?;
                    )*
                }

                for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
                    if cache.either_modified(children)? {
                        cache.modify_chunk(parent, &cache.hash_children(children)?)?;
                    }
                }

                Ok(offset_handler.next_node)
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
                tree_hash::TreeHashType::Composite
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

                tree_hash::merkle_root(&leaves)
            }
        }
    };
    output.into()
}

/// Implements `tree_hash::TreeHash` for some `struct`, whilst excluding any fields following and
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
#[proc_macro_derive(SignedRoot, attributes(signed_root))]
pub fn tree_hash_signed_root_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("tree_hash_derive only supports structs."),
    };

    let idents = get_signed_root_named_field_idents(&struct_data);

    let output = quote! {
        impl tree_hash::SignedRoot for #name {
            fn signed_root(&self) -> Vec<u8> {
                let mut leaves = Vec::with_capacity(4 * tree_hash::HASHSIZE);

                #(
                    leaves.append(&mut self.#idents.tree_hash_root());
                )*

                tree_hash::merkle_root(&leaves)
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
