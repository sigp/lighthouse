#![recursion_limit = "256"]

extern crate proc_macro;

use merkle_partial::tree_arithmetic::{log_base_two, next_power_of_two};
use proc_macro::TokenStream;
use proc_macro2;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[derive(Clone, Debug)]
struct LeafData<'a> {
    ident: &'a syn::Ident,
    ty: &'a syn::Type,
    offset: u8,
    size: u8,
    is_primitive: bool,
}

/// Returns a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be accounted for in the merkle partial.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_named_field_idents<'a>(struct_data: &'a syn::DataStruct) -> Vec<&'a syn::Ident> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip(&f) {
                None
            } else {
                Some(match &f.ident {
                    Some(ref ident) => ident,
                    _ => panic!("merkle_partial only supports named struct fields."),
                })
            }
        })
        .collect()
}

/// Returns a Vec of `syn::Type` for each named field in the struct, whilst filtering out fields
/// that should not be accounted for in the merkle partial.
fn get_field_types<'a>(struct_data: &'a syn::DataStruct) -> Vec<&'a syn::Type> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| if should_skip(&f) { None } else { Some(&f.ty) })
        .collect()
}

/// Returns true if some field has an attribute declaring it should not be included in the merkle
/// partial.
///
/// The field attribute is: `#[ssz(skip)]`
fn should_skip(field: &syn::Field) -> bool {
    for attr in &field.attrs {
        if attr.tts.to_string() == "( skip )" {
            return true;
        }
    }

    false
}

/// Returns a Vec of data required to generate the nodes for each leaf index.
fn get_leaf_data_from_fields<'a>(
    idents: Vec<&'a syn::Ident>,
    types: Vec<&'a syn::Type>,
) -> Vec<Vec<LeafData<'a>>> {
    let mut offset = 0;
    let mut ret: Vec<Vec<LeafData<'a>>> = vec![];
    let mut leaf: Vec<LeafData<'a>> = vec![];

    for it in idents.iter().zip(types.iter()) {
        let (ident, ty) = it;
        let (size, is_primitive) = get_type_info(ty);

        if offset + size > 32 {
            ret.push(leaf.clone());
            leaf.drain(..);
            offset = 0;
        }

        leaf.push(LeafData {
            ident,
            ty,
            offset,
            size,
            is_primitive,
        });

        offset += size;
    }

    ret.push(leaf.clone());

    ret
}

/// Returns the size of the type (in bytes) and a boolean to denote whether the type is a primitive
/// of SSZ or it is a composite.
fn get_type_info(ty: &syn::Type) -> (u8, bool) {
    match ty {
        syn::Type::Path(syn::TypePath { path, .. }) => {
            return match path.segments[0].ident.to_string().as_ref() {
                "bool" => (1, true),
                "u8" => (1, true),
                "u16" => (2, true),
                "u32" => (4, true),
                "u64" => (8, true),
                "u128" => (16, true),
                "U256" => (32, true),
                _ => (32, false),
            };
        }
        _ => (),
    }

    (32, false)
}

fn generate_node(index: u64, leaf_data: &Vec<LeafData>) -> proc_macro2::TokenStream {
    if leaf_data[0].is_primitive {
        let primitive_nodes: Vec<proc_macro2::TokenStream> = leaf_data
            .iter()
            .map(|p| {
                let LeafData {
                    ident,
                    offset,
                    size,
                    ..
                } = p;
                let ident = ident.to_string();

                quote! {
                    merkle_partial::field::Primitive {
                        index: #index,
                        ident: #ident.to_owned(),
                        size: #size,
                        offset: #offset,
                    }
                }
            })
            .collect();

        quote! {
            merkle_partial::field::Node::Primitive(vec![
                #(#primitive_nodes),*
            ])
        }
    } else {
        let LeafData { ident, ty, .. } = leaf_data[0];
        let ident = ident.to_string();
        quote! {
            merkle_partial::field::Node::Composite(
                merkle_partial::field::Composite {
                    index: #index,
                    ident: #ident.to_owned(),
                    height: <#ty>::height(),
                }
            )
        }
    }
}

/// Returns a vector of `TokenStreams` consisting of if branches which match all field idents
/// specified in `leaf_data` and return the coresponding `Node`.
fn build_if_chain<'a>(
    leaf_data: &Vec<Vec<LeafData<'a>>>,
    height: u64,
) -> Vec<proc_macro2::TokenStream> {
    leaf_data
        .iter()
        .clone()
        .enumerate()
        .map(|(i, leaf)| {
            leaf.iter().map(|field| {
                // leaf_index = first leaf + current chunk
                let leaf_index = (1_u64 << height) - 1 + i as u64;

                let ident = field.ident.to_string();
                let ty = field.ty;

                // Builds the `Node` that should be returned upon a match of the path.
                let ret_node = generate_node(leaf_index, leaf);

                // Build the coresponding matcher for each field ident and its coresponding chunk.
                // If the path terminates, retrieve the specified node. Otherwise, recusively
                // request the node from the field's type for `path[1..]`. This matcher will never
                // need to match a `Path::Index(_)` type.
                quote! {
                    if Some(&merkle_partial::Path::Ident(#ident.to_string())) == path.first() {
                        if path.len() == 1 {
                            return Ok(#ret_node);
                        } else {
                            let node = <#ty>::get_node(path[1..].to_vec())?;
                            let index = merkle_partial::tree_arithmetic::zeroed::subtree_index_to_general(#leaf_index, node.get_index());

                            return Ok(merkle_partial::impls::replace_index(node.clone(), index));
                        }
                    }
                }
            }).collect()
        })
        .collect()
}

/// Implements `merkle_partial::merkle_tree_overlay::MerkleTreeOverlay` for some `struct`.
///
/// Fields are stored in the merkle tree in the order they appear in the struct.
#[proc_macro_derive(Partial)]
pub fn merkle_partial_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let struct_data = match &item.data {
        syn::Data::Struct(s) => s,
        _ => panic!("merkle_partial_derive only supports structs."),
    };

    // Parse the struct into a vector of data elements which contain the necessary information to
    // implement the rest of the trait.
    let leaf_data = get_leaf_data_from_fields(
        get_named_field_idents(&struct_data),
        get_field_types(&struct_data),
    );

    // Calculate the height of the tree needed to represent all the elements in the struct.
    let height = log_base_two(next_power_of_two(leaf_data.len() as u64));

    // Build the if chain for `get_node`
    let if_chain = build_if_chain(&leaf_data, height);

    let output = quote! {
        impl #impl_generics merkle_partial::MerkleTreeOverlay for #name #ty_generics #where_clause {
            fn height() -> u8 {
                #height as u8
            }

            fn first_leaf() -> merkle_partial::NodeIndex {
                (1_u64 << Self::height()) - 1
            }

            fn last_leaf() -> merkle_partial::NodeIndex {
                (1_u64 << Self::height() + 1) - 2
            }

            fn get_node(path: Vec<merkle_partial::Path>) -> Result<merkle_partial::field::Node, merkle_partial::Error> {
                #(#if_chain else)*
                if let Some(p) = path.first() {
                    Err(merkle_partial::Error::InvalidPath(p.clone()))
                } else {
                    Err(merkle_partial::Error::EmptyPath())
                }
            }
        }
    };

    output.into()
}
