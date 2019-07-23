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

/// Returns a Vec of `TokenStream`s which define the behavior for calculating the node for each
/// leaf index.
///
/// It also determines whether the index is child of the leaf object, in which case it
/// should recursive call `get_node` on the type associated with the leaf, or whether it is
/// directly referencing the leaf, in which case it should return the coresponding `Leaf` node.
fn build_match_body<'a>(
    leaf_data: Vec<Vec<LeafData<'a>>>,
    first_leaf_index: u64,
) -> Vec<proc_macro2::TokenStream> {
    leaf_data
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let leaf_index = first_leaf_index + i as u64;
            let ret_node = if l[0].is_primitive {
                let primitive_nodes: Vec<proc_macro2::TokenStream> = l
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
                                index: #leaf_index,
                                ident: #ident.to_owned(),
                                size: #size,
                                offset: #offset,
                            }
                        }
                    })
                    .collect();

                quote! {
                    merkle_partial::field::Node::Leaf(merkle_partial::field::Leaf::Primitive(vec![
                        #(#primitive_nodes),*
                    ]))
                }
            } else {
                let LeafData { ident, ty, .. } = l[0];
                let ident = ident.to_string();
                quote! {
                    merkle_partial::field::Node::Composite(
                        merkle_partial::field::Composite {
                            index: #leaf_index,
                            ident: #ident.to_owned(),
                            height: <#ty>::height(),
                        }
                    )
                }
            };

            let leaf_type = l[0].ty;

            quote! {
                #leaf_index => {
                    if index == subtree_root {
                        #ret_node
                    } else {
                        <#leaf_type>::get_node(subtree_index)
                    }
            }}
        })
        .collect()
}

/// Returns a vector of `TokenStreams` consisting of if branches which match all field idents
/// specified in `leaf_data` and return the coresponding `Node`.
fn build_if_chain<'a>(
    leaf_data: Vec<Vec<LeafData<'a>>>,
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

                // Build the coresponding matcher for each field ident and its coresponding chunk.
                // If the path terminates, retrieve the specified node. Otherwise, recusively
                // request the node from the field's type for `path[1..]`. This matcher will never
                // need to match a `Path::Index(_)` type.
                quote! {
                    if Some(&merkle_partial::Path::Ident(#ident.to_string())) == path.first() {
                        if path.len() == 1 {
                            return Ok(Self::get_node(#leaf_index));
                        } else {
                            let node = <#ty>::get_node_from_path(path[1..].to_vec())?;
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

    // Build the body of the match expression for `get_node`
    let match_body = build_match_body(leaf_data.clone(), (1_u64 << height) - 1);
    let match_body2 = match_body.clone();

    // Build the if chain for `get_node_from_path`
    let if_chain = build_if_chain(leaf_data, height);

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

            fn get_node(index: merkle_partial::NodeIndex) -> merkle_partial::field::Node {
                let first_leaf = Self::first_leaf();
                let last_leaf = Self::last_leaf();

                // When the first leaf is 0 or 1, there are no internal nodes in the merkle tree.
                // By setting the internal nodes to 0 in this case, their coresponding arm of the
                // `if` branch will not execute. When the tree is larger, they are set correctly.
                let (first_internal, last_internal) = if first_leaf == 0 || first_leaf == 1 {
                    (0, 0)
                } else {
                    (1, first_leaf - 1)
                };

                // There is an edge case for when the entire structure can fit inside 32 bytes,
                // the data itself is defined as the merkle root. For fixed sized types, this is
                // when the height is 0. For variable sized types, this is when the height is 1.
                if Self::height() == 0 && index == 0 {
                    let subtree_root = 0;
                    let subtree_index = index;

                    return match index {
                        #(#match_body2)*
                        _ => unreachable!()
                    };
                }

                if index == 0 {
                    merkle_partial::field::Node::Composite(merkle_partial::field::Composite {
                        ident: "".to_owned(),
                        index: 0,
                        height: Self::height().into(),
                    })
                } else if (first_internal..=last_internal).contains(&index) {
                    merkle_partial::field::Node::Intermediate(index)
                } else {
                    // If no match at this point, the node must be in one of the subtrees or
                    // unattached.
                    let subtree_root = merkle_partial::tree_arithmetic::zeroed::root_from_depth(index, merkle_partial::tree_arithmetic::zeroed::relative_depth(first_leaf, index));
                    let subtree_index = merkle_partial::tree_arithmetic::zeroed::general_index_to_subtree(subtree_root, index);

                    if (first_leaf..=last_leaf).contains(&subtree_root) {
                        let node = match subtree_root {
                            #(#match_body)*
                            _ => merkle_partial::field::Node::Leaf(merkle_partial::field::Leaf::Padding())
                        };

                        merkle_partial::impls::replace_index(node, index)
                    } else {
                        merkle_partial::field::Node::Unattached(index)
                    }
                }
            }

            fn get_node_from_path(path: Vec<merkle_partial::Path>) -> merkle_partial::Result<merkle_partial::field::Node> {
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
