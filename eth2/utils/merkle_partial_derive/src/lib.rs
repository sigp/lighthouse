#![recursion_limit = "256"]

extern crate proc_macro;

use merkle_partial::tree_arithmetic::{log_base_two, next_power_of_two};
use proc_macro::TokenStream;
use proc_macro2;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

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

#[derive(Clone, Debug)]
struct LeafData<'a> {
    ident: &'a syn::Ident,
    ty: &'a syn::Type,
    offset: u8,
    size: u8,
    is_primitive: bool,
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
                    merkle_partial::field::Node::Leaf(merkle_partial::field::Leaf::Composite(
                        merkle_partial::field::Composite {
                            index: #leaf_index,
                            ident: #ident.to_owned(),
                            height: <#ty>::height(),
                        }
                    ))
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

    let field_idents = get_named_field_idents(&struct_data);
    let field_types = get_field_types(&struct_data);
    let leaf_data = get_leaf_data_from_fields(field_idents.clone(), field_types.clone());

    let height = log_base_two(next_power_of_two(leaf_data.len() as u64));
    let match_body = build_match_body(leaf_data, (1_u64 << height) - 1);

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

                if index == 0 {
                    merkle_partial::field::Node::Composite(merkle_partial::field::Composite {
                        ident: "".to_owned(),
                        index: 0,
                        height: Self::height().into(),
                    })
                } else if (first_internal..=last_internal).contains(&index) {
                    merkle_partial::field::Node::Intermediate(index)
                } else {
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
        }
    };

    output.into()
}
