#![recursion_limit = "256"]
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Attribute, DataEnum, DataStruct, DeriveInput, Meta};

/// Return a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be hashed.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_hashable_fields(struct_data: &syn::DataStruct) -> Vec<&syn::Ident> {
    get_hashable_fields_and_their_caches(struct_data)
        .into_iter()
        .map(|(ident, _, _)| ident)
        .collect()
}

/// Return a Vec of the hashable fields of a struct, and each field's type and optional cache field.
fn get_hashable_fields_and_their_caches(
    struct_data: &syn::DataStruct,
) -> Vec<(&syn::Ident, syn::Type, Option<syn::Ident>)> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_hashing(f) {
                None
            } else {
                let ident = f
                    .ident
                    .as_ref()
                    .expect("tree_hash_derive only supports named struct fields");
                let opt_cache_field = get_cache_field_for(f);
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
            NestedMeta::Meta(Meta::Path(path)) => path.get_ident().cloned(),
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
        attr.path.is_ident("tree_hash")
            && attr.tokens.to_string().replace(" ", "") == "(skip_hashing)"
    })
}

/// Implements `tree_hash::TreeHash` for some `struct`.
///
/// Fields are hashed in the order they are defined.
#[proc_macro_derive(TreeHash, attributes(tree_hash))]
pub fn tree_hash_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    match &item.data {
        syn::Data::Struct(s) => tree_hash_derive_struct(&item, s),
        syn::Data::Enum(e) => tree_hash_derive_enum(&item, e),
        _ => panic!("tree_hash_derive only supports structs."),
    }
}

fn tree_hash_derive_struct(item: &DeriveInput, struct_data: &DataStruct) -> TokenStream {
    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let idents = get_hashable_fields(struct_data);
    let num_leaves = idents.len();

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

            fn tree_hash_root(&self) -> tree_hash::Hash256 {
                let mut hasher = tree_hash::MerkleHasher::with_leaves(#num_leaves);

                #(
                    hasher.write(self.#idents.tree_hash_root().as_bytes())
                        .expect("tree hash derive should not apply too many leaves");
                )*

                hasher.finish().expect("tree hash derive should not have a remaining buffer")
            }
        }
    };
    output.into()
}

/// Derive `TreeHash` for a restricted subset of all possible enum types.
///
/// Only supports:
/// - Enums with a single field per variant, where
///     - All fields are "container" types.
///
/// Will panic at compile-time if the single field requirement isn't met, but will panic *at run
/// time* if the container type requirement isn't met.
fn tree_hash_derive_enum(derive_input: &DeriveInput, enum_data: &DataEnum) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let (patterns, type_exprs): (Vec<_>, Vec<_>) = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("TreeHash can only be derived for enums with 1 field per variant");
            }

            let pattern = quote! {
                #name::#variant_name(ref inner)
            };

            let ty = &(&variant.fields).into_iter().next().unwrap().ty;
            let type_expr = quote! {
                <#ty as tree_hash::TreeHash>::tree_hash_type()
            };
            (pattern, type_expr)
        })
        .unzip();

    let output = quote! {
        impl #impl_generics tree_hash::TreeHash for #name #ty_generics #where_clause {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                #(
                    assert_eq!(
                        #type_exprs,
                        tree_hash::TreeHashType::Container,
                        "all variants must be of container type"
                    );
                )*
                tree_hash::TreeHashType::Container
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("Enum should never be packed")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Enum should never be packed")
            }

            fn tree_hash_root(&self) -> Hash256 {
                match self {
                    #(
                        #patterns => inner.tree_hash_root(),
                    )*
                }
            }
        }
    };
    output.into()
}
