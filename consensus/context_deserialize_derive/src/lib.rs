use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, DeriveInput, LifetimeDef, Meta, NestedMeta, Path};

/// `#[context_deserialize(Foo, Bar, ...)]`
/// generates `ContextDeserialize<'de, Foo>` and `ContextDeserialize<'de, Bar>`
/// forwarding impls for the given struct.
#[proc_macro_attribute]
pub fn context_deserialize(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse attribute and input struct
    let args = parse_macro_input!(attr as AttributeArgs);
    let input = parse_macro_input!(item as DeriveInput);
    let ident = &input.ident;

    // Context types provided in macro
    let ctx_types: Vec<Path> = args
        .iter()
        .filter_map(|meta| match meta {
            NestedMeta::Meta(Meta::Path(p)) => Some(p.clone()),
            _ => None,
        })
        .collect();

    if ctx_types.is_empty() {
        return quote! {
            compile_error!("Usage: #[context_deserialize(Type1, Type2, ...)]");
        }
        .into();
    }

    // Generic handling
    let generics = &input.generics;
    let params = &generics.params;
    let (_, ty_generics, where_clause) = generics.split_for_impl();

    let has_de = generics
        .lifetimes()
        .any(|LifetimeDef { lifetime, .. }| lifetime.ident == "de");

    let base_generics = if has_de {
        quote! { #params }
    } else if params.is_empty() {
        quote! { 'de }
    } else {
        quote! { 'de, #params }
    };

    // Generate impls per context type
    let mut impls = quote! {};
    for ctx in ctx_types {
        impls.extend(quote! {
            impl<#base_generics> context_deserialize::ContextDeserialize<'de, #ctx>
                for #ident #ty_generics #where_clause
            {
                fn context_deserialize<D>(
                    deserializer: D,
                    _context: #ctx,
                ) -> Result<Self, D::Error>
                where
                    D: serde::de::Deserializer<'de>,
                {
                    <Self as serde::Deserialize>::deserialize(deserializer)
                }
            }
        });
    }

    // Final output: input struct + impl blocks
    quote! {
        #input
        #impls
    }
    .into()
}
