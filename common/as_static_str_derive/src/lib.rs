use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

#[proc_macro_derive(VariantName)]
pub fn variant_name(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input: DeriveInput = syn::parse(input).unwrap();

    let name = &input.ident;

    let expanded = match input.data {
        syn::Data::Enum(enu) => {
            let branches = enu.variants.iter().map(|v| {
                let ident = &v.ident;
                let match_identifier = match v.fields {
                    _ => {
                        quote! {
                            #ident{ .. }
                        }
                    }
                };
                quote! {
                    &#name::#match_identifier => stringify!(#ident)
                }
            });
            let names = enu.variants.iter().map(|v| &v.ident);
            quote! {
                impl VariantName for #name {
                    fn variant_name(&self) -> &'static str {
                        match self {
                            #(#branches),*
                        }
                    }
                    fn variant_names() -> &'static [&'static str] {
                        &[#(stringify!(#names)),*]
                    }
                }
            }
        }
        _ => panic!("Derive variant names only for Enums"),
    };

    // Hand the output tokens back to the compiler
    expanded.into()
}
