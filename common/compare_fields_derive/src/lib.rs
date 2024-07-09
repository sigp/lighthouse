use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

fn is_iter(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path.is_ident("compare_fields")
            && (attr.tokens.to_string().replace(' ', "") == "(as_slice)"
                || attr.tokens.to_string().replace(' ', "") == "(as_iter)")
    })
}

#[proc_macro_derive(CompareFields, attributes(compare_fields))]
pub fn compare_fields_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let syn::Data::Struct(struct_data) = &item.data else {
        panic!("compare_fields_derive only supports structs.");
    };

    let mut quotes = vec![];

    for field in struct_data.fields.iter() {
        let Some(ident_a) = &field.ident else {
            panic!("compare_fields_derive only supports named struct fields.");
        };
        let field_name = ident_a.to_string();
        let ident_b = ident_a.clone();

        let quote = if is_iter(field) {
            quote! {
                comparisons.push(compare_fields::Comparison::from_into_iter(
                        #field_name.to_string(),
                        &self.#ident_a,
                        &b.#ident_b
                ));
            }
        } else {
            quote! {
                comparisons.push(
                    compare_fields::Comparison::child(
                        #field_name.to_string(),
                        &self.#ident_a,
                        &b.#ident_b
                    )
                );
            }
        };

        quotes.push(quote);
    }

    let output = quote! {
        impl #impl_generics compare_fields::CompareFields for #name #ty_generics #where_clause {
            fn compare_fields(&self, b: &Self) -> Vec<compare_fields::Comparison> {
                let mut comparisons = vec![];

                #(
                    #quotes
                )*

                comparisons
            }
        }
    };
    output.into()
}
