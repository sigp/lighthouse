use cargo_metadata::MetadataCommand;
use proc_macro::TokenStream;
use quote::quote;
use std::error::Error;

fn get_workspace_crates() -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new().no_deps().exec()?;

    Ok(metadata
        .workspace_members
        .iter()
        .filter_map(|member_id| {
            metadata
                .packages
                .iter()
                .find(|package| &package.id == member_id)
                .map(|package| package.name.clone())
        })
        .collect())
}

#[proc_macro]
pub fn workspace_crates(_input: TokenStream) -> TokenStream {
    match get_workspace_crates() {
        Ok(crate_names) => {
            let crate_strs = crate_names.iter().map(|s| s.as_str());
            quote! {
                &[#(#crate_strs),*]
            }
        }
        Err(e) => {
            let msg = format!("Failed to get workspace crates: {e}");
            quote! {
                compile_error!(#msg);
            }
        }
    }
    .into()
}
