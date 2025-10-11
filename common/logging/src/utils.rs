use std::collections::HashSet;
use tracing_subscriber::filter::FilterFn;
use workspace_members::workspace_crates;

const WORKSPACE_CRATES: &[&str] = workspace_crates!();

/// Constructs a filter which only permits logging from crates which are members of the workspace.
pub fn build_workspace_filter()
-> Result<FilterFn<impl Fn(&tracing::Metadata) -> bool + Clone>, String> {
    let workspace_crates: HashSet<&str> = WORKSPACE_CRATES.iter().copied().collect();

    Ok(tracing_subscriber::filter::FilterFn::new(move |metadata| {
        let target_crate = metadata.target().split("::").next().unwrap_or("");
        workspace_crates.contains(target_crate)
    }))
}

/// Function to filter out ascii control codes.
///
/// This helps to keep log formatting consistent.
/// Whitespace and padding control codes are excluded.
pub fn is_ascii_control(character: &u8) -> bool {
    matches!(
        character,
        b'\x00'..=b'\x08' |
        b'\x0b'..=b'\x0c' |
        b'\x0e'..=b'\x1f' |
        b'\x7f' |
        b'\x81'..=b'\x9f'
    )
}
