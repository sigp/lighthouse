// This is a stub for determining the build profile, see `build_profile_name`.
fn main() {
    // Warn about the deprecated `gnosis` feature, which does nothing.
    if std::env::var_os("CARGO_FEATURE_GNOSIS").is_some() {
        println!(
            "cargo:warning=The `gnosis` feature is deprecated and does nothing. A Lighthouse \
             binary runs only one preset; build with `--features spec-gnosis` to compile for the \
             Gnosis preset (Gnosis and Chiado)."
        );
    }
}
