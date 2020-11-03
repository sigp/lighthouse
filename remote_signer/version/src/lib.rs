use git_version::git_version;
use target_info::Target;

/// Returns the current version of this build of Lighthouse.
///
/// A plus-sign (`+`) is appended to the git commit if the tree is dirty.
///
/// ## Example
///
/// `BLS_Remote_Signer/v0.1.0--d5d7c43+`
pub const VERSION: &str = git_version!(
    args = ["--always", "--dirty=+"],
    prefix = "Remote_Signer/v0.2.0-",
    fallback = "unknown"
);

/// Returns `VERSION`, but with platform information appended to the end.
///
/// ## Example
///
/// `Lighthouse/v0.2.0--d5d7c43+/x86_64-linux`
pub fn version_with_platform() -> String {
    format!("{}/{}-{}", VERSION, Target::arch(), Target::os())
}
