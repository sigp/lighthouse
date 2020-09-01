use git_version::git_version;
use target_info::Target;

/// Returns the current version of this build of Lighthouse.
///
/// A plus-sign (`+`) is appended to the git commit if the tree is dirty.
///
/// ## Example
///
/// `Lighthouse/v0.2.0-1419501f2+`
pub const VERSION: &str = git_version!(
    args = ["--always", "--dirty=+"],
    prefix = "Lighthouse/v0.2.8-",
    fallback = "unknown"
);

/// Returns `VERSION`, but with platform information appended to the end.
///
/// ## Example
///
/// `Lighthouse/v0.2.0-1419501f2+/x86_64-linux`
pub fn version_with_platform() -> String {
    format!("{}/{}-{}", VERSION, Target::arch(), Target::os())
}
