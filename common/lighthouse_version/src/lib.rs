use git_version::git_version;
use target_info::Target;

/// Returns the current version of this build of Lighthouse.
///
/// A plus-sign (`+`) is appended to the git commit if the tree is dirty.
///
/// ## Example
///
/// `Lighthouse/v1.5.1-67da032+`
pub const VERSION: &str = git_version!(
    args = [
        "--always",
        "--dirty=+",
        "--abbrev=7",
        // NOTE: using --match instead of --exclude for compatibility with old Git
        "--match=thiswillnevermatchlol"
    ],
    prefix = "Lighthouse/v2.0.1-",
    fallback = "unknown"
);

/// Returns `VERSION`, but with platform information appended to the end.
///
/// ## Example
///
/// `Lighthouse/v1.5.1-67da032+/x86_64-linux`
pub fn version_with_platform() -> String {
    format!("{}/{}-{}", VERSION, Target::arch(), Target::os())
}

#[cfg(test)]
mod test {
    use super::*;
    use regex::Regex;

    #[test]
    fn version_formatting() {
        let re = Regex::new(r"^Lighthouse/v[0-9]+\.[0-9]+\.[0-9]+(-rc.[0-9])?-[[:xdigit:]]{7}\+?$")
            .unwrap();
        assert!(
            re.is_match(VERSION),
            "version doesn't match regex: {}",
            VERSION
        );
    }
}
