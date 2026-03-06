use std::env::consts;

/// Returns the current version of this build of Lighthouse.
///
/// Commit hash is omitted if the sources don't include git information.
///
/// ## Example
///
/// `Lighthouse/v8.0.0-67da032`
pub const VERSION: &str = env!("GIT_VERSION");

/// Returns the first eight characters of the latest commit hash for this build.
///
/// No indication is given if the tree is dirty. This is part of the standard
/// for reporting the client version to the execution engine.
pub const COMMIT_PREFIX: &str = env!("GIT_COMMIT_PREFIX");

/// Returns `VERSION`, but with platform information appended to the end.
///
/// ## Example
///
/// `Lighthouse/v8.0.0-67da032/x86_64-linux`
pub fn version_with_platform() -> String {
    format!("{}/{}-{}", VERSION, consts::ARCH, consts::OS)
}

/// Returns semantic versioning information only.
///
/// ## Example
///
/// `8.0.0`
pub fn version() -> &'static str {
    env!("SEMANTIC_VERSION")
}

/// Returns the name of the current client running.
///
/// This will usually be "Lighthouse"
pub fn client_name() -> &'static str {
    env!("CLIENT_NAME")
}

#[cfg(test)]
mod test {
    use super::*;
    use regex::Regex;

    #[test]
    fn version_formatting() {
        let re = Regex::new(
            r"^Lighthouse/v[0-9]+\.[0-9]+\.[0-9]+(-(rc|beta)\.[0-9])?(-[[:xdigit:]]{7})?$",
        )
        .unwrap();
        assert!(
            re.is_match(VERSION),
            "version doesn't match regex: {}",
            VERSION
        );
    }

    #[test]
    fn semantic_version_formatting() {
        let re = Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+").unwrap();
        assert!(
            re.is_match(version()),
            "semantic version doesn't match regex: {}",
            version()
        );
    }

    #[test]
    fn client_name_is_lighthouse() {
        assert_eq!(client_name(), "Lighthouse");
    }

    #[test]
    fn version_contains_semantic_version() {
        assert!(VERSION.contains(version()));
    }
}
