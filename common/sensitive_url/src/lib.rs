#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::str::FromStr;
use url::Url;

/// Errors that can occur when creating or parsing a `SensitiveUrl`.
#[derive(Debug)]
pub enum Error {
    /// The URL cannot be used as a base URL.
    InvalidUrl(String),
    /// Failed to parse the URL string.
    ParseError(url::ParseError),
    /// Failed to redact sensitive information from the URL.
    RedactError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
            Error::ParseError(e) => write!(f, "Parse error: {}", e),
            Error::RedactError(msg) => write!(f, "Redact error: {}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ParseError(e) => Some(e),
            _ => None,
        }
    }
}

/// A URL wrapper that redacts sensitive information in `Display` and `Debug` output.
///
/// This type stores both the full URL (with credentials, paths, and query parameters)
/// and a redacted version (containing only the scheme, host, and port). The redacted
/// version is used when displaying or debugging to prevent accidental leakage of
/// credentials in logs.
///
/// Note that `SensitiveUrl` specifically does NOT implement `Deref`, meaning you cannot call
/// `Url` methods like `.password()` or `.scheme()` directly on `SensitiveUrl`. You must first
/// explicitly call `.expose_full()`.
///
/// # Examples
///
/// ```
/// use sensitive_url::SensitiveUrl;
///
/// let url = SensitiveUrl::parse("https://user:pass@example.com/api?token=secret").unwrap();
///
/// // Display shows only the redacted version:
/// assert_eq!(url.to_string(), "https://example.com/");
///
/// // But you can still access the full URL when needed:
/// let full = url.expose_full();
/// assert_eq!(full.to_string(), "https://user:pass@example.com/api?token=secret");
/// assert_eq!(full.password(), Some("pass"));
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SensitiveUrl {
    full: Url,
    redacted: String,
}

impl fmt::Display for SensitiveUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted.fmt(f)
    }
}

impl fmt::Debug for SensitiveUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveUrl")
            .field("redacted", &self.redacted)
            // Maintains traditional `Debug` format but hides the 'full' field.
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "serde")]
impl Serialize for SensitiveUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.full.as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SensitiveUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        SensitiveUrl::parse(&s)
            .map_err(|e| de::Error::custom(format!("Failed to deserialize sensitive URL {:?}", e)))
    }
}

impl FromStr for SensitiveUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl SensitiveUrl {
    /// Attempts to parse a `&str` into a `SensitiveUrl`.
    pub fn parse(url: &str) -> Result<Self, Error> {
        let surl = Url::parse(url).map_err(Error::ParseError)?;
        SensitiveUrl::new(surl)
    }

    /// Creates a `SensitiveUrl` from an existing `Url`.
    pub fn new(full: Url) -> Result<Self, Error> {
        let mut redacted = full.clone();
        redacted
            .path_segments_mut()
            .map_err(|_| Error::InvalidUrl("URL cannot be a base.".to_string()))?
            .clear();
        redacted.set_query(None);

        if redacted.has_authority() {
            redacted
                .set_username("")
                .map_err(|_| Error::RedactError("Unable to redact username.".to_string()))?;
            redacted
                .set_password(None)
                .map_err(|_| Error::RedactError("Unable to redact password.".to_string()))?;
        }

        Ok(Self {
            full,
            redacted: redacted.to_string(),
        })
    }

    /// Returns a reference to the full, unredacted URL.
    pub fn expose_full(&self) -> &Url {
        &self.full
    }

    /// Returns the redacted URL as a `&str`.
    pub fn redacted(&self) -> &str {
        &self.redacted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_remote_url() {
        let full = "https://user:pass@example.com/example?somequery";
        let surl = SensitiveUrl::parse(full).unwrap();
        assert_eq!(surl.to_string(), "https://example.com/");
        assert_eq!(surl.expose_full().to_string(), full);
    }

    #[test]
    fn redact_localhost_url() {
        let full = "http://user:pass@localhost:5052/";
        let surl = SensitiveUrl::parse(full).unwrap();
        assert_eq!(surl.to_string(), "http://localhost:5052/");
        assert_eq!(surl.expose_full().to_string(), full);
    }

    #[test]
    fn test_no_credentials() {
        let full = "https://example.com/path";
        let surl = SensitiveUrl::parse(full).unwrap();
        assert_eq!(surl.to_string(), "https://example.com/");
        assert_eq!(surl.expose_full().to_string(), full);
    }

    #[test]
    fn test_display() {
        let full = "https://user:pass@example.com/api?token=secret";
        let surl = SensitiveUrl::parse(full).unwrap();

        let display = surl.to_string();
        assert_eq!(display, "https://example.com/");
    }

    #[test]
    fn test_debug() {
        let full = "https://user:pass@example.com/api?token=secret";
        let surl = SensitiveUrl::parse(full).unwrap();

        let debug = format!("{:?}", surl);

        assert_eq!(
            debug,
            "SensitiveUrl { redacted: \"https://example.com/\", .. }"
        );
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;

        #[test]
        fn test_serialize() {
            let full = "https://user:pass@example.com/api?token=secret";
            let surl = SensitiveUrl::parse(full).unwrap();

            let json = serde_json::to_string(&surl).unwrap();
            assert_eq!(json, format!("\"{}\"", full));
        }

        #[test]
        fn test_deserialize() {
            let full = "https://user:pass@example.com/api?token=secret";
            let json = format!("\"{}\"", full);

            let surl: SensitiveUrl = serde_json::from_str(&json).unwrap();
            assert_eq!(surl.expose_full().as_str(), full);
        }

        #[test]
        fn test_roundtrip() {
            let full = "https://user:pass@example.com/api?token=secret";
            let original = SensitiveUrl::parse(full).unwrap();

            let json = serde_json::to_string(&original).unwrap();
            let deserialized: SensitiveUrl = serde_json::from_str(&json).unwrap();

            assert_eq!(deserialized.expose_full(), original.expose_full());
        }
    }
}
