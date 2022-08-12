use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use url::Url;

#[derive(Debug)]
pub enum SensitiveError {
    InvalidUrl(String),
    ParseError(url::ParseError),
    RedactError(String),
}

impl fmt::Display for SensitiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Wrapper around Url which provides a custom `Display` implementation to protect user secrets.
#[derive(Clone, PartialEq)]
pub struct SensitiveUrl {
    pub full: Url,
    pub redacted: String,
}

impl fmt::Display for SensitiveUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted.fmt(f)
    }
}

impl fmt::Debug for SensitiveUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted.fmt(f)
    }
}

impl AsRef<str> for SensitiveUrl {
    fn as_ref(&self) -> &str {
        self.redacted.as_str()
    }
}

impl Serialize for SensitiveUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.full.as_ref())
    }
}

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
    type Err = SensitiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl SensitiveUrl {
    pub fn parse(url: &str) -> Result<Self, SensitiveError> {
        let surl = Url::parse(url).map_err(SensitiveError::ParseError)?;
        SensitiveUrl::new(surl)
    }

    fn new(full: Url) -> Result<Self, SensitiveError> {
        let mut redacted = full.clone();
        redacted
            .path_segments_mut()
            .map_err(|_| SensitiveError::InvalidUrl("URL cannot be a base.".to_string()))?
            .clear();
        redacted.set_query(None);

        if redacted.has_authority() {
            redacted.set_username("").map_err(|_| {
                SensitiveError::RedactError("Unable to redact username.".to_string())
            })?;
            redacted.set_password(None).map_err(|_| {
                SensitiveError::RedactError("Unable to redact password.".to_string())
            })?;
        }

        Ok(Self {
            full,
            redacted: redacted.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_remote_url() {
        let full = "https://project:secret@example.com/example?somequery";
        let surl = SensitiveUrl::parse(full).unwrap();
        assert_eq!(surl.to_string(), "https://example.com/");
        assert_eq!(surl.full.to_string(), full);
    }
    #[test]
    fn redact_localhost_url() {
        let full = "http://localhost:5052/";
        let surl = SensitiveUrl::parse(full).unwrap();
        assert_eq!(surl.to_string(), "http://localhost:5052/");
        assert_eq!(surl.full.to_string(), full);
    }
}
