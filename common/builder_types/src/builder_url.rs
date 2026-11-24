use crate::RequestAuthData;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::fmt;
use std::str::FromStr;
use tree_hash::{PackedEncoding, TreeHash};

/// Maximum length (in bytes) of a builder URL on the wire (`MAX_BUILDER_URL_SIZE`), per
/// beacon-APIs #630.
pub type MaxBuilderUrlSize = typenum::U2048;

/// Maximum number of builder entries a validator may supply on a single request, per
/// beacon-APIs #630. Used as the SSZ `List` bound on `BuilderConfig.builders`.
pub type MaxBuilderEntries = typenum::U64;

/// [`MaxBuilderEntries`] as a `usize` (derived, so the two cannot drift), for runtime bounds checks.
pub const MAX_BUILDER_ENTRIES: usize = <MaxBuilderEntries as typenum::Unsigned>::USIZE;

/// A builder URL as it travels on the beacon-API wire.
///
/// Held as the UTF-8 bytes of the URL so it can serialize two ways, matching the `ByteList` /
/// `string` duality in beacon-APIs #630: an SSZ `ByteList[MAX_BUILDER_URL_SIZE]` (a bare byte list,
/// via the transparent struct behaviour) and a plain string in JSON.
///
/// This is unsigned routing metadata. On the validator side the URL is held as a `SensitiveUrl`
/// (for redaction/ergonomics) and converted into a `BuilderUrl` only when building a request.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
#[ssz(struct_behaviour = "transparent")]
pub struct BuilderUrl {
    bytes: VariableList<u8, MaxBuilderUrlSize>,
}

/// An error constructing or converting a [`BuilderUrl`].
#[derive(Debug)]
pub enum BuilderUrlError {
    /// The URL exceeds `MaxBuilderUrlSize` bytes.
    TooLong,
    /// The bytes cannot be parsed as a URL or used to derive an ASCII hostname.
    InvalidUrl,
}

impl BuilderUrl {
    /// The URL's raw UTF-8 bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The URL as a string slice, if it is valid UTF-8 (it always is when constructed through the
    /// public API).
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.bytes)
    }

    /// Parse this URL into a [`SensitiveUrl`], for making requests or redacted logging.
    ///
    /// Fails if the bytes are not valid UTF-8 or do not parse as a URL. `BuilderUrl` itself is just
    /// opaque bytes on the wire, so this is the conversion point where URL validity is checked.
    pub fn to_sensitive_url(&self) -> Result<SensitiveUrl, BuilderUrlError> {
        let url = self.as_str().map_err(|_| BuilderUrlError::InvalidUrl)?;
        SensitiveUrl::parse(url).map_err(|_| BuilderUrlError::InvalidUrl)
    }

    /// The default opaque auth `data` to sign for this builder when no custom auth data is provided.
    ///
    /// Uses the lowercase ASCII hostname, with IPv6 compressed inside brackets. Internationalized
    /// hostnames must be supplied in punycode form, as required by builder-specs #168.
    pub fn to_default_auth_data(&self) -> Result<RequestAuthData, BuilderUrlError> {
        let parsed = self.to_sensitive_url()?;
        // Match URL parsing without changing the stored routing URL or explicit auth data.
        let url = self
            .as_str()
            .map_err(|_| BuilderUrlError::InvalidUrl)?
            .replace(['\t', '\r', '\n'], "");
        let (_, authority) = url.split_once("://").ok_or(BuilderUrlError::InvalidUrl)?;
        let host_port = authority
            .split(['/', '?', '#'])
            .next()
            .and_then(|authority| authority.rsplit('@').next())
            .ok_or(BuilderUrlError::InvalidUrl)?;
        let host = if host_port.starts_with('[') {
            // URL serialization uses hexadecimal groups even for IPv4-mapped IPv6 addresses.
            parsed.expose_full().host_str()
        } else {
            // Keep the advertised spelling: URL parsing also rewrites IPv4 and percent escapes.
            host_port.split(':').next()
        }
        .filter(|host| !host.is_empty() && host.is_ascii())
        .ok_or(BuilderUrlError::InvalidUrl)?;
        RequestAuthData::new(host.to_ascii_lowercase().into_bytes())
            .map_err(|_| BuilderUrlError::TooLong)
    }
}

impl TryFrom<&SensitiveUrl> for BuilderUrl {
    type Error = BuilderUrlError;

    fn try_from(url: &SensitiveUrl) -> Result<Self, Self::Error> {
        // Error rather than silently truncating to an (invalid) empty url if the URL string somehow
        // exceeds `MaxBuilderUrlSize`.
        let bytes = VariableList::new(url.expose_full().as_str().as_bytes().to_vec())
            .map_err(|_| BuilderUrlError::TooLong)?;
        Ok(Self { bytes })
    }
}

impl FromStr for BuilderUrl {
    type Err = BuilderUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            VariableList::new(s.as_bytes().to_vec()).map_err(|_| BuilderUrlError::TooLong)?;
        Ok(Self { bytes })
    }
}

impl fmt::Display for BuilderUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.bytes))
    }
}

impl Serialize for BuilderUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = std::str::from_utf8(&self.bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for BuilderUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        BuilderUrl::from_str(&s).map_err(|e| de::Error::custom(format!("{e:?}")))
    }
}

impl TreeHash for BuilderUrl {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <VariableList<u8, MaxBuilderUrlSize> as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.bytes.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <VariableList<u8, MaxBuilderUrlSize> as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.bytes.tree_hash_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderUrl);

    #[test]
    fn json_is_a_string() {
        let url = BuilderUrl::from_str("https://builder.example.com").unwrap();
        let json = serde_json::to_string(&url).unwrap();
        assert_eq!(json, "\"https://builder.example.com\"");

        let decoded: BuilderUrl = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, url);
    }

    #[test]
    fn default_auth_data_ignores_url_spelling() {
        for url in [
            "https://builder.example.com",
            "https://builder.example.com/",
            "HTTPS://Builder.Example.com:443/bids?x=1#fragment",
            "https://user:pw@builder.example.com:8080/",
            "https://Builder.Example.com\r\n",
            "https:/\t/Buil\tder.Example.com/",
        ] {
            let url = BuilderUrl::from_str(url).unwrap();
            assert_eq!(
                &*url.to_default_auth_data().unwrap(),
                b"builder.example.com"
            );
        }
    }

    #[test]
    fn default_auth_data_hostnames() {
        for (url, expected) in [
            ("https://10.0.0.5:18550/eth/v1/builder", "10.0.0.5"),
            ("https://[0:0:0:0:0:0:0:1]:8443/", "[::1]"),
            ("https://[::ffff:192.0.2.1]/", "[::ffff:c000:201]"),
            ("https://[2001:0DB8:0:0:1:0:0:1]/", "[2001:db8::1:0:0:1]"),
            ("https://XN--BCHER-KVA.example/", "xn--bcher-kva.example"),
            ("https://builder.example/路徑", "builder.example"),
            ("http://127.1/", "127.1"),
            ("http://0177.0.0.1/", "0177.0.0.1"),
            ("https://%65XAMPLE.com/", "%65xample.com"),
        ] {
            let url = BuilderUrl::from_str(url).unwrap();
            assert_eq!(&*url.to_default_auth_data().unwrap(), expected.as_bytes());
        }
    }

    #[test]
    fn default_auth_data_requires_ascii_hostname() {
        for url in [
            "",
            "not a URL",
            "mailto:builder@example.com",
            "https://bücher.example/",
        ] {
            assert!(matches!(
                BuilderUrl::from_str(url).unwrap().to_default_auth_data(),
                Err(BuilderUrlError::InvalidUrl)
            ));
        }
        let url = BuilderUrl {
            bytes: VariableList::new(vec![0xff]).unwrap(),
        };
        assert!(matches!(
            url.to_default_auth_data(),
            Err(BuilderUrlError::InvalidUrl)
        ));
    }

    #[test]
    fn default_auth_data_at_max_url_size() {
        use ssz_types::typenum::Unsigned;

        let prefix = "https://builder.example/";
        let url_string = format!(
            "{prefix}{}",
            "a".repeat(MaxBuilderUrlSize::USIZE - prefix.len())
        );
        let url = BuilderUrl::from_str(&url_string).unwrap();
        assert_eq!(url.as_bytes().len(), MaxBuilderUrlSize::USIZE);
        assert_eq!(&*url.to_default_auth_data().unwrap(), b"builder.example");
    }
}
