use account_utils::write_file_via_temporary;
use bls::PublicKeyBytes;
use builder_types::{BuilderUrl, MAX_BUILDER_ENTRIES, RequestAuthData};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, create_dir_all};
use std::io;
use std::path::{Path, PathBuf};

/// The file name for the serialized `BuilderConfigFile` struct.
pub const BUILDERS_FILENAME: &str = "builder_definitions.yml";
/// The temporary file name for the serialized `BuilderConfigFile` struct.
///
/// This is used to achieve an atomic update of the contents on disk, without truncation.
pub const BUILDERS_TEMP_FILENAME: &str = ".builder_definitions.yml.tmp";

#[derive(Debug)]
pub enum Error {
    /// The config file could not be opened.
    UnableToOpenFile(io::Error),
    /// The config file could not be parsed as YAML.
    UnableToParseFile(yaml_serde::Error),
    /// The builders file could not be serialized as YAML.
    UnableToEncodeFile(yaml_serde::Error),
    /// The builders file or temp file could not be written to the filesystem.
    UnableToWriteFile(filesystem::Error),
    /// The validator directory could not be created.
    UnableToCreateValidatorDir(PathBuf),
    /// A builder with the given URL already exists.
    DuplicateBuilderAuth(BuilderUrl),
    /// A builder URL could not be parsed as a URL.
    InvalidBuilderUrl(BuilderUrl),
    /// A builder URL does not use an `http`/`https` scheme.
    UnsupportedUrlScheme(BuilderUrl),
    /// More than `MAX_BUILDER_ENTRIES` builders are enabled, exceeding what fits in a
    /// `BuilderConfig`.
    TooManyEnabledBuilders { enabled: usize, max: usize },
}

/// A single builder in the config file: a direct bid request, with optional per-builder overrides
/// of the global bid policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderDefinition {
    /// Indicates whether this definition is enabled or disabled.
    pub enabled: bool,
    /// The URL the beacon node uses to contact this builder. Routing metadata; never signed.
    pub url: BuilderUrl,
    /// Opaque authentication data signed into `RequestAuth.data`, agreed with the builder out of
    /// band, as a `0x`-prefixed hex string. When unset, it defaults to the UTF-8 bytes of `url`
    /// (the builder-specs #165 default). Must be non-empty when set: a zero-length `data` is
    /// invalid on the wire.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_option_auth_data"
    )]
    pub auth_data: Option<RequestAuthData>,
    /// The builder BLS public keys this builder's bids may be signed by, hex-encoded. Empty (or
    /// omitted) accepts any builder; otherwise a bid not signed by one of them is rejected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builder_pubkeys: Vec<PublicKeyBytes>,
    /// The maximum execution payment, in gwei, that we're willing to accept from this builder.
    pub max_execution_payment: u64,
    /// Per-builder override of the global minimum total payment (gwei). Inherits the global when
    /// unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_bid: Option<u64>,
    /// Per-builder override of the global boost factor. Inherits the global when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor: Option<u64>,
}

fn default_builder_boost_factor() -> u64 {
    100
}

/// Serde helper: represent `Option<RequestAuthData>` as a `0x`-prefixed hex string in the config
/// file (matching how other byte fields are encoded), omitting it entirely when `None`.
mod serde_option_auth_data {
    use super::RequestAuthData;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(
        value: &Option<RequestAuthData>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(data) => serializer.serialize_some(&format!("0x{}", hex::encode(&data[..]))),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<RequestAuthData>, D::Error> {
        let Some(s) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(stripped).map_err(de::Error::custom)?;
        let data = RequestAuthData::new(bytes)
            .map_err(|_| de::Error::custom("auth_data exceeds the maximum size"))?;
        Ok(Some(data))
    }
}

/// The validator client's builder configuration file.
///
/// Holds the global bid-policy defaults plus the list of builders to request bids from directly. It
/// resolves into the wire `BuilderConfig` at block-production time: the globals govern p2p bids and
/// fill in any builder that omits `min_bid`/`builder_boost_factor`.
#[derive(Clone, Serialize, Deserialize)]
pub struct BuilderConfigFile {
    /// Global minimum total payment (gwei). Applies to p2p bids and is inherited by any builder that
    /// omits its own `min_bid`.
    #[serde(default)]
    pub min_bid: u64,
    /// Global boost factor. Applies to p2p bids and is inherited by any builder that omits its own
    /// `builder_boost_factor`.
    #[serde(default = "default_builder_boost_factor")]
    pub builder_boost_factor: u64,
    /// The builders to request bids from directly.
    #[serde(default)]
    pub builders: Vec<BuilderDefinition>,
}

impl Default for BuilderConfigFile {
    fn default() -> Self {
        Self {
            min_bid: 0,
            builder_boost_factor: default_builder_boost_factor(),
            builders: Vec::new(),
        }
    }
}

impl BuilderConfigFile {
    /// Open an existing file or create a new, empty one if it does not exist.
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        create_dir_all(validators_dir.as_ref()).map_err(|_| {
            Error::UnableToCreateValidatorDir(PathBuf::from(validators_dir.as_ref()))
        })?;
        let builders_file_path = validators_dir.as_ref().join(BUILDERS_FILENAME);
        if !builders_file_path.exists() {
            let this = Self::default();
            this.save(&validators_dir)?;
        }
        Self::open(validators_dir)
    }

    /// Open an existing file, returning an error if the file does not exist.
    pub fn open<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(BUILDERS_FILENAME);
        let file = File::options()
            .write(true)
            .read(true)
            .create_new(false)
            .open(config_path)
            .map_err(Error::UnableToOpenFile)?;
        let config: Self = yaml_serde::from_reader(file).map_err(Error::UnableToParseFile)?;
        config.validate()?;
        Ok(config)
    }

    /// Encodes `self` as a YAML string and atomically writes it to the `CONFIG_FILENAME` file in
    /// the `validators_dir` directory.
    ///
    /// Will create a new file if it does not exist or overwrite any existing file.
    pub fn save<P: AsRef<Path>>(&self, validators_dir: P) -> Result<(), Error> {
        let config_path = validators_dir.as_ref().join(BUILDERS_FILENAME);
        let temp_path = validators_dir.as_ref().join(BUILDERS_TEMP_FILENAME);
        let mut bytes = vec![];
        yaml_serde::to_writer(&mut bytes, self).map_err(Error::UnableToEncodeFile)?;

        write_file_via_temporary(&config_path, &temp_path, &bytes)
            .map_err(Error::UnableToWriteFile)?;

        Ok(())
    }

    pub fn as_slice(&self) -> &[BuilderDefinition] {
        &self.builders
    }

    pub fn push(&mut self, definition: BuilderDefinition) {
        self.builders.push(definition);
    }

    pub fn validate(&self) -> Result<(), Error> {
        // The enabled builders must fit in a `BuilderConfig`'s bounded list, so
        // `BuilderStore::builder_config` cannot overflow when constructing it.
        let enabled = self.builders.iter().filter(|d| d.enabled).count();
        if enabled > MAX_BUILDER_ENTRIES {
            return Err(Error::TooManyEnabledBuilders {
                enabled,
                max: MAX_BUILDER_ENTRIES,
            });
        }

        let mut seen_auth_urls = HashSet::new();

        for definition in &self.builders {
            if !definition.enabled {
                // ignore disabled builders
                continue;
            }
            let url = &definition.url;
            // Reject malformed or non-http(s) builder URLs here, at config load, rather than
            // silently skipping them during block proposal.
            let sensitive_url = url
                .to_sensitive_url()
                .map_err(|_| Error::InvalidBuilderUrl(url.clone()))?;
            if !matches!(sensitive_url.expose_full().scheme(), "http" | "https") {
                return Err(Error::UnsupportedUrlScheme(url.clone()));
            }

            let auth = definition
                .auth_data
                .clone()
                .unwrap_or_else(|| url.to_default_auth_data());
            // two entries cannot contain the same url and auth data
            let key = (url.clone(), auth);
            if !seen_auth_urls.insert(key) {
                return Err(Error::DuplicateBuilderAuth(url.clone()));
            }
        }

        Ok(())
    }
}

impl<'a> IntoIterator for &'a BuilderConfigFile {
    type Item = &'a BuilderDefinition;
    type IntoIter = std::slice::Iter<'a, BuilderDefinition>;

    fn into_iter(self) -> Self::IntoIter {
        self.builders.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_data_round_trips_as_hex() {
        let definition = BuilderDefinition {
            enabled: true,
            url: "http://builder.example.com".parse().unwrap(),
            auth_data: Some(RequestAuthData::new(b"hello".to_vec()).unwrap()),
            builder_pubkeys: vec![],
            max_execution_payment: 1,
            min_bid: None,
            builder_boost_factor: None,
        };

        let yaml = yaml_serde::to_string(&definition).unwrap();
        // "hello" is 0x68656c6c6f, a hex string — not a YAML sequence of byte values.
        assert!(
            yaml.contains("0x68656c6c6f"),
            "auth_data not hex-encoded:\n{yaml}"
        );

        let decoded: BuilderDefinition = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(decoded, definition);
    }

    #[test]
    fn omits_none_optional_fields() {
        let definition = BuilderDefinition {
            enabled: true,
            url: "http://builder.example.com".parse().unwrap(),
            auth_data: None,
            builder_pubkeys: vec![],
            max_execution_payment: 1,
            min_bid: None,
            builder_boost_factor: None,
        };
        let yaml = yaml_serde::to_string(&definition).unwrap();
        for field in [
            "auth_data",
            "builder_pubkeys",
            "min_bid",
            "builder_boost_factor",
        ] {
            assert!(
                !yaml.contains(field),
                "unset `{field}` should be omitted:\n{yaml}"
            );
        }
    }
}
