use bls::PublicKeyBytes;
pub use builder_types::{BuilderUrl, RequestAuthData};
use eth2_keystore::Keystore;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, value::StringDeserializer},
};
pub use serde_utils::quoted_u64::Quoted;
use types::{Address, Graffiti};
use zeroize::Zeroizing;

fn deserialize_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn deserialize_strict_uint64_string<'de, D>(
    deserializer: D,
) -> Result<Option<Quoted<u64>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let is_canonical = value == "0"
        || (value.len() <= 20
            && value.as_bytes().first().is_some_and(|byte| *byte >= b'1')
            && value.as_bytes().iter().all(u8::is_ascii_digit));
    if !is_canonical {
        return Err(de::Error::custom("invalid quoted uint64"));
    }
    value
        .parse()
        .map(|value| Some(Quoted { value }))
        .map_err(de::Error::custom)
}

mod serde_option_auth_data {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<RequestAuthData>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(data) => ssz_types::serde_utils::hex_var_list::serialize(data, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<RequestAuthData>, D::Error> {
        let value = String::deserialize(deserializer)?;
        ssz_types::serde_utils::hex_var_list::deserialize(StringDeserializer::<D::Error>::new(
            value,
        ))
        .map(Some)
    }
}

pub use eip_3076::Interchange;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct GetFeeRecipientResponse {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::address_hex")]
    pub ethaddress: Address,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct GetGasLimitResponse {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
}

/// Per-validator external-builder configuration from the standard keymanager API.
///
/// A missing field inherits the validator client's global configuration. The GET endpoint returns
/// all fields resolved, while POST accepts an omitted `builders` field and an explicitly empty
/// list as distinct values.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct BuilderConfig {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_strict_uint64_string"
    )]
    pub min_bid: Option<Quoted<u64>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_strict_uint64_string"
    )]
    pub builder_boost_factor: Option<Quoted<u64>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null"
    )]
    pub builders: Option<Vec<BuilderEntry>>,
}

/// An external-builder entry from the standard keymanager API.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BuilderEntry {
    pub url: BuilderUrl,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_option_auth_data"
    )]
    pub auth_data: Option<RequestAuthData>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null"
    )]
    pub builder_pubkeys: Option<Vec<PublicKeyBytes>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_strict_uint64_string"
    )]
    pub max_execution_payment: Option<Quoted<u64>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_strict_uint64_string"
    )]
    pub min_bid: Option<Quoted<u64>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_strict_uint64_string"
    )]
    pub builder_boost_factor: Option<Quoted<u64>>,
}

#[cfg(test)]
mod builder_config_tests {
    use super::*;

    #[test]
    fn builder_config_uses_keymanager_json_encoding() {
        let json = serde_json::json!({
            "min_bid": "3",
            "builder_boost_factor": "110",
            "builders": [{
                "url": "https://builder.example",
                "auth_data": "0x0102",
                "builder_pubkeys": [],
                "max_execution_payment": "8"
            }]
        });
        let config = serde_json::from_value::<BuilderConfig>(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(config).unwrap(), json);
        assert_eq!(
            serde_json::to_value(BuilderConfig::default()).unwrap(),
            serde_json::json!({})
        );
        assert!(
            serde_json::from_value::<BuilderConfig>(serde_json::json!({"min_bid": 3})).is_err()
        );
        for invalid in [
            serde_json::json!({"min_bid": null}),
            serde_json::json!({"min_bid": "01"}),
            serde_json::json!({"min_bid": "+1"}),
            serde_json::json!({"builders": null}),
            serde_json::json!({"builders": [{"url": "https://builder.example", "auth_data": null}]}),
            serde_json::json!({"builders": [{"url": "https://builder.example", "builder_pubkeys": null}]}),
        ] {
            assert!(serde_json::from_value::<BuilderConfig>(invalid).is_err());
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct AuthResponse {
    pub token_path: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ListKeystoresResponse {
    pub data: Vec<SingleKeystoreResponse>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct SingleKeystoreResponse {
    pub validating_pubkey: PublicKeyBytes,
    pub derivation_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportKeystoresRequest {
    pub keystores: Vec<KeystoreJsonStr>,
    pub passwords: Vec<Zeroizing<String>>,
    pub slashing_protection: Option<InterchangeJsonStr>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct KeystoreJsonStr(#[serde(with = "serde_utils::json_str")] pub Keystore);

impl std::ops::Deref for KeystoreJsonStr {
    type Target = Keystore;
    fn deref(&self) -> &Keystore {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct InterchangeJsonStr(#[serde(with = "serde_utils::json_str")] pub Interchange);

#[derive(Debug, Deserialize, Serialize)]
pub struct ImportKeystoresResponse {
    pub data: Vec<Status<ImportKeystoreStatus>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Status<T> {
    pub status: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl<T> Status<T> {
    pub fn ok(status: T) -> Self {
        Self {
            status,
            message: None,
        }
    }

    pub fn error(status: T, message: String) -> Self {
        Self {
            status,
            message: Some(message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportKeystoreStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteKeystoresRequest {
    pub pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteKeystoresResponse {
    pub data: Vec<Status<DeleteKeystoreStatus>>,
    #[serde(with = "serde_utils::json_str")]
    pub slashing_protection: Interchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteKeystoreStatus {
    Deleted,
    NotActive,
    NotFound,
    Error,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ListRemotekeysResponse {
    pub data: Vec<SingleListRemotekeysResponse>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SingleListRemotekeysResponse {
    pub pubkey: PublicKeyBytes,
    pub url: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRemotekeysRequest {
    pub remote_keys: Vec<SingleImportRemotekeysRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SingleImportRemotekeysRequest {
    pub pubkey: PublicKeyBytes,
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportRemotekeyStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ImportRemotekeysResponse {
    pub data: Vec<Status<ImportRemotekeyStatus>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRemotekeysRequest {
    pub pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteRemotekeyStatus {
    Deleted,
    NotFound,
    Error,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteRemotekeysResponse {
    pub data: Vec<Status<DeleteRemotekeyStatus>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetGraffitiResponse {
    pub pubkey: PublicKeyBytes,
    pub graffiti: Graffiti,
}
