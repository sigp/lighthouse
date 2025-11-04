use crate::{ContextDeserialize, ForkName};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::Value;

pub trait ForkVersionDecode: Sized {
    /// SSZ decode with explicit fork variant.
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError>;
}

/// The metadata of type M should be set to `EmptyMetadata` if you don't care about adding fields other than
/// version. If you *do* care about adding other fields you can mix in any type that implements
/// `Deserialize`.
#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct ForkVersionedResponse<T, M = EmptyMetadata> {
    pub version: ForkName,
    #[serde(flatten)]
    pub metadata: M,
    pub data: T,
}

// Used for responses to V1 endpoints that don't have a version field.
/// The metadata of type M should be set to `EmptyMetadata` if you don't care about adding fields other than
/// version. If you *do* care about adding other fields you can mix in any type that implements
/// `Deserialize`.
#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct UnversionedResponse<T, M = EmptyMetadata> {
    #[serde(flatten)]
    pub metadata: M,
    pub data: T,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
#[serde(untagged)]
pub enum BeaconResponse<T, M = EmptyMetadata> {
    ForkVersioned(ForkVersionedResponse<T, M>),
    Unversioned(UnversionedResponse<T, M>),
}

impl<T, M> BeaconResponse<T, M> {
    pub fn version(&self) -> Option<ForkName> {
        match self {
            BeaconResponse::ForkVersioned(response) => Some(response.version),
            BeaconResponse::Unversioned(_) => None,
        }
    }

    pub fn data(&self) -> &T {
        match self {
            BeaconResponse::ForkVersioned(response) => &response.data,
            BeaconResponse::Unversioned(response) => &response.data,
        }
    }

    pub fn metadata(&self) -> &M {
        match self {
            BeaconResponse::ForkVersioned(response) => &response.metadata,
            BeaconResponse::Unversioned(response) => &response.metadata,
        }
    }
}

/// Metadata type similar to unit (i.e. `()`) but deserializes from a map (`serde_json::Value`).
///
/// Unfortunately the braces are semantically significant, i.e. `struct EmptyMetadata;` does not
/// work.
#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct EmptyMetadata {}

/// Fork versioned response with extra information about finalization & optimistic execution.
pub type ExecutionOptimisticFinalizedBeaconResponse<T> =
    BeaconResponse<T, ExecutionOptimisticFinalizedMetadata>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ExecutionOptimisticFinalizedMetadata {
    pub execution_optimistic: Option<bool>,
    pub finalized: Option<bool>,
}

impl<'de, T, M> Deserialize<'de> for ForkVersionedResponse<T, M>
where
    T: ContextDeserialize<'de, ForkName>,
    M: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: ForkName,
            #[serde(flatten)]
            metadata: Value,
            data: Value,
        }

        let helper = Helper::deserialize(deserializer)?;

        // Deserialize metadata
        let metadata = serde_json::from_value(helper.metadata).map_err(serde::de::Error::custom)?;

        // Deserialize `data` using ContextDeserialize
        let data = T::context_deserialize(helper.data, helper.version)
            .map_err(serde::de::Error::custom)?;

        Ok(ForkVersionedResponse {
            version: helper.version,
            metadata,
            data,
        })
    }
}

impl<'de, T, M> Deserialize<'de> for UnversionedResponse<T, M>
where
    T: DeserializeOwned,
    M: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<T, M> {
            #[serde(flatten)]
            metadata: M,
            data: T,
        }

        let helper = Helper::deserialize(deserializer)?;

        Ok(UnversionedResponse {
            metadata: helper.metadata,
            data: helper.data,
        })
    }
}

impl<T, M> BeaconResponse<T, M> {
    pub fn map_data<U>(self, f: impl FnOnce(T) -> U) -> BeaconResponse<U, M> {
        match self {
            BeaconResponse::ForkVersioned(response) => {
                BeaconResponse::ForkVersioned(response.map_data(f))
            }
            BeaconResponse::Unversioned(response) => {
                BeaconResponse::Unversioned(response.map_data(f))
            }
        }
    }

    pub fn into_data(self) -> T {
        match self {
            BeaconResponse::ForkVersioned(response) => response.data,
            BeaconResponse::Unversioned(response) => response.data,
        }
    }
}

impl<T, M> UnversionedResponse<T, M> {
    pub fn map_data<U>(self, f: impl FnOnce(T) -> U) -> UnversionedResponse<U, M> {
        let UnversionedResponse { metadata, data } = self;
        UnversionedResponse {
            metadata,
            data: f(data),
        }
    }
}

impl<T, M> ForkVersionedResponse<T, M> {
    /// Apply a function to the inner `data`, potentially changing its type.
    pub fn map_data<U>(self, f: impl FnOnce(T) -> U) -> ForkVersionedResponse<U, M> {
        let ForkVersionedResponse {
            version,
            metadata,
            data,
        } = self;
        ForkVersionedResponse {
            version,
            metadata,
            data: f(data),
        }
    }
}

impl<T, M> From<ForkVersionedResponse<T, M>> for BeaconResponse<T, M> {
    fn from(response: ForkVersionedResponse<T, M>) -> Self {
        BeaconResponse::ForkVersioned(response)
    }
}

impl<T, M> From<UnversionedResponse<T, M>> for BeaconResponse<T, M> {
    fn from(response: UnversionedResponse<T, M>) -> Self {
        BeaconResponse::Unversioned(response)
    }
}

#[cfg(test)]
mod fork_version_response_tests {
    use crate::beacon_response::ExecutionOptimisticFinalizedMetadata;
    use crate::{
        ExecutionPayload, ExecutionPayloadBellatrix, ForkName, ForkVersionedResponse,
        MainnetEthSpec, UnversionedResponse,
    };
    use serde_json::json;

    #[test]
    fn fork_versioned_response_deserialize_correct_fork() {
        type E = MainnetEthSpec;

        let response_json =
            serde_json::to_string(&json!(ForkVersionedResponse::<ExecutionPayload<E>> {
                version: ForkName::Bellatrix,
                metadata: Default::default(),
                data: ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix::default()),
            }))
            .unwrap();

        let result: Result<ForkVersionedResponse<ExecutionPayload<E>>, _> =
            serde_json::from_str(&response_json);

        assert!(result.is_ok());
    }

    #[test]
    fn fork_versioned_response_deserialize_incorrect_fork() {
        type E = MainnetEthSpec;

        let response_json =
            serde_json::to_string(&json!(ForkVersionedResponse::<ExecutionPayload<E>> {
                version: ForkName::Capella,
                metadata: Default::default(),
                data: ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix::default()),
            }))
            .unwrap();

        let result: Result<ForkVersionedResponse<ExecutionPayload<E>>, _> =
            serde_json::from_str(&response_json);

        assert!(result.is_err());
    }

    // The following test should only pass by having the attribute #[serde(flatten)] on the metadata
    #[test]
    fn unversioned_response_serialize_dezerialize_round_trip_test() {
        // Create an UnversionedResponse with some data
        let data = UnversionedResponse {
            metadata: ExecutionOptimisticFinalizedMetadata {
                execution_optimistic: Some(false),
                finalized: Some(false),
            },
            data: "some_test_data".to_string(),
        };

        let serialized = serde_json::to_string(&data);

        let deserialized =
            serde_json::from_str(&serialized.unwrap()).expect("Failed to deserialize");

        assert_eq!(data, deserialized);
    }
}
