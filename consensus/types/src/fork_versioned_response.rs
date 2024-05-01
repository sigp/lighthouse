use crate::ForkName;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::Value;
use std::sync::Arc;

pub trait ForkVersionDeserialize: Sized + DeserializeOwned {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error>;
}

/// Deserialize is only implemented for types that implement ForkVersionDeserialize.
///
/// The metadata of type M should be set to `EmptyMetadata` if you don't care about adding fields other than
/// version. If you *do* care about adding other fields you can mix in any type that implements
/// `Deserialize`.
#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct ForkVersionedResponse<T, M = EmptyMetadata> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ForkName>,
    #[serde(flatten)]
    pub metadata: M,
    pub data: T,
}

/// Metadata type similar to unit (i.e. `()`) but deserializes from a map (`serde_json::Value`).
///
/// Unfortunately the braces are semantically significant, i.e. `struct EmptyMetadata;` does not
/// work.
#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct EmptyMetadata {}

/// Fork versioned response with extra information about finalization & optimistic execution.
pub type ExecutionOptimisticFinalizedForkVersionedResponse<T> =
    ForkVersionedResponse<T, ExecutionOptimisticFinalizedMetadata>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ExecutionOptimisticFinalizedMetadata {
    pub execution_optimistic: Option<bool>,
    pub finalized: Option<bool>,
}

impl<'de, F, M> serde::Deserialize<'de> for ForkVersionedResponse<F, M>
where
    F: ForkVersionDeserialize,
    M: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: Option<ForkName>,
            #[serde(flatten)]
            metadata: serde_json::Value,
            data: serde_json::Value,
        }

        let helper = Helper::deserialize(deserializer)?;
        let data = match helper.version {
            Some(fork_name) => F::deserialize_by_fork::<'de, D>(helper.data, fork_name)?,
            None => serde_json::from_value(helper.data).map_err(serde::de::Error::custom)?,
        };
        let metadata = serde_json::from_value(helper.metadata).map_err(serde::de::Error::custom)?;

        Ok(ForkVersionedResponse {
            version: helper.version,
            metadata,
            data,
        })
    }
}

impl<F: ForkVersionDeserialize> ForkVersionDeserialize for Arc<F> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        Ok(Arc::new(F::deserialize_by_fork::<'de, D>(
            value, fork_name,
        )?))
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

#[cfg(test)]
mod fork_version_response_tests {
    use crate::{
        ExecutionPayload, ExecutionPayloadBellatrix, ForkName, ForkVersionedResponse,
        MainnetEthSpec,
    };
    use serde_json::json;

    #[test]
    fn fork_versioned_response_deserialize_correct_fork() {
        type E = MainnetEthSpec;

        let response_json =
            serde_json::to_string(&json!(ForkVersionedResponse::<ExecutionPayload<E>> {
                version: Some(ForkName::Bellatrix),
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
                version: Some(ForkName::Capella),
                metadata: Default::default(),
                data: ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix::default()),
            }))
            .unwrap();

        let result: Result<ForkVersionedResponse<ExecutionPayload<E>>, _> =
            serde_json::from_str(&response_json);

        assert!(result.is_err());
    }
}
