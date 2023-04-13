use crate::ForkName;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::Value;
use std::sync::Arc;

// Deserialize is only implemented for types that implement ForkVersionDeserialize
#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct ExecutionOptimisticFinalizedForkVersionedResponse<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ForkName>,
    pub execution_optimistic: Option<bool>,
    pub finalized: Option<bool>,
    pub data: T,
}

impl<'de, F> serde::Deserialize<'de> for ExecutionOptimisticFinalizedForkVersionedResponse<F>
where
    F: ForkVersionDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: Option<ForkName>,
            execution_optimistic: Option<bool>,
            finalized: Option<bool>,
            data: serde_json::Value,
        }

        let helper = Helper::deserialize(deserializer)?;
        let data = match helper.version {
            Some(fork_name) => F::deserialize_by_fork::<'de, D>(helper.data, fork_name)?,
            None => serde_json::from_value(helper.data).map_err(serde::de::Error::custom)?,
        };

        Ok(ExecutionOptimisticFinalizedForkVersionedResponse {
            version: helper.version,
            execution_optimistic: helper.execution_optimistic,
            finalized: helper.finalized,
            data,
        })
    }
}

pub trait ForkVersionDeserialize: Sized + DeserializeOwned {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error>;
}

// Deserialize is only implemented for types that implement ForkVersionDeserialize
#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct ForkVersionedResponse<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ForkName>,
    pub data: T,
}

impl<'de, F> serde::Deserialize<'de> for ForkVersionedResponse<F>
where
    F: ForkVersionDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: Option<ForkName>,
            data: serde_json::Value,
        }

        let helper = Helper::deserialize(deserializer)?;
        let data = match helper.version {
            Some(fork_name) => F::deserialize_by_fork::<'de, D>(helper.data, fork_name)?,
            None => serde_json::from_value(helper.data).map_err(serde::de::Error::custom)?,
        };

        Ok(ForkVersionedResponse {
            version: helper.version,
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

#[cfg(test)]
mod fork_version_response_tests {
    use crate::{
        ExecutionPayload, ExecutionPayloadMerge, ForkName, ForkVersionedResponse, MainnetEthSpec,
    };
    use serde_json::json;

    #[test]
    fn fork_versioned_response_deserialize_correct_fork() {
        type E = MainnetEthSpec;

        let response_json =
            serde_json::to_string(&json!(ForkVersionedResponse::<ExecutionPayload<E>> {
                version: Some(ForkName::Merge),
                data: ExecutionPayload::Merge(ExecutionPayloadMerge::default()),
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
                data: ExecutionPayload::Merge(ExecutionPayloadMerge::default()),
            }))
            .unwrap();

        let result: Result<ForkVersionedResponse<ExecutionPayload<E>>, _> =
            serde_json::from_str(&response_json);

        assert!(result.is_err());
    }
}
