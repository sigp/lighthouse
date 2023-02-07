use crate::ForkName;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::Value;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ExecutionOptimisticForkVersionedResponse<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ForkName>,
    pub execution_optimistic: Option<bool>,
    pub data: T,
}

pub trait ForkVersionDeserialize: Sized + DeserializeOwned {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error>;
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct ForkVersionedResponse<F: ForkVersionDeserialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ForkName>,
    pub data: F,
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
