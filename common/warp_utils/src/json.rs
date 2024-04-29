use bytes::Bytes;
use serde::de::DeserializeOwned;
use std::error::Error as StdError;
use warp::{Filter, Rejection};

use crate::reject;

struct Json;

type BoxError = Box<dyn StdError + Send + Sync>;

impl Json {
    fn decode<T: DeserializeOwned>(bytes: Bytes) -> Result<T, BoxError> {
        serde_json::from_slice(&bytes).map_err(Into::into)
    }
}

pub fn json<T: DeserializeOwned + Send>() -> impl Filter<Extract = (T,), Error = Rejection> + Copy {
    warp::body::bytes().and_then(|bytes: Bytes| async move {
        Json::decode(bytes).map_err(|err| reject::custom_deserialize_error(format!("{:?}", err)))
    })
}
