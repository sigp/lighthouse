use warp::{Filter, Rejection, Reply};
use bytes::{Buf, Bytes};
use std::error::Error as StdError;
use serde::de::DeserializeOwned;

struct Json;

type BoxError = Box<dyn StdError + Send + Sync>;

impl Json {
    fn decode<B: Buf, T: DeserializeOwned>(mut buf: B) -> Result<T, BoxError> {
        serde_json::from_slice(&buf.copy_to_bytes(buf.remaining())).map_err(Into::into)
    }
}

pub fn json<T: DeserializeOwned + Send>() -> impl Filter<Extract = (T,), Error = Rejection> + Copy {
    warp::body::bytes()
        .and_then(|buf: Bytes| async move {
            Json::decode(buf).map_err(|err| {
                warp::reject::reject()
            })
        })
}
