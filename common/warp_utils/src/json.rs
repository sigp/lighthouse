use bytes::Bytes;
use eth2::{CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER};
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
    warp::header::optional::<String>(CONTENT_TYPE_HEADER)
        .and(warp::body::bytes())
        .and_then(|header: Option<String>, bytes: Bytes| async move {
            if let Some(header) = header {
                if header == SSZ_CONTENT_TYPE_HEADER {
                    return Err(reject::unsupported_media_type(
                        "The request's content-type is not supported".to_string(),
                    ));
                }
            }
            Json::decode(bytes)
                .map_err(|err| reject::custom_deserialize_error(format!("{:?}", err)))
        })
}
