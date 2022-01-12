use crate::reject::custom_bad_request;
use serde::Deserialize;
use warp::Filter;

pub fn multi_key_query<'de, T: Deserialize<'de>>(
) -> impl warp::Filter<Extract = (Result<T, warp::Rejection>,), Error = warp::Rejection> + Copy {
    warp::filters::query::raw().then(|query_str: String| async move {
        serde_array_query::from_str(&query_str).map_err(|e| custom_bad_request(e.to_string()))
    })
}
