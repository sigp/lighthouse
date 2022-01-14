use crate::reject::custom_bad_request;
use serde::Deserialize;
use warp::Filter;

// Custom query filter using `serde_array_query`.
// This allows duplicate keys inside query strings.
pub fn multi_key_query<'de, T: Deserialize<'de>>(
) -> impl warp::Filter<Extract = (Result<T, warp::Rejection>,), Error = std::convert::Infallible> + Copy
{
    raw_query().then(|query_str: String| async move {
        serde_array_query::from_str(&query_str).map_err(|e| custom_bad_request(e.to_string()))
    })
}

// This ensures that empty query strings are still accepted.
// This is because warp::filters::query::raw() does not allow empty query strings
// but warp::query::<T>() does.
fn raw_query() -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Copy {
    warp::filters::query::raw()
        .or(warp::any().map(String::default))
        .unify()
}
