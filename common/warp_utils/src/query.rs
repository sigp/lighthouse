use serde::Deserialize;
use warp::Filter;

pub fn multi_key_query<'de, T: Deserialize<'de>>(
) -> impl warp::Filter<Extract = (T,), Error = warp::Rejection> + Copy {
    warp::filters::query::raw().and_then(|query_str: String| async move {
        serde_array_query::from_str(&query_str).map_err(|_| warp::reject::reject())
    })
}
