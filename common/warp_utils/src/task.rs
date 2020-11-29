use serde::Serialize;

/// A convenience wrapper around `blocking_task`.
pub async fn blocking_task<F, T>(func: F) -> Result<T, warp::Rejection>
where
    F: FnOnce() -> Result<T, warp::Rejection> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .unwrap_or_else(|_| Err(warp::reject::reject())) // This should really be a 500
}

/// A convenience wrapper around `blocking_task` for use with `warp` JSON responses.
pub async fn blocking_json_task<F, T>(func: F) -> Result<warp::reply::Json, warp::Rejection>
where
    F: FnOnce() -> Result<T, warp::Rejection> + Send + 'static,
    T: Serialize + Send + 'static,
{
    blocking_task(func)
        .await
        .map(|resp| warp::reply::json(&resp))
}
