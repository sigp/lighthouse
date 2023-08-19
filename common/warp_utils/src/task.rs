use serde::Serialize;
use warp::reply::{Reply, Response};

/// A convenience wrapper around `blocking_task`.
pub async fn blocking_task<F>(func: F) -> Result<Response, warp::Rejection>
where
    F: FnOnce() -> Result<Response, warp::Rejection> + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .unwrap_or_else(|_| Err(warp::reject::reject()))
}

/// A convenience wrapper around `blocking_task` that returns a `warp::reply::Response`.
///
/// Using this method consistently makes it possible to simplify types using `.unify()` or `.uor()`.
pub async fn blocking_response_task<F>(func: F) -> Result<Response, warp::Rejection>
where
    F: FnOnce() -> Result<Response, warp::Rejection> + Send + 'static,
{
    blocking_task(func).await
}

/// A convenience wrapper around `blocking_task` for use with `warp` JSON responses.
pub async fn blocking_json_task<F, T>(func: F) -> Result<Response, warp::Rejection>
where
    F: FnOnce() -> Result<T, warp::Rejection> + Send + 'static,
    T: Serialize + Send + 'static,
{
    blocking_response_task(|| {
        let response = func()?;
        let json_reply = warp::reply::json(&response);
        Ok(json_reply.into_response())
    })
    .await
}
