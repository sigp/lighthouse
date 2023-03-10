use serde::Serialize;
use warp::reply::{Reply, Response};

/// A convenience wrapper around `blocking_task`.
pub async fn blocking_task<F, T>(func: F) -> Result<T, warp::Rejection>
where
    F: FnOnce() -> Result<T, warp::Rejection> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .unwrap_or_else(|_| Err(warp::reject::reject()))
}

pub async fn blocking_response_task<F, T>(func: F) -> Result<Response, warp::Rejection>
where
    F: FnOnce() -> Result<T, warp::Rejection> + Send + 'static,
    T: Reply + Send + 'static,
{
    blocking_task(func).await.map(Reply::into_response)
}

/// A convenience wrapper around `blocking_task` for use with `warp` JSON responses.
pub async fn blocking_json_task<F, T>(func: F) -> Result<Response, warp::Rejection>
where
    F: FnOnce() -> Result<T, warp::Rejection> + Send + 'static,
    T: Serialize + Send + 'static,
{
    blocking_response_task(|| {
        let response = func()?;
        Ok(warp::reply::json(&response))
    })
    .await
}
