use serde::Serialize;

/// Execute some task in a tokio "blocking thread". These threads are ideal for long-running
/// (blocking) tasks since they don't jam up the core executor.
pub async fn blocking_task<F, T>(func: F) -> T
where
    F: Fn() -> T,
{
    tokio::task::block_in_place(func)
}

/// A convenience wrapper around `blocking_task` for use with `warp` JSON responses.
pub async fn blocking_json_task<F, T>(func: F) -> Result<warp::reply::Json, warp::Rejection>
where
    F: Fn() -> Result<T, warp::Rejection>,
    T: Serialize,
{
    blocking_task(func)
        .await
        .map(|resp| warp::reply::json(&resp))
}
