use reqwest::StatusCode;

/// Convert a `reqwest::StatusCode` to a `warp::http::StatusCode`.
///
/// In warp 0.4, both `reqwest` (0.12) and `warp` use the `http` v1 crate,
/// so `reqwest::StatusCode` and `warp::http::StatusCode` are the same type.
/// This function is retained for API compatibility but is now a no-op.
pub fn convert(code: StatusCode) -> Result<warp::http::StatusCode, warp::Rejection> {
    Ok(code)
}
