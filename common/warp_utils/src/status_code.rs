use eth2::StatusCode;
use warp::Rejection;

/// Convert from a "new" `http::StatusCode` to a `warp` compatible one.
pub fn convert(code: StatusCode) -> Result<warp::http::StatusCode, Rejection> {
    code.as_u16().try_into().map_err(|e| {
        crate::reject::custom_server_error(format!("bad status code {code:?} - {e:?}"))
    })
}
