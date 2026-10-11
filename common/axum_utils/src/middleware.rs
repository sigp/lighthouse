use axum::http::header;
use tower_http::set_header::SetResponseHeaderLayer;

/// Returns a layer that adds the "Server" header to all responses.
pub fn add_server_header(
    value: header::HeaderValue,
) -> SetResponseHeaderLayer<header::HeaderValue> {
    SetResponseHeaderLayer::overriding(header::SERVER, value)
}
