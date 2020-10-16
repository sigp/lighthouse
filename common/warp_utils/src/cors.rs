use std::net::Ipv4Addr;
use warp::filters::cors::Builder;

/// Configure a `cors::Builder`.
///
/// If `allow_origin.is_none()` the `default_origin` is used.
pub fn set_builder_origins(
    builder: Builder,
    allow_origin: Option<&str>,
    default_origin: (Ipv4Addr, u16),
) -> Builder {
    if let Some(allow_origin) = allow_origin {
        if allow_origin == "*" {
            builder.allow_any_origin()
        } else {
            builder.allow_origins(allow_origin.split(","))
        }
    } else {
        builder.allow_origin(format!("http://{}:{}", default_origin.0, default_origin.1).as_str())
    }
}
