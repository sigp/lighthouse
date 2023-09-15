use std::net::IpAddr;
use warp::filters::cors::Builder;

/// Configure a `cors::Builder`.
///
/// If `allow_origin.is_none()` the `default_origin` is used.
pub fn set_builder_origins(
    builder: Builder,
    allow_origin: Option<&str>,
    default_origin: (IpAddr, u16),
) -> Result<Builder, String> {
    if let Some(allow_origin) = allow_origin {
        let mut origins = vec![];
        for origin in allow_origin.split(',') {
            verify_cors_origin_str(origin)?;
            if origin == "*" {
                return Ok(builder.allow_any_origin());
            }
            origins.push(origin)
        }
        Ok(builder.allow_origins(origins))
    } else {
        let origin = match default_origin.0 {
            IpAddr::V4(_) => format!("http://{}:{}", default_origin.0, default_origin.1),
            IpAddr::V6(_) => format!("http://[{}]:{}", default_origin.0, default_origin.1),
        };
        verify_cors_origin_str(&origin)?;

        Ok(builder.allow_origin(origin.as_str()))
    }
}

/// Verify that `s` can be used as a CORS origin.
///
/// ## Notes
///
/// We need this function since `warp` will panic if provided an invalid origin. The verification
/// code is taken from here:
///
/// https://github.com/seanmonstar/warp/blob/3d1760c6ca35ce2d03dee0562259d0320e9face3/src/filters/cors.rs#L616
///
/// Ideally we should make a PR to `warp` to expose this behaviour, however we defer this for a
/// later time. The impact of a false-positive on this function is fairly limited, since only
/// trusted users should be setting CORS origins.
fn verify_cors_origin_str(s: &str) -> Result<(), String> {
    // Always the wildcard origin.
    if s == "*" {
        return Ok(());
    }

    let mut parts = s.splitn(2, "://");
    let scheme = parts
        .next()
        .ok_or_else(|| format!("{} is missing a scheme", s))?;
    let rest = parts
        .next()
        .ok_or_else(|| format!("{} is missing the part following the scheme", s))?;

    headers::Origin::try_from_parts(scheme, rest, None)
        .map_err(|e| format!("Unable to parse {}: {}", s, e))
        .map(|_| ())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_origins() {
        verify_cors_origin_str("*").unwrap();
        verify_cors_origin_str("http://127.0.0.1").unwrap();
        verify_cors_origin_str("http://localhost").unwrap();
        verify_cors_origin_str("http://127.0.0.1:8000").unwrap();
        verify_cors_origin_str("http://localhost:8000").unwrap();
        verify_cors_origin_str("http://[::1]").unwrap();
        verify_cors_origin_str("http://[::1]:8000").unwrap();
    }

    #[test]
    fn invalid_origins() {
        verify_cors_origin_str(".*").unwrap_err();
        verify_cors_origin_str("127.0.0.1").unwrap_err();
        verify_cors_origin_str("localhost").unwrap_err();
        verify_cors_origin_str("[::1]").unwrap_err();
    }
}
