use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Errors that can occur during CORS configuration
#[derive(Debug, thiserror::Error)]
pub enum CorsError {
    #[error("Invalid CORS origin '{origin}': {reason}")]
    InvalidOrigin { origin: String, reason: String },

    #[error("CORS origins string cannot be empty")]
    EmptyOriginsString,
}

/// A validated CORS origin
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Allow any origin (*).
    Any,
    /// A specific origin URL.
    Exact(http::HeaderValue),
}

impl FromStr for Origin {
    type Err = CorsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();

        if trimmed == "*" {
            return Ok(Origin::Any);
        }

        validate_origin(trimmed)?;

        let header_value =
            http::HeaderValue::from_str(trimmed).map_err(|e| CorsError::InvalidOrigin {
                origin: trimmed.to_string(),
                reason: format!("invalid header value: {}", e),
            })?;

        Ok(Origin::Exact(header_value))
    }
}

/// Validate a CORS origin string
fn validate_origin(s: &str) -> Result<(), CorsError> {
    let make_error = |reason: &str| CorsError::InvalidOrigin {
        origin: s.to_string(),
        reason: reason.to_string(),
    };

    if !s.contains("://") {
        return Err(make_error("missing scheme (http:// or https://)"));
    }

    let (scheme, rest) = s
        .split_once("://")
        .ok_or_else(|| make_error("failed to parse scheme"))?;

    if !matches!(scheme, "http" | "https") {
        return Err(make_error(&format!(
            "invalid scheme '{}' (only http and https are allowed)",
            scheme
        )));
    }

    if rest.is_empty() {
        return Err(make_error("missing host"));
    }

    let host = rest
        .split(':')
        .next()
        .ok_or_else(|| make_error("failed to extract host"))?;

    if host.is_empty() {
        return Err(make_error("empty host"));
    }

    Ok(())
}

/// Configuration for CORS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Comma-separated list of allowed origins, or "*" for any origin.
    pub allowed_origins: String,
}

impl CorsConfig {
    /// Create a new CORS config from an origins string.
    pub fn new(allowed_origins: impl Into<String>) -> Self {
        Self {
            allowed_origins: allowed_origins.into(),
        }
    }

    /// Parse and validate the origins string, returning a list of validated origins.
    pub fn parse_origins(&self) -> Result<Vec<Origin>, CorsError> {
        let trimmed = self.allowed_origins.trim();

        if trimmed.is_empty() {
            return Err(CorsError::EmptyOriginsString);
        }

        let origins: Vec<Origin> = trimmed
            .split(',')
            .map(|s| s.trim().parse::<Origin>())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(origins)
    }

    /// Convert this config into a Tower-compatible CorsLayer.
    pub fn into_layer(self) -> Result<CorsLayer, CorsError> {
        let origins = self.parse_origins()?;

        // If any origin is the wildcard `*`, allow all origins, even when the
        // list also contains explicit origins.
        if origins.iter().any(|o| matches!(o, Origin::Any)) {
            return Ok(CorsLayer::new().allow_origin(tower_http::cors::Any));
        }

        let header_values: Vec<http::HeaderValue> = origins
            .into_iter()
            .filter_map(|o| match o {
                Origin::Exact(hv) => Some(hv),
                Origin::Any => None,
            })
            .collect();

        Ok(CorsLayer::new().allow_origin(AllowOrigin::list(header_values)))
    }
}

fn format_default_origin(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(addr) => format!("http://{}:{}", addr, port),
        IpAddr::V6(addr) => format!("http://[{}]:{}", addr, port),
    }
}

/// Build a CORS layer from an optional origins string and a default fallback
///
/// This is the main function for CLI usage:
/// - If `allow_origin` is `Some`, parse it as comma-separated origins
/// - If `allow_origin` is `None`, use the default IP and port
///
/// Callers can chain additional configuration like `.allow_methods()` and
/// `.allow_headers()` on the returned `CorsLayer`.
pub fn build_cors_layer(
    allow_origin: Option<&str>,
    default_ip: IpAddr,
    default_port: u16,
) -> Result<CorsLayer, CorsError> {
    let origins = match allow_origin {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => format_default_origin(default_ip, default_port),
    };

    CorsConfig {
        allowed_origins: origins,
    }
    .into_layer()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    fn parse_origin(s: &str) -> Result<(), CorsError> {
        s.parse::<Origin>()?;
        Ok(())
    }

    #[test]
    fn valid_origins() {
        parse_origin("*").unwrap();
        parse_origin("http://127.0.0.1").unwrap();
        parse_origin("http://localhost").unwrap();
        parse_origin("http://127.0.0.1:8000").unwrap();
        parse_origin("http://localhost:8000").unwrap();
        parse_origin("http://[::1]").unwrap();
        parse_origin("http://[::1]:8000").unwrap();
    }

    #[test]
    fn invalid_origins() {
        parse_origin(".*").unwrap_err();
        parse_origin("127.0.0.1").unwrap_err();
        parse_origin("localhost").unwrap_err();
        parse_origin("[::1]").unwrap_err();
    }

    #[test]
    fn origin_variants() {
        assert_eq!("*".parse::<Origin>().unwrap(), Origin::Any);

        match "http://localhost:3000".parse::<Origin>().unwrap() {
            Origin::Exact(_) => {}
            Origin::Any => panic!("Expected Exact variant, got Any"),
        }

        match "https://example.com".parse::<Origin>().unwrap() {
            Origin::Exact(_) => {}
            Origin::Any => panic!("Expected Exact variant, got Any"),
        }
    }

    struct HttpConfig {
        allow_origin: Option<String>,
        listen_addr: IpAddr,
        listen_port: u16,
    }

    #[test]
    fn default_config() {
        let config = HttpConfig {
            allow_origin: None,
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        );
        assert!(layer.is_ok());
    }

    #[test]
    fn wildcard_origin() {
        // lighthouse bn --http-allow-origin "*"
        let config = HttpConfig {
            allow_origin: Some("*".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        );
        assert!(layer.is_ok());
    }

    #[test]
    fn single_origin() {
        // lighthouse bn --http-allow-origin "http://localhost:3000"
        let config = HttpConfig {
            allow_origin: Some("http://localhost:3000".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        );
        assert!(layer.is_ok());
    }

    #[test]
    fn multiple_origins() {
        // lighthouse bn --http-allow-origin "http://localhost:3000,https://example.com"
        let config = HttpConfig {
            allow_origin: Some("http://localhost:3000,https://example.com".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        );
        assert!(layer.is_ok());
    }

    #[test]
    fn ipv6_listen_address() {
        let config = HttpConfig {
            allow_origin: None,
            listen_addr: "::1".parse().unwrap(),
            listen_port: 5052,
        };

        let layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        );
        assert!(layer.is_ok());
    }

    #[test]
    fn invalid_origin_missing_scheme() {
        let config = HttpConfig {
            allow_origin: Some("localhost:3000".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        );
        assert!(layer.is_err());
    }

    #[test]
    fn invalid_origin_in_list() {
        let config = HttpConfig {
            allow_origin: Some("http://localhost:3000,invalid,https://example.com".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        );
        assert!(layer.is_err());
    }

    #[tokio::test]
    async fn verify_cors_layer() {
        let config = HttpConfig {
            allow_origin: Some("http://localhost:3000".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let cors_layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        )
        .unwrap();

        async fn handler() -> &'static str {
            "test"
        }

        let app = Router::new().route("/", get(handler)).layer(cors_layer);

        // Preflight request
        let request = Request::builder()
            .method("OPTIONS")
            .uri("/")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "GET")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Verify CORS header matches origin
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "http://localhost:3000"
        );
    }

    #[tokio::test]
    async fn wildcard_overrides_exact() {
        // Mix specific origin with wildcard
        let config = HttpConfig {
            allow_origin: Some("http://localhost:3000,*".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let cors_layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        )
        .unwrap();

        async fn handler() -> &'static str {
            "test"
        }

        let app = Router::new().route("/", get(handler)).layer(cors_layer);

        let request = Request::builder()
            .method("OPTIONS")
            .uri("/")
            .header("Origin", "https://completely-different-origin.com")
            .header("Access-Control-Request-Method", "GET")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "*"
        );
    }

    #[tokio::test]
    async fn verify_allowed_methods() {
        use axum::{Router, routing::get};
        use http::{Request, StatusCode};
        use tower::ServiceExt;

        let config = HttpConfig {
            allow_origin: Some("http://localhost:3000".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let cors_layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        )
        .unwrap()
        .allow_methods([http::Method::GET, http::Method::POST])
        .allow_headers([http::header::CONTENT_TYPE]);

        async fn handler() -> &'static str {
            "test"
        }

        let app = Router::new().route("/", get(handler)).layer(cors_layer);

        let request = Request::builder()
            .method("OPTIONS")
            .uri("/")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "GET")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let allowed_methods = response
            .headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(allowed_methods.contains("GET"));
        assert!(allowed_methods.contains("POST"));
    }

    #[tokio::test]
    async fn verify_allowed_headers() {
        let config = HttpConfig {
            allow_origin: Some("http://localhost:3000".to_string()),
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 5052,
        };

        let cors_layer = build_cors_layer(
            config.allow_origin.as_deref(),
            config.listen_addr,
            config.listen_port,
        )
        .unwrap()
        .allow_methods([http::Method::GET])
        .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION]);

        async fn handler() -> &'static str {
            "test"
        }

        let app = Router::new().route("/", get(handler)).layer(cors_layer);

        // Preflight request with Content-Type header
        let request = Request::builder()
            .method("OPTIONS")
            .uri("/")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "content-type")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let allowed_headers = response
            .headers()
            .get("access-control-allow-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .to_lowercase();
        assert!(allowed_headers.contains("content-type"));
        assert!(allowed_headers.contains("authorization"));
    }
}
