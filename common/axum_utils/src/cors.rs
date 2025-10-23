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

    #[error("No valid CORS origins found after parsing")]
    NoValidOrigins,
}

/// A validated CORS origin
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Allow any origin (*)
    Any,
    /// A specific origin URL
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

    let mut parts = s.splitn(2, "://");
    let scheme = parts
        .next()
        .ok_or_else(|| make_error("failed to parse scheme"))?;
    let rest = parts
        .next()
        .ok_or_else(|| make_error("missing content after scheme"))?;

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
        if self.allowed_origins.trim().is_empty() {
            return Err(CorsError::EmptyOriginsString);
        }

        let mut origins = Vec::new();

        for origin_str in self.allowed_origins.split(',') {
            let origin = origin_str.trim().parse::<Origin>()?;

            if origin == Origin::Any {
                return Ok(vec![Origin::Any]);
            }

            origins.push(origin);
        }

        if origins.is_empty() {
            return Err(CorsError::NoValidOrigins);
        }

        Ok(origins)
    }

    /// Convert this config into a Tower-compatible CorsLayer.
    pub fn into_layer(self) -> Result<CorsLayer, CorsError> {
        let origins = self.parse_origins()?;

        let cors = match origins.as_slice() {
            [Origin::Any] => CorsLayer::new().allow_origin(tower_http::cors::Any),
            _ => {
                let header_values: Vec<http::HeaderValue> = origins
                    .into_iter()
                    .filter_map(|o| match o {
                        Origin::Exact(hv) => Some(hv),
                        Origin::Any => None,
                    })
                    .collect();

                if header_values.is_empty() {
                    return Err(CorsError::NoValidOrigins);
                }

                CorsLayer::new().allow_origin(AllowOrigin::list(header_values))
            }
        };

        Ok(cors)
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
}
