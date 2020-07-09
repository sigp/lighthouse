use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Defines the encoding for the API.
#[derive(Clone, Serialize, Deserialize, Copy)]
pub enum ApiEncodingFormat {
    JSON,
    YAML,
    SSZ,
}

impl From<&str> for ApiEncodingFormat {
    fn from(f: &str) -> ApiEncodingFormat {
        match f {
            "application/yaml" => ApiEncodingFormat::YAML,
            "application/ssz" => ApiEncodingFormat::SSZ,
            _ => ApiEncodingFormat::JSON,
        }
    }
}

/// HTTP REST API Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Enable the REST API server.
    pub enabled: bool,
    /// The IPv4 address the REST API HTTP server will listen on.
    pub listen_address: Ipv4Addr,
    /// The port the REST API HTTP server will listen on.
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: false,
            listen_address: Ipv4Addr::new(127, 0, 0, 1),
            port: 5054,
        }
    }
}
