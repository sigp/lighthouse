use jsonwebtoken::{encode, errors::Error, get_current_timestamp, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

const DEFAULT_ALGORITHM: Algorithm = Algorithm::HS256;

pub struct Auth {
    secret: EncodingKey,
    id: Option<String>,
    clv: Option<String>,
}

impl Auth {
    pub fn new(secret: &str, id: Option<String>, clv: Option<String>) -> Result<Self, Error> {
        Ok(Self {
            secret: EncodingKey::from_base64_secret(secret)?,
            id,
            clv,
        })
    }

    /// Generate a JWT token with iat set to current time.
    pub fn generate_token(&self) -> Result<String, Error> {
        let header = Header::new(DEFAULT_ALGORITHM);
        let claims = Claims {
            iat: get_current_timestamp(),
            id: self.id.clone(),
            clv: self.clv.clone(),
        };
        encode(&header, &claims, &self.secret)
    }
}

/// Claims struct as defined in https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md#jwt-claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// issued-at claim. Represented as seconds passed since UNIX_EPOCH.
    iat: u64,
    /// Optional unique identifier for the CL node.
    id: Option<String>,
    /// Optional client version for the CL node.
    clv: Option<String>,
}
