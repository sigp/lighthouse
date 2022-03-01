use jsonwebtoken::{encode, get_current_timestamp, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

const DEFAULT_ALGORITHM: Algorithm = Algorithm::HS256;

#[derive(Debug)]
pub enum Error {
    InvalidSecret(hex::FromHexError),
    JWT(jsonwebtoken::errors::Error),
    InvalidToken,
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::InvalidSecret(e)
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Error::JWT(e)
    }
}

/// Contains the JWT secret and claims parameters.
pub struct Auth {
    secret: EncodingKey,
    id: Option<String>,
    clv: Option<String>,
}

impl Auth {
    pub fn new(secret: &str, id: Option<String>, clv: Option<String>) -> Result<Self, Error> {
        Ok(Self {
            secret: EncodingKey::from_secret(hex::decode(secret)?.as_slice()),
            id,
            clv,
        })
    }

    /// Generate a JWT token with `claims.iat` set to current time.
    pub fn generate_token(&self) -> Result<String, Error> {
        let header = Header::new(DEFAULT_ALGORITHM);
        let claims = Claims {
            iat: get_current_timestamp(),
            id: self.id.clone(),
            clv: self.clv.clone(),
        };
        Ok(encode(&header, &claims, &self.secret)?)
    }

    /// Validate a JWT token given the secret key.
    pub fn validate_token(token: &str, secret: &str) -> Result<(), Error> {
        let mut validation = jsonwebtoken::Validation::new(DEFAULT_ALGORITHM);
        validation.validate_exp = false;
        // Really weird that we have to do this to get the validation working
        validation.required_spec_claims.remove("exp");

        jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(hex::decode(secret)?.as_slice()),
            &validation,
        )
        .map(|_| ())
        .map_err(Into::into)
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
