pub mod http_client;
pub mod std_types;
pub mod types;

/// The number of bytes in the secp256k1 public key used as the authorization token for the VC API.
pub const PK_LEN: usize = 33;

/// The prefix for the secp256k1 public key when it is used as the authorization token for the VC
/// API.
pub const SECRET_PREFIX: &str = "api-token-";
