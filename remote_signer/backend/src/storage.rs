use crate::{BackendError, ZeroizeString};

/// The storage medium for the secret keys used by a `Backend`.
pub trait Storage: 'static + Clone + Send + Sync {
    /// Queries storage for the available keys to sign.
    fn get_keys(&self) -> Result<Vec<String>, BackendError>;

    /// Retrieves secret key from storage, using its public key as reference.
    fn get_secret_key(&self, input: &str) -> Result<ZeroizeString, BackendError>;
}
