#[derive(Debug)]
pub enum BackendError {
    /// Parameter is not a hexadecimal representation of a BLS public key.
    InvalidPublicKey(String),

    /// Retrieved value is not a hexadecimal representation of a BLS secret key.
    InvalidSecretKey(String),

    /// Public and Secret key won't match.
    KeyMismatch(String),

    /// Item requested by its public key is not found.
    KeyNotFound(String),

    /// Errors from the storage medium.
    ///
    /// When converted from `std::io::Error`, stores `std::io::ErrorKind`
    /// and `std::io::Error` both formatted to string.
    StorageError(String, String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BackendError::InvalidPublicKey(e) => write!(f, "Invalid public key: {}", e),

            // Feed it with the public key value used to retrieve it.
            BackendError::InvalidSecretKey(e) => write!(f, "Invalid secret key: {}", e),

            // Feed it with the public key value used to retrieve it.
            BackendError::KeyMismatch(e) => write!(f, "Key mismatch: {}", e),

            BackendError::KeyNotFound(e) => write!(f, "Key not found: {}", e),

            // Only outputs to string the first component of the tuple, accounting
            // for potential differences on error displays between OS distributions.
            BackendError::StorageError(e, _) => write!(f, "Storage error: {}", e),
        }
    }
}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> BackendError {
        BackendError::StorageError(format!("{:?}", e.kind()), format!("{}", e))
    }
}
