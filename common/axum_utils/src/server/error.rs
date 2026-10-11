#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("TLS configuration failed: {0}")]
    TlsConfigFailed(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Server failed: {0}")]
    ServerFailed(#[from] std::io::Error),
}
