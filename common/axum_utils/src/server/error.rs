#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("No router provided")]
    MissingRouter,

    #[error("No address provided")]
    MissingAddress,

    #[error("TLS configuration failed: {0}")]
    TlsConfigFailed(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Server failed: {0}")]
    ServerFailed(#[from] std::io::Error),
}
