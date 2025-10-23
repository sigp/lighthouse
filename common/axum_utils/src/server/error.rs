#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("No router provided")]
    MissingRouter,

    #[error("No address provided")]
    MissingAddress,

    #[error("TLS configuration failed")]
    TlsConfigFailed(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Server failed")]
    ServerFailed(#[from] std::io::Error),
}
