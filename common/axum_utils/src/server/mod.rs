mod builder;
mod error;

pub use builder::ServerBuilder;
pub use error::{BuilderError, ServerError};

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

pub struct Server {
    pub(crate) router: Router,
    pub(crate) address: SocketAddr,
    pub(crate) rustls_config: Option<RustlsConfig>,
}

impl Server {
    /// Initialize a new server builder.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Get information about the server configuration.
    pub fn info(&self) -> ServerInfo {
        ServerInfo {
            address: self.address,
            protocol: if self.rustls_config.is_some() {
                Protocol::Https
            } else {
                Protocol::Http
            },
        }
    }

    /// Serve the application indefinitely.
    pub async fn serve(self) -> Result<(), ServerError> {
        self.serve_with_shutdown(std::future::pending()).await
    }

    /// Serve the application until the shutdown signal is received.
    pub async fn serve_with_shutdown<F>(self, shutdown_signal: F) -> Result<(), ServerError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = axum_server::Handle::new();

        tokio::spawn({
            let handle = handle.clone();
            async move {
                shutdown_signal.await;
                handle.graceful_shutdown(None);
            }
        });

        match self.rustls_config {
            Some(config) => {
                axum_server::bind_rustls(self.address, config)
                    .handle(handle)
                    .serve(self.router.into_make_service())
                    .await
                    .map_err(ServerError::ServerFailed)?;
            }
            None => {
                axum_server::bind(self.address)
                    .handle(handle)
                    .serve(self.router.into_make_service())
                    .await
                    .map_err(ServerError::ServerFailed)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ServerInfo {
    pub address: SocketAddr,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Http => write!(f, "http"),
            Protocol::Https => write!(f, "https"),
        }
    }
}
