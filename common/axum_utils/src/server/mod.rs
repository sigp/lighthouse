mod builder;
mod error;

pub use builder::ServerBuilder;
pub use error::{BuilderError, ServerError};

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::time::Duration;

/// Default timeout for graceful shutdown. After this duration, the server will
/// stop waiting for existing connections and shut down immediately.
const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Server {
    pub(crate) router: Router,
    pub(crate) address: SocketAddr,
    pub(crate) rustls_config: Option<RustlsConfig>,
}

impl Server {
    /// Initialize a new server builder.
    pub fn builder(router: Router, address: SocketAddr) -> ServerBuilder {
        ServerBuilder::new(router, address)
    }

    /// Get information about the server configuration.
    ///
    /// Note that the address is only the configured address, not the actual address
    /// the server is listening on (such as when using port 0).
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

    /// Serve the application until the shutdown signal is received.
    /// Returns the actual address the server is listening on.
    pub async fn serve_with_shutdown<F>(
        self,
        shutdown_signal: F,
    ) -> Result<(SocketAddr, impl Future<Output = Result<(), ServerError>>), ServerError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let tokio_listener = tokio::net::TcpListener::bind(self.address).await?;

        let actual_addr = tokio_listener.local_addr()?;

        let listener = tokio_listener.into_std()?;

        let handle = axum_server::Handle::new();

        let server_future = async move {
            // Spawn a task that triggers graceful shutdown when the signal fires.
            // If the server exits before the signal, this task will linger until the
            // signal resolves, which is harmless.
            let shutdown_handle = tokio::spawn({
                let handle = handle.clone();
                async move {
                    shutdown_signal.await;
                    handle.graceful_shutdown(Some(DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT));
                }
            });

            let result = match self.rustls_config {
                Some(config) => {
                    axum_server::from_tcp_rustls(listener, config)
                        .handle(handle)
                        .serve(self.router.into_make_service())
                        .await
                }
                None => {
                    axum_server::from_tcp(listener)
                        .handle(handle)
                        .serve(self.router.into_make_service())
                        .await
                }
            };

            // Abort the shutdown listener if it's still running (server exited first).
            shutdown_handle.abort();

            result.map_err(ServerError::ServerFailed)
        };

        Ok((actual_addr, server_future))
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
