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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::TlsConfig;
    use axum::routing::get;

    /// Serve a router over TLS and fetch a page from it over HTTPS.
    ///
    /// Regression test for https://github.com/sigp/lighthouse/issues/10598.
    #[tokio::test]
    async fn serve_over_tls() {
        let certified_key =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_pem = certified_key.cert.pem();

        let tls_dir = tempfile::tempdir().unwrap();
        let cert = tls_dir.path().join("cert.pem");
        let key = tls_dir.path().join("key.pem");
        std::fs::write(&cert, &cert_pem).unwrap();
        std::fs::write(&key, certified_key.key_pair.serialize_pem()).unwrap();

        let router = Router::new().route("/", get(|| async { "hello" }));
        let server = Server::builder(router, SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_tls(TlsConfig { cert, key })
            .build()
            .await
            .unwrap();
        assert_eq!(server.info().protocol, Protocol::Https);

        let (address, server_future) = server
            .serve_with_shutdown(std::future::pending())
            .await
            .unwrap();
        tokio::spawn(server_future);

        // Trust only the server's certificate, so the request succeeds only if the TLS handshake
        // with that certificate does.
        let client = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let response = client
            .get(format!("https://{address}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "hello");
    }
}
