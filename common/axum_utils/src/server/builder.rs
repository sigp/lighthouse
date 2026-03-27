use std::net::SocketAddr;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

use crate::{
    server::{Server, error::BuilderError},
    tls::TlsConfig,
};

pub struct ServerBuilder {
    router: Option<Router>,
    address: Option<SocketAddr>,
    tls_config: Option<TlsConfig>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            router: None,
            address: None,
            tls_config: None,
        }
    }

    pub fn router(mut self, router: Router) -> Self {
        self.router = Some(router);
        self
    }

    pub fn address(mut self, address: SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    pub fn with_tls(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub async fn build(self) -> Result<Server, BuilderError> {
        let router = self.router.ok_or(BuilderError::MissingRouter)?;
        let address = self.address.ok_or(BuilderError::MissingAddress)?;

        let rustls_config = if let Some(tls) = self.tls_config {
            Some(
                RustlsConfig::from_pem_file(&tls.cert, &tls.key)
                    .await
                    .map_err(BuilderError::TlsConfigFailed)?,
            )
        } else {
            None
        };

        Ok(Server {
            router,
            address,
            rustls_config,
        })
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
