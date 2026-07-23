use crate::{
    server::{Server, error::BuilderError},
    tls::TlsConfig,
};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

pub struct ServerBuilder {
    router: Router,
    address: SocketAddr,
    tls_config: Option<TlsConfig>,
}

impl ServerBuilder {
    pub fn new(router: Router, address: SocketAddr) -> Self {
        Self {
            router,
            address,
            tls_config: None,
        }
    }

    pub fn with_tls(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub async fn build(self) -> Result<Server, BuilderError> {
        let rustls_config = if let Some(tls) = self.tls_config {
            Some(RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?)
        } else {
            None
        };

        Ok(Server {
            router: self.router,
            address: self.address,
            rustls_config,
        })
    }
}
