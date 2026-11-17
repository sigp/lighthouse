use crate::{
    server::{Server, error::BuilderError},
    tls::TlsConfig,
};
use axum::Router;
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
            Some(tls.load().await?)
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
