use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer,
    pem::{self, PemObject},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Configuration used when serving the HTTP server over TLS.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Errors from loading the certificate chain and private key of a [`TlsConfig`].
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("unable to read {path:?}: {error}")]
    Read {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("invalid PEM in {path:?}: {error}")]
    Pem { path: PathBuf, error: pem::Error },
    #[error("{0}")]
    Rustls(#[from] rustls::Error),
}

impl TlsConfig {
    /// Load the PEM-encoded certificate chain and private key into a rustls server config.
    pub(crate) async fn load(&self) -> Result<RustlsConfig, TlsError> {
        let cert_pem = read(&self.cert).await?;
        let key_pem = read(&self.key).await?;

        let pem_error = |path: &Path, error| TlsError::Pem {
            path: path.to_path_buf(),
            error,
        };
        let cert_chain = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| pem_error(&self.cert, e))?;
        if cert_chain.is_empty() {
            return Err(pem_error(&self.cert, pem::Error::NoItemsFound));
        }
        let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| pem_error(&self.key, e))?;

        // Select the `ring` crypto provider explicitly. Binaries such as `lighthouse` link both
        // rustls crypto providers, in which case rustls has no default provider and panics if a
        // config is built without one.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        // Offer HTTP/2 and HTTP/1.1, as `axum-server` does for the configs it builds itself.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(RustlsConfig::from_config(Arc::new(config)))
    }
}

async fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
    tokio::fs::read(path).await.map_err(|error| TlsError::Read {
        path: path.to_path_buf(),
        error,
    })
}
