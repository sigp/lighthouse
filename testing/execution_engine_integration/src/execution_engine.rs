use execution_layer::DEFAULT_JWT_FILE;
use sensitive_url::SensitiveUrl;
use std::path::PathBuf;
use std::process::Child;
use tempfile::TempDir;
use unused_port::unused_tcp_port;

/// Defined for each EE type (e.g., Geth, Nethermind, etc).
pub trait GenericExecutionEngine: Clone {
    fn init_datadir() -> TempDir;
    fn start_client(
        datadir: &TempDir,
        http_port: u16,
        http_auth_port: u16,
        jwt_secret_path: PathBuf,
    ) -> Child;
}

/// Holds handle to a running EE process, plus some other metadata.
pub struct ExecutionEngine<E> {
    #[allow(dead_code)]
    engine: E,
    #[allow(dead_code)]
    datadir: TempDir,
    http_auth_port: u16,
    child: Child,
}

impl<E> Drop for ExecutionEngine<E> {
    fn drop(&mut self) {
        // Ensure the EE process is killed on drop.
        if let Err(e) = self.child.kill() {
            eprintln!("failed to kill child: {:?}", e)
        }
    }
}

impl<E: GenericExecutionEngine> ExecutionEngine<E> {
    pub fn new(engine: E) -> Self {
        let datadir = E::init_datadir();
        let jwt_secret_path = datadir.path().join(DEFAULT_JWT_FILE);
        let http_port = unused_tcp_port().unwrap();
        let http_auth_port = unused_tcp_port().unwrap();
        let child = E::start_client(&datadir, http_port, http_auth_port, jwt_secret_path);
        Self {
            engine,
            datadir,
            http_auth_port,
            child,
        }
    }

    pub fn http_auth_url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", self.http_auth_port)).unwrap()
    }

    pub fn datadir(&self) -> PathBuf {
        self.datadir.path().to_path_buf()
    }
}
