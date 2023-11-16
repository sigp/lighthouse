use ethers_providers::{Http, Provider};
use execution_layer::DEFAULT_JWT_FILE;
use sensitive_url::SensitiveUrl;
use std::path::PathBuf;
use std::process::Child;
use tempfile::TempDir;
use unused_port::unused_tcp4_port;

pub const KEYSTORE_PASSWORD: &str = "testpwd";
pub const ACCOUNT1: &str = "7b8C3a386C0eea54693fFB0DA17373ffC9228139";
pub const ACCOUNT2: &str = "dA2DD7560DB7e212B945fC72cEB54B7D8C886D77";
pub const PRIVATE_KEYS: [&str; 2] = [
    "115fe42a60e5ef45f5490e599add1f03c73aeaca129c2c41451eca6cf8ff9e04",
    "6a692e710077d9000be1326acbe32f777b403902ac8779b19eb1398b849c99c3",
];

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
    http_port: u16,
    http_auth_port: u16,
    child: Child,
    pub provider: Provider<Http>,
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
        let http_port = unused_tcp4_port().unwrap();
        let http_auth_port = unused_tcp4_port().unwrap();
        let child = E::start_client(&datadir, http_port, http_auth_port, jwt_secret_path);
        let provider = Provider::<Http>::try_from(format!("http://localhost:{}", http_port))
            .expect("failed to instantiate ethers provider");
        Self {
            engine,
            datadir,
            http_port,
            http_auth_port,
            child,
            provider,
        }
    }

    pub fn http_auth_url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", self.http_auth_port)).unwrap()
    }

    pub fn http_url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", self.http_port)).unwrap()
    }

    pub fn datadir(&self) -> PathBuf {
        self.datadir.path().to_path_buf()
    }
}
