use crate::{genesis_json::geth_genesis_json, SUPPRESS_LOGS};
use execution_layer::DEFAULT_JWT_FILE;
use sensitive_url::SensitiveUrl;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::{env, fs::File};
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
    http_port: u16,
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
            http_port,
            http_auth_port,
            child,
        }
    }

    pub fn http_url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", self.http_port)).unwrap()
    }

    pub fn http_auth_url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", self.http_auth_port)).unwrap()
    }

    pub fn datadir(&self) -> PathBuf {
        self.datadir.path().to_path_buf()
    }
}

/*
 * Geth-specific Implementation
 */

#[derive(Clone)]
pub struct Geth;

impl Geth {
    fn binary_path() -> PathBuf {
        let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
        manifest_dir
            .join("execution_clients")
            .join("go-ethereum")
            .join("build")
            .join("bin")
            .join("geth")
    }
}

impl GenericExecutionEngine for Geth {
    fn init_datadir() -> TempDir {
        let datadir = TempDir::new().unwrap();

        let genesis_json_path = datadir.path().join("genesis.json");
        let mut file = File::create(&genesis_json_path).unwrap();
        let json = geth_genesis_json();
        serde_json::to_writer(&mut file, &json).unwrap();

        let output = Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("init")
            .arg(genesis_json_path.to_str().unwrap())
            .output()
            .expect("failed to init geth");

        check_command_output(output, "geth init failed");

        datadir
    }

    fn start_client(
        datadir: &TempDir,
        http_port: u16,
        http_auth_port: u16,
        jwt_secret_path: PathBuf,
    ) -> Child {
        let network_port = unused_tcp_port().unwrap();

        Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("--http")
            .arg("--http.api")
            .arg("engine,eth")
            .arg("--http.port")
            .arg(http_port.to_string())
            .arg("--authrpc.port")
            .arg(http_auth_port.to_string())
            .arg("--port")
            .arg(network_port.to_string())
            .arg("--authrpc.jwtsecret")
            .arg(jwt_secret_path.as_path().to_str().unwrap())
            .stdout(build_stdio())
            .stderr(build_stdio())
            .spawn()
            .expect("failed to start beacon node")
    }
}

fn check_command_output(output: Output, failure_msg: &'static str) {
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        dbg!(stdout);
        dbg!(stderr);
        panic!("{}", failure_msg);
    }
}

/// Builds the stdout/stderr handler for commands which might output to the terminal.
fn build_stdio() -> Stdio {
    if SUPPRESS_LOGS {
        Stdio::null()
    } else {
        Stdio::inherit()
    }
}
