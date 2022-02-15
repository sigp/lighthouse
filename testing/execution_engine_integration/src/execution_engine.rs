use crate::genesis_json::geth_genesis_json;
use sensitive_url::SensitiveUrl;
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::{env, fs::File};
use tempfile::TempDir;

/// Defined for each EE type (e.g., Geth, Nethermind, etc).
pub trait GenericExecutionEngine: Clone {
    fn init_datadir() -> TempDir;
    fn start_client(datadir: &TempDir, http_port: u16) -> Child;
}

/// Holds handle to a running EE process, plus some other metadata.
pub struct ExecutionEngine<E> {
    #[allow(dead_code)]
    engine: E,
    #[allow(dead_code)]
    datadir: TempDir,
    http_port: u16,
    child: Child,
}

impl<E> Drop for ExecutionEngine<E> {
    fn drop(&mut self) {
        // Ensure the EE process is killed on drop.
        self.child.kill().unwrap()
    }
}

impl<E: GenericExecutionEngine> ExecutionEngine<E> {
    pub fn new(engine: E) -> Self {
        let datadir = E::init_datadir();
        let http_port = unused_port("tcp").unwrap();
        let child = E::start_client(&datadir, http_port);
        Self {
            engine,
            datadir,
            http_port,
            child,
        }
    }

    pub fn http_url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", self.http_port)).unwrap()
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

    fn start_client(datadir: &TempDir, http_port: u16) -> Child {
        let network_port = unused_port("tcp").unwrap();

        Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("--http")
            .arg("--http.api")
            .arg("engine,eth")
            .arg("--http.port")
            .arg(http_port.to_string())
            .arg("--port")
            .arg(network_port.to_string())
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

/// A bit of hack to find an unused port.
///
/// Does not guarantee that the given port is unused after the function exits, just that it was
/// unused before the function started (i.e., it does not reserve a port).
pub fn unused_port(transport: &str) -> Result<u16, String> {
    let local_addr = match transport {
        "tcp" => {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| {
                format!("Failed to create TCP listener to find unused port: {:?}", e)
            })?;
            listener.local_addr().map_err(|e| {
                format!(
                    "Failed to read TCP listener local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
        "udp" => {
            let socket = UdpSocket::bind("127.0.0.1:0")
                .map_err(|e| format!("Failed to create UDP socket to find unused port: {:?}", e))?;
            socket.local_addr().map_err(|e| {
                format!(
                    "Failed to read UDP socket local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
        _ => return Err("Invalid transport to find unused port".into()),
    };
    Ok(local_addr.port())
}
