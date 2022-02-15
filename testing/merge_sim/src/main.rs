use execution_layer::{ExecutionLayer, PayloadAttributes, PayloadStatusV1Status};
use genesis_json::geth_genesis_json;
use sensitive_url::SensitiveUrl;
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, fs::File};
use task_executor::TaskExecutor;
use tempfile::TempDir;
use tokio::time::sleep;
use types::{Address, ChainSpec, EthSpec, Hash256, MainnetEthSpec, Uint256};

mod genesis_json;

const EXECUTION_ENGINE_START_TIMEOUT: Duration = Duration::from_secs(10);

struct ExecutionEngine<E> {
    engine: E,
    datadir: TempDir,
    http_port: u16,
    child: Child,
}

impl<E> Drop for ExecutionEngine<E> {
    fn drop(&mut self) {
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

struct Geth;

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

pub trait GenericExecutionEngine {
    fn init_datadir() -> TempDir;
    fn start_client(datadir: &TempDir, http_port: u16) -> Child;
}

impl GenericExecutionEngine for Geth {
    fn init_datadir() -> TempDir {
        let datadir = TempDir::new().unwrap();

        let genesis_json_path = datadir.path().join("genesis.json");
        let mut file = File::create(&genesis_json_path).unwrap();
        let json = geth_genesis_json();
        json.write(&mut file).unwrap();

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
        Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("--http")
            .arg("--http.api")
            .arg("engine,eth")
            .arg("--http.port")
            .arg(http_port.to_string())
            .spawn()
            .expect("failed to start beacon node")
    }
}

struct TestRig<E> {
    runtime: Arc<tokio::runtime::Runtime>,
    execution_layer: ExecutionLayer,
    execution_engine: ExecutionEngine<E>,
    spec: ChainSpec,
    _runtime_shutdown: exit_future::Signal,
}

impl<E: GenericExecutionEngine> TestRig<E> {
    pub fn new(execution_engine: ExecutionEngine<E>) -> Self {
        let log = environment::null_logger().unwrap();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (runtime_shutdown, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor = TaskExecutor::new(Arc::downgrade(&runtime), exit, log.clone(), shutdown_tx);

        let mut urls = vec![];
        urls.push(execution_engine.http_url());

        let fee_recipient = None;
        let execution_layer =
            ExecutionLayer::from_urls(urls, fee_recipient, executor, log).unwrap();

        let mut spec = MainnetEthSpec::default_spec();
        spec.terminal_total_difficulty = Uint256::zero();

        Self {
            runtime,
            execution_layer,
            execution_engine,
            spec,
            _runtime_shutdown: runtime_shutdown,
        }
    }

    pub fn perform_tests_blocking(&self) {
        self.execution_layer
            .block_on_generic(|_| async { self.perform_tests().await })
            .unwrap()
    }

    pub async fn wait_until_synced(&self) {
        let start_instant = Instant::now();

        loop {
            // Run the routine to check for online nodes.
            self.execution_layer.watchdog_task().await;

            if self.execution_layer.is_synced().await {
                break;
            } else {
                if start_instant + EXECUTION_ENGINE_START_TIMEOUT > Instant::now() {
                    sleep(Duration::from_millis(500)).await;
                } else {
                    panic!("timeout waiting for execution engines to come online")
                }
            }
        }
    }

    pub async fn perform_tests(&self) {
        self.wait_until_synced().await;

        let terminal_pow_block_hash = self
            .execution_layer
            .get_terminal_pow_block_hash(&self.spec)
            .await
            .unwrap()
            .unwrap();

        /*
         * Produce a valid payload atop the terminal block.
         */

        let parent_hash = terminal_pow_block_hash;
        let timestamp = timestamp_now();
        let random = Hash256::zero();
        let finalized_block_hash = Hash256::zero();
        let proposer_index = 0;
        let valid_payload = self
            .execution_layer
            .get_payload::<MainnetEthSpec>(
                parent_hash,
                timestamp,
                random,
                finalized_block_hash,
                proposer_index,
            )
            .await
            .unwrap();

        /*
         * Indicate that the payload is the head of the chain, before submitting a
         * `notify_new_payload`.
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = Hash256::zero();
        let payload_attributes = None;
        let (status, _) = self
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Syncing);

        /*
         * Provide the valid payload back to the EE again.
         */

        let (status, _) = self
            .execution_layer
            .notify_new_payload(&valid_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);

        /*
         * Indicate that the payload is the head of the chain.
         *
         * Do not provide payload attributes (we'll test that later).
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = Hash256::zero();
        let payload_attributes = None;
        let (status, _) = self
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);

        /*
         * Provide an invalidated payload to the EE.
         */

        let mut invalid_payload = valid_payload.clone();
        invalid_payload.random = Hash256::from_low_u64_be(42);
        let (status, _) = self
            .execution_layer
            .notify_new_payload(&invalid_payload)
            .await
            .unwrap();
        assert!(matches!(
            status,
            PayloadStatusV1Status::Invalid | PayloadStatusV1Status::InvalidBlockHash
        ));

        /*
         * Produce another payload atop the previous one.
         */

        let parent_hash = valid_payload.block_hash;
        let timestamp = valid_payload.timestamp + 1;
        let random = Hash256::zero();
        let finalized_block_hash = Hash256::zero();
        let proposer_index = 0;
        let second_payload = self
            .execution_layer
            .get_payload::<MainnetEthSpec>(
                parent_hash,
                timestamp,
                random,
                finalized_block_hash,
                proposer_index,
            )
            .await
            .unwrap();

        /*
         * Provide the second payload back to the EE again.
         */

        let (status, _) = self
            .execution_layer
            .notify_new_payload(&second_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);

        /*
         * Indicate that the payload is the head of the chain, providing payload attributes.
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = Hash256::zero();
        let payload_attributes = PayloadAttributes {
            timestamp: second_payload.timestamp + 1,
            random: Hash256::zero(),
            suggested_fee_recipient: Address::zero(),
        };
        let (status, _) = self
            .execution_layer
            .notify_forkchoice_updated(
                head_block_hash,
                finalized_block_hash,
                Some(payload_attributes),
            )
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);
    }
}

fn main() {
    let geth_rig = TestRig::new(ExecutionEngine::new(Geth));
    geth_rig.perform_tests_blocking();
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

/// Returns the duration since the unix epoch.
pub fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
