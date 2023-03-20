use crate::build_utils;
use crate::execution_engine::GenericExecutionEngine;
use crate::genesis_json::geth_genesis_json;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::{env, fs::File};
use tempfile::TempDir;
use unused_port::unused_tcp4_port;

const GETH_BRANCH: &str = "master";
const GETH_REPO_URL: &str = "https://github.com/ethereum/go-ethereum";

pub fn build_result(repo_dir: &Path) -> Output {
    Command::new("make")
        .arg("geth")
        .current_dir(repo_dir)
        .output()
        .expect("failed to make geth")
}

pub fn build(execution_clients_dir: &Path) {
    let repo_dir = execution_clients_dir.join("go-ethereum");

    if !repo_dir.exists() {
        // Clone the repo
        build_utils::clone_repo(execution_clients_dir, GETH_REPO_URL).unwrap();
    }

    // Get the latest tag on the branch
    let last_release = build_utils::get_latest_release(&repo_dir, GETH_BRANCH).unwrap();
    build_utils::checkout(&repo_dir, dbg!(&last_release)).unwrap();

    // Build geth
    build_utils::check_command_output(build_result(&repo_dir), || {
        format!("geth make failed using release {last_release}")
    });
}

/*
 * Geth-specific Implementation for GenericExecutionEngine
 */

#[derive(Clone)]
pub struct GethEngine;

impl GethEngine {
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

impl GenericExecutionEngine for GethEngine {
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

        build_utils::check_command_output(output, || "geth init failed".into());

        datadir
    }

    fn start_client(
        datadir: &TempDir,
        http_port: u16,
        http_auth_port: u16,
        jwt_secret_path: PathBuf,
    ) -> Child {
        let network_port = unused_tcp4_port().unwrap();

        Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("--http")
            .arg("--http.api")
            .arg("engine,eth,personal")
            .arg("--http.port")
            .arg(http_port.to_string())
            .arg("--authrpc.port")
            .arg(http_auth_port.to_string())
            .arg("--port")
            .arg(network_port.to_string())
            .arg("--allow-insecure-unlock")
            .arg("--authrpc.jwtsecret")
            .arg(jwt_secret_path.as_path().to_str().unwrap())
            // This flag is required to help Geth perform reliably when feeding it blocks
            // one-by-one. For more information, see:
            //
            // https://github.com/sigp/lighthouse/pull/3382#issuecomment-1197680345
            .arg("--syncmode=full")
            .stdout(build_utils::build_stdio())
            .stderr(build_utils::build_stdio())
            .spawn()
            .expect("failed to start geth")
    }
}
