use crate::build_utils;
use crate::execution_engine::GenericExecutionEngine;
use crate::genesis_json::nethermind_genesis_json;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::{env, fs::File};
use tempfile::TempDir;
use unused_port::unused_tcp_port;

const NETHERMIND_BRANCH: &str = "kiln";
const NETHERMIND_REPO_URL: &str = "https://github.com/NethermindEth/nethermind";

fn build_result(repo_dir: &Path) -> Output {
    Command::new("dotnet")
        .arg("build")
        .arg("src/Nethermind/Nethermind.sln")
        .arg("-c")
        .arg("Release")
        .current_dir(repo_dir)
        .output()
        .expect("failed to make nethermind")
}

pub fn build(execution_clients_dir: &Path) {
    let repo_dir = execution_clients_dir.join("nethermind");

    if !repo_dir.exists() {
        // Clone the repo
        assert!(build_utils::clone_repo(
            execution_clients_dir,
            NETHERMIND_REPO_URL
        ));
    }

    // Checkout the correct branch
    assert!(build_utils::checkout_branch(&repo_dir, NETHERMIND_BRANCH));

    // Update the branch
    assert!(build_utils::update_branch(&repo_dir, NETHERMIND_BRANCH));

    // Build nethermind
    build_utils::check_command_output(build_result(&repo_dir), "dotnet build failed");

    // Build nethermind a second time to enable Merge-related features.
    // Not sure why this is necessary.
    build_utils::check_command_output(build_result(&repo_dir), "dotnet build failed");
}

/*
 * Nethermind-specific Implementation for GenericExecutionEngine
 */

#[derive(Clone)]
pub struct NethermindEngine;

impl NethermindEngine {
    fn binary_path() -> PathBuf {
        let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
        manifest_dir
            .join("execution_clients")
            .join("nethermind")
            .join("src")
            .join("Nethermind")
            .join("Nethermind.Runner")
            .join("bin")
            .join("Release")
            .join("net6.0")
            .join("Nethermind.Runner")
    }
}

impl GenericExecutionEngine for NethermindEngine {
    fn init_datadir() -> TempDir {
        let datadir = TempDir::new().unwrap();

        let genesis_json_path = datadir.path().join("genesis.json");
        let mut file = File::create(&genesis_json_path).unwrap();
        let json = nethermind_genesis_json();
        serde_json::to_writer(&mut file, &json).unwrap();

        datadir
    }

    fn start_client(
        datadir: &TempDir,
        http_port: u16,
        http_auth_port: u16,
        jwt_secret_path: PathBuf,
    ) -> Child {
        let network_port = unused_tcp_port().unwrap();
        let genesis_json_path = datadir.path().join("genesis.json");

        Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("--config")
            .arg("themerge_kiln_testvectors")
            .arg("--Init.ChainSpecPath")
            .arg(genesis_json_path.to_str().unwrap())
            .arg("--JsonRpc.AdditionalRpcUrls")
            .arg(format!("http://localhost:{}|http;ws|net;eth;subscribe;engine;web3;client|no-auth,http://localhost:{}|http;ws|net;eth;subscribe;engine;web3;client", http_port, http_auth_port))
            .arg("--JsonRpc.EnabledModules")
            .arg("net,eth,subscribe,web3,admin,engine")
            .arg("--JsonRpc.Port")
            .arg(http_port.to_string())
            .arg("--Network.DiscoveryPort")
            .arg(network_port.to_string())
            .arg("--Network.P2PPort")
            .arg(network_port.to_string())
            .arg("--JsonRpc.JwtSecretFile")
            .arg(jwt_secret_path.as_path().to_str().unwrap())
            .stdout(build_utils::build_stdio())
            .stderr(build_utils::build_stdio())
            .spawn()
            .expect("failed to start nethermind")
    }
}
