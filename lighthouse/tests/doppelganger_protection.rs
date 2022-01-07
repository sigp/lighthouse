use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
use sensitive_url::SensitiveUrl;
use std::process::{Command, Child, ExitStatus};
use std::path::PathBuf;
use std::{io, thread, time, fs};

const BEACON_CMD: &str = "beacon_node";
const VALIDATOR_CMD: &str = "validator_client";
const BOOTNODE_CMD: &str = "bootnode";

// 0. start ganache
// 1. generate ENR
// 2. start bootnode
// 3. deploy deposit contract
// 4. new testnet
// 5. insecure validators
// 6. interop genesis

use lcli::new_app;

#[derive(Debug)]
pub struct SimProcess {
    // should command be consumed?
    cmd: Command,
    process: Option<Child>,
}

impl Drop for SimProcess {
    fn drop(&mut self){
        if self.process.is_some() {
            self.kill_process();
        }
    }
}

impl SimProcess {
    pub fn new(base_cmd_name: &str) -> SimProcess {
        let lighthouse_bin = env!("CARGO_BIN_EXE_lighthouse");
        let path = lighthouse_bin
            .parse::<PathBuf>()
            .expect("should parse CARGO_TARGET_DIR");

        let mut cmd = Command::new(path);
        cmd.arg(base_cmd_name);
        SimProcess { cmd, process: None }
    }

    pub fn new_from_base_cmd(base_cmd: Command) -> SimProcess {
        SimProcess { cmd: base_cmd, process: None }
    }

    pub fn new_beacon() -> SimProcess {
        Self::new(BEACON_CMD)
    }

    pub fn new_validator() -> SimProcess {
        Self::new(VALIDATOR_CMD)
    }

    pub fn new_bootnode() -> SimProcess {
        Self::new(BOOTNODE_CMD)
    }

    pub fn flag(mut self, flag: &str, value: Option<&str>) -> Self {
        // Build the command by adding the flag and any values.
        self.cmd.arg(format!("--{}", flag));
        if let Some(value) = value {
            self.cmd.arg(value);
        }
        self
    }

    pub fn spawn_no_wait(mut self) -> Self {
        dbg!(&self.cmd);
        self.process = Some(self.cmd.spawn().expect("should start process"));
        self
    }

    pub fn spawn_and_wait(&mut self) -> ExitStatus {
        dbg!(&self.cmd);

        self.cmd.spawn().expect("should start process").wait().expect("spawned process should be running")
    }

    pub fn wait(&mut self) -> ExitStatus {
        self.process.as_mut().expect("simulator process should be running").wait().expect("child process should be running")
    }

    pub fn kill_process(&mut self) {
        self.process.as_mut().expect("simulator process should be running").kill().expect("child process should be running")
    }
}

fn clean() {
    let source_dir = env!("CARGO_MANIFEST_DIR");
    let clean_location = format!("{}{}", source_dir, "/../scripts/local_testnet/clean.sh");

    let mut cmd = Command::new("sh");
    cmd.arg(clean_location);
    let mut process = SimProcess::new_from_base_cmd(cmd);

    process.spawn_and_wait();
}

fn bootnode() -> SimProcess {
    let source_dir = env!("CARGO_MANIFEST_DIR");
    let bootnode = format!("{}{}", source_dir, "/../scripts/local_testnet/bootnode.sh");

    let mut cmd = Command::new("sh");
    cmd.arg(bootnode);
    let process = SimProcess::new_from_base_cmd(cmd);

    let process = process.spawn_no_wait();

    // Need to give the bootnode time to start up
    thread::sleep(time::Duration::from_secs(5));

    process
}

fn setup() {
    let source_dir = env!("CARGO_MANIFEST_DIR");

    let setup_location = format!("{}{}", source_dir, "/../scripts/local_testnet/setup.sh");

    let mut cmd = Command::new("sh");
    cmd.arg(setup_location);
    let mut process = SimProcess::new_from_base_cmd(cmd);

    process.spawn_and_wait();
}

fn ganache() -> SimProcess {

    let mut cmd = Command::new("ganache-cli");

    let mut process = SimProcess {
        cmd,
        process: None,
    };

    let process = process.flag("defaultBalanceEther", Some("1000000000"))
        .flag("gasLimit", Some("1000000000"))
        .flag("accounts", Some("10"))
        .flag("mnemonic", Some("'vast thought differ pull jewel broom cook wrist tribe word before omit'"))
        .flag("port", Some("8545"))
        .flag("blockTime", Some("1"))
        .flag("networkId", Some("4242"))
        .flag("chainId", Some("4242"));

    let process = process.spawn_no_wait();

    // Need to give ganache time to start up
    thread::sleep(time::Duration::from_secs(5));

    process

}

fn setup() -> SimProcess {
    clean();
    let ganache = ganache();
    setup_ganache();
    ganache
}

fn spawn_beacon(port: usize, http_port: usize, index: usize) -> SimProcess {
    SimProcess::new_beacon()
        .flag("http-port", Some(&format!("{}", http_port)))
        .flag("port", Some(&format!("{}", port)))
        .flag("datadir", Some(&format!("{}{}", "~/.lighthouse/local-testnet/node_", index)))
        .flag("testnet-dir", Some(&format!("{}", "~/.lighthouse/local-testnet/testnet")))
        .spawn_no_wait()
}

fn spawn_validator(beacon_port: usize, http_port: usize,index: usize) -> (SimProcess, ValidatorClientHttpClient) {
    let datadir = format!("{}{}", "~/.lighthouse/local-testnet/node_", index);
    let url = format!("{}{}", "http://localhost:", beacon_port);
    let process = SimProcess::new_validator()
        .flag("debug-level", Some("debug"))
        .flag("init-slashing-protection", None)
        .flag("enable-doppelganger-protection", None)
        .flag("http-port",  Some(&format!("{}",http_port)))
        .flag("beacon-nodes", Some(&url))
        .flag("datadir", Some(&datadir))
        .flag("testnet-dir", Some(&format!("{}", "~/.lighthouse/local-testnet/testnet")))
        .spawn_no_wait();
    thread::sleep(time::Duration::from_secs(20));

    let token_path = PathBuf::from(format!("{}{}", datadir, "/validators/api-token.txt"));
    dbg!(&token_path);
    let secret = fs::read_to_string(token_path).expect("should read API token from file");
    let http_client = ValidatorClientHttpClient::new(SensitiveUrl::parse(&url).expect("should create HTTP client"),secret).expect("should create HTTP client");
    (process, http_client)
}

#[test]
fn datadir_flag() {

    let ganache = setup();

    // let boot_node = bootnode();
    let beacon_1 = spawn_beacon(9100,8100,1);
    // let beacon_2 = spawn_beacon(9200,8200,2);
    // let beacon_3 = spawn_beacon(9300,8300,3);
    // let beacon_4 = spawn_beacon(9400,8400,4);
    //
    let (validator_1, _) = spawn_validator(8100,8150,1);
    // let (validator_2, _) = spawn_validator(8200,None,2);
    // let (validator_3, _) = spawn_validator(8300,None,3);
    // let (validator_4, _) = spawn_validator(8400,None,4);


    thread::sleep(time::Duration::from_secs(5));
    dbg!(&beacon_1);
    // dbg!(&validator_1.process);

}