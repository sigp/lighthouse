use validator_client::Config;

use bls::{Keypair, PublicKeyBytes};
use serde_json::from_reader;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str::from_utf8;
use std::string::ToString;
use tempfile::TempDir;

const VALIDATOR_CMD: &str = "validator_client";
const CONFIG_NAME: &str = "vc_dump.json";
const DUMP_CONFIG_CMD: &str = "dump-config";
const IMMEDIATE_SHUTDOWN_CMD: &str = "immediate-shutdown";

/// Returns the `lighthouse validator_client --immediate-shutdown` command.
fn base_cmd() -> Command {
    let lighthouse_bin = env!("CARGO_BIN_EXE_lighthouse");
    let path = lighthouse_bin
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR");

    let mut cmd = Command::new(path);
    cmd.arg(VALIDATOR_CMD)
        .arg(format!("--{}", IMMEDIATE_SHUTDOWN_CMD));

    cmd
}

/// Executes a `Command`, returning a `Result` based upon the success exit code of the command.
fn output_result(cmd: &mut Command) -> Result<Output, String> {
    let output = cmd.output().expect("should run command");

    if output.status.success() {
        Ok(output)
    } else {
        Err(from_utf8(&output.stderr)
            .expect("stderr is not utf8")
            .to_string())
    }
}

// Wrapper around `Command` for easier Command Line Testing.
struct CommandLineTest {
    cmd: Command,
}
impl CommandLineTest {
    fn new() -> CommandLineTest {
        let base_cmd = base_cmd();
        CommandLineTest { cmd: base_cmd }
    }

    fn flag(mut self, flag: &str, value: Option<&str>) -> Self {
        // Build the command by adding the flag and any values.
        self.cmd.arg(format!("--{}", flag));
        if let Some(value) = value {
            self.cmd.arg(value);
        }
        self
    }

    fn run(&mut self) -> CompletedTest {
        // Setup temp directories.
        let tmp_dir = TempDir::new().expect("Unable to create temporary directory");
        let tmp_path: PathBuf = tmp_dir.path().join(CONFIG_NAME);

        // Add --datadir <temp_dir> --dump-config <temp_path> to cmd.
        self.cmd
            .arg("--datadir")
            .arg(tmp_dir.path().as_os_str())
            .arg(format!("--{}", DUMP_CONFIG_CMD))
            .arg(tmp_path.as_os_str());

        // Run the command.
        let _output = output_result(&mut self.cmd).expect("Unable to run command");

        // Grab the config.
        let config: Config =
            from_reader(File::open(tmp_path).expect("Unable to open dumped config"))
                .expect("Unable to deserialize to ClientConfig");
        CompletedTest {
            config,
            dir: tmp_dir,
        }
    }

    // In order to test custom validator and secrets directory flags,
    // datadir cannot be defined.
    fn run_with_no_datadir(&mut self) -> CompletedTest {
        // Setup temp directories
        let tmp_dir = TempDir::new().expect("Unable to create temporary directory");
        let tmp_path: PathBuf = tmp_dir.path().join(CONFIG_NAME);

        // Add --dump-config <temp_path> to cmd.
        self.cmd
            .arg(format!("--{}", DUMP_CONFIG_CMD))
            .arg(tmp_path.as_os_str());

        // Run the command.
        let _output = output_result(&mut self.cmd).expect("Unable to run command");

        // Grab the config.
        let config: Config =
            from_reader(File::open(tmp_path).expect("Unable to open dumped config"))
                .expect("Unable to deserialize to ClientConfig");
        CompletedTest {
            config,
            dir: tmp_dir,
        }
    }
}
struct CompletedTest {
    config: Config,
    dir: TempDir,
}
impl CompletedTest {
    fn with_config<F: Fn(&Config)>(self, func: F) {
        func(&self.config);
    }
    fn with_config_and_dir<F: Fn(&Config, &TempDir)>(self, func: F) {
        func(&self.config, &self.dir);
    }
}

#[test]
fn datadir_flag() {
    CommandLineTest::new()
        .run()
        .with_config_and_dir(|config, dir| {
            assert_eq!(config.validator_dir, dir.path().join("validators"));
            assert_eq!(config.secrets_dir, dir.path().join("secrets"));
        });
}

#[test]
fn validators_and_secrets_dir_flags() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("validators-dir", dir.path().join("validators").to_str())
        .flag("secrets-dir", dir.path().join("secrets").to_str())
        .run_with_no_datadir()
        .with_config(|config| {
            assert_eq!(config.validator_dir, dir.path().join("validators"));
            assert_eq!(config.secrets_dir, dir.path().join("secrets"));
        });
}

#[test]
fn beacon_nodes_flag() {
    CommandLineTest::new()
        .flag(
            "beacon-nodes",
            Some("http://localhost:1001,https://project:secret@infura.io/"),
        )
        .run()
        .with_config(|config| {
            assert_eq!(
                config.beacon_nodes[0].full.to_string(),
                "http://localhost:1001/"
            );
            assert_eq!(config.beacon_nodes[0].to_string(), "http://localhost:1001/");
            assert_eq!(
                config.beacon_nodes[1].full.to_string(),
                "https://project:secret@infura.io/"
            );
            assert_eq!(config.beacon_nodes[1].to_string(), "https://infura.io/");
        });
}

#[test]
fn allow_unsynced_flag() {
    CommandLineTest::new()
        .flag("allow-unsynced", None)
        .run()
        .with_config(|config| assert!(config.allow_unsynced_beacon_node));
}

#[test]
fn disable_auto_discover_flag() {
    CommandLineTest::new()
        .flag("disable-auto-discover", None)
        .run()
        .with_config(|config| assert!(config.disable_auto_discover));
}

#[test]
fn init_slashing_protections_flag() {
    CommandLineTest::new()
        .flag("init-slashing-protection", None)
        .run()
        .with_config(|config| assert!(config.init_slashing_protection));
}

// Tests for Graffiti flags.
#[test]
fn graffiti_flag() {
    CommandLineTest::new()
        .flag("graffiti", Some("nice-graffiti"))
        .run()
        .with_config(|config| {
            assert_eq!(
                config.graffiti.unwrap().to_string(),
                "0x6e6963652d677261666669746900000000000000000000000000000000000000"
            )
        });
}
#[test]
fn graffiti_file_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let mut file = File::create(dir.path().join("graffiti.txt")).expect("Unable to create file");
    let new_key = Keypair::random();
    let pubkeybytes = PublicKeyBytes::from(new_key.pk);
    let contents = "default:nice-graffiti";
    file.write_all(contents.as_bytes())
        .expect("Unable to write to file");
    CommandLineTest::new()
        .flag(
            "graffiti-file",
            dir.path().join("graffiti.txt").as_os_str().to_str(),
        )
        .run()
        .with_config(|config| {
            // Public key not present so load default.
            assert_eq!(
                config
                    .graffiti_file
                    .clone()
                    .unwrap()
                    .load_graffiti(&pubkeybytes)
                    .unwrap()
                    .unwrap()
                    .to_string(),
                "0x6e6963652d677261666669746900000000000000000000000000000000000000"
            )
        });
}
#[test]
fn graffiti_file_with_pk_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let mut file = File::create(dir.path().join("graffiti.txt")).expect("Unable to create file");
    let new_key = Keypair::random();
    let pubkeybytes = PublicKeyBytes::from(new_key.pk);
    let contents = format!("{}:nice-graffiti", pubkeybytes.to_string());
    file.write_all(contents.as_bytes())
        .expect("Unable to write to file");
    CommandLineTest::new()
        .flag(
            "graffiti-file",
            dir.path().join("graffiti.txt").as_os_str().to_str(),
        )
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .graffiti_file
                    .clone()
                    .unwrap()
                    .load_graffiti(&pubkeybytes)
                    .unwrap()
                    .unwrap()
                    .to_string(),
                "0x6e6963652d677261666669746900000000000000000000000000000000000000"
            )
        });
}

// Tests for HTTP flags.
#[test]
fn http_flag() {
    CommandLineTest::new()
        .flag("http", None)
        .run()
        .with_config(|config| assert!(config.http_api.enabled));
}
#[test]
fn http_port_flag() {
    CommandLineTest::new()
        .flag("http-port", Some("9090"))
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_port, 9090));
}
#[test]
fn http_allow_origin_flag() {
    CommandLineTest::new()
        .flag("http-allow-origin", Some("http://localhost:9009"))
        .run()
        .with_config(|config| {
            assert_eq!(
                config.http_api.allow_origin,
                Some("http://localhost:9009".to_string())
            );
        });
}
#[test]
fn http_allow_origin_all_flag() {
    CommandLineTest::new()
        .flag("http-allow-origin", Some("*"))
        .run()
        .with_config(|config| assert_eq!(config.http_api.allow_origin, Some("*".to_string())));
}

// Tests for Metrics flags.
#[test]
fn metrics_flag() {
    CommandLineTest::new()
        .flag("metrics", None)
        .run()
        .with_config(|config| assert!(config.http_metrics.enabled));
}
#[test]
fn metrics_address_flag() {
    let addr = "127.0.0.99".parse::<Ipv4Addr>().unwrap();
    CommandLineTest::new()
        .flag("metrics-address", Some("127.0.0.99"))
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.listen_addr, addr));
}
#[test]
fn metrics_port_flag() {
    CommandLineTest::new()
        .flag("metrics-port", Some("9090"))
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.listen_port, 9090));
}
#[test]
fn metrics_allow_origin_flag() {
    CommandLineTest::new()
        .flag("metrics-allow-origin", Some("http://localhost:9009"))
        .run()
        .with_config(|config| {
            assert_eq!(
                config.http_metrics.allow_origin,
                Some("http://localhost:9009".to_string())
            );
        });
}
#[test]
fn metrics_allow_origin_all_flag() {
    CommandLineTest::new()
        .flag("metrics-allow-origin", Some("*"))
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.allow_origin, Some("*".to_string())));
}
#[test]
pub fn malloc_tuning_flag() {
    CommandLineTest::new()
        .flag("disable-malloc-tuning", None)
        // Simply ensure that the node can start with this flag, it's very difficult to observe the
        // effects of it.
        .run();
}
