use validator_client::Config;

use crate::exec::CommandLineTestExec;
use bls::{Keypair, PublicKeyBytes};
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::string::ToString;
use tempfile::TempDir;
use types::Address;

/// Returns the `lighthouse validator_client` command.
fn base_cmd() -> Command {
    let lighthouse_bin = env!("CARGO_BIN_EXE_lighthouse");
    let path = lighthouse_bin
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR");

    let mut cmd = Command::new(path);
    cmd.arg("validator_client");
    cmd
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
}

impl CommandLineTestExec for CommandLineTest {
    type Config = Config;

    fn cmd_mut(&mut self) -> &mut Command {
        &mut self.cmd
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
fn validators_dir_alias_flags() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("validator-dir", dir.path().join("validators").to_str())
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

#[test]
fn use_long_timeouts_flag() {
    CommandLineTest::new()
        .flag("use-long-timeouts", None)
        .run()
        .with_config(|config| assert!(config.use_long_timeouts));
}

#[test]
fn beacon_nodes_tls_certs_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag(
            "beacon-nodes-tls-certs",
            Some(
                vec![
                    dir.path().join("certificate.crt").to_str().unwrap(),
                    dir.path().join("certificate2.crt").to_str().unwrap(),
                ]
                .join(",")
                .as_str(),
            ),
        )
        .run()
        .with_config(|config| {
            assert_eq!(
                config.beacon_nodes_tls_certs,
                Some(vec![
                    dir.path().join("certificate.crt"),
                    dir.path().join("certificate2.crt")
                ])
            )
        });
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

// Tests for suggested-fee-recipient flags.
#[test]
fn fee_recipient_flag() {
    CommandLineTest::new()
        .flag(
            "suggested-fee-recipient",
            Some("0x00000000219ab540356cbb839cbe05303d7705fa"),
        )
        .run()
        .with_config(|config| {
            assert_eq!(
                config.fee_recipient,
                Some(Address::from_str("0x00000000219ab540356cbb839cbe05303d7705fa").unwrap())
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
fn http_address_flag() {
    let addr = "127.0.0.99".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("http-address", Some("127.0.0.99"))
        .flag("unencrypted-http-transport", None)
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
}
#[test]
fn http_address_ipv6_flag() {
    let addr = "::1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("http-address", Some("::1"))
        .flag("unencrypted-http-transport", None)
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
}
#[test]
#[should_panic]
fn missing_unencrypted_http_transport_flag() {
    let addr = "127.0.0.99".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("http-address", Some("127.0.0.99"))
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
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
    let addr = "127.0.0.99".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("metrics-address", Some("127.0.0.99"))
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.listen_addr, addr));
}
#[test]
fn metrics_address_ipv6_flag() {
    let addr = "::1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("metrics-address", Some("::1"))
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
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.allocator_metrics_enabled, false));
}
#[test]
pub fn malloc_tuning_default() {
    CommandLineTest::new()
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.allocator_metrics_enabled, true));
}
#[test]
fn doppelganger_protection_flag() {
    CommandLineTest::new()
        .flag("enable-doppelganger-protection", None)
        .run()
        .with_config(|config| assert!(config.enable_doppelganger_protection));
}
#[test]
fn no_doppelganger_protection_flag() {
    CommandLineTest::new()
        .run()
        .with_config(|config| assert!(!config.enable_doppelganger_protection));
}
#[test]
fn strict_fee_recipient_flag() {
    CommandLineTest::new()
        .flag("strict-fee-recipient", None)
        .run()
        .with_config(|config| assert!(config.strict_fee_recipient));
}
#[test]
fn no_strict_fee_recipient_flag() {
    CommandLineTest::new()
        .run()
        .with_config(|config| assert!(!config.strict_fee_recipient));
}
