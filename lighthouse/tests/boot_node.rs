use boot_node::config::BootNodeConfigSerialization;

use crate::exec::{CommandLineTestExec, CompletedTest};
use clap::ArgMatches;
use clap_utils::get_eth2_network_config;
use lighthouse_network::discovery::ENR_FILENAME;
use lighthouse_network::Enr;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use tempfile::TempDir;
use unused_port::unused_udp_port;

const IP_ADDRESS: &str = "192.168.2.108";

/// Returns the `lighthouse boot_node` command.
fn base_cmd() -> Command {
    let lighthouse_bin = env!("CARGO_BIN_EXE_lighthouse");
    let path = lighthouse_bin
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR");

    let mut cmd = Command::new(path);
    cmd.arg("boot_node");
    cmd
}

struct CommandLineTest {
    cmd: Command,
}

impl CommandLineTest {
    fn new() -> CommandLineTest {
        let base_cmd = base_cmd();
        CommandLineTest { cmd: base_cmd }
    }

    fn run_with_ip(&mut self) -> CompletedTest<BootNodeConfigSerialization> {
        self.cmd.arg(IP_ADDRESS);
        self.run()
    }
}

impl CommandLineTestExec for CommandLineTest {
    type Config = BootNodeConfigSerialization;

    fn cmd_mut(&mut self) -> &mut Command {
        &mut self.cmd
    }
}

#[test]
fn enr_address_arg() {
    let mut test = CommandLineTest::new();
    test.run_with_ip().with_config(|config| {
        assert_eq!(config.local_enr.ip4(), Some(IP_ADDRESS.parse().unwrap()));
    });
}

#[test]
fn port_flag() {
    let port = unused_udp_port().unwrap();
    CommandLineTest::new()
        .flag("port", Some(port.to_string().as_str()))
        .run_with_ip()
        .with_config(|config| {
            assert_eq!(config.listen_socket.port(), port);
        })
}

#[test]
fn listen_address_flag() {
    let addr = "127.0.0.2".parse::<Ipv4Addr>().unwrap();
    CommandLineTest::new()
        .flag("listen-address", Some("127.0.0.2"))
        .run_with_ip()
        .with_config(|config| {
            assert_eq!(config.listen_socket.ip(), addr);
        });
}

#[test]
fn boot_nodes_flag() {
    // Get hardcoded boot-nodes to verify they end up in the config.
    // Pass empty `ArgMatches` to `get_eth2_network_config` as we want to
    // receive the default `Eth2NetworkConfig`.
    let empty_args = ArgMatches::default();
    let default_enr = get_eth2_network_config(&empty_args)
        .unwrap()
        .boot_enr
        .unwrap();
    let default_enr: Vec<String> = default_enr.iter().map(|enr| enr.to_base64()).collect();

    // Nodes passed via `--boot-nodes` are added to the local routing table.
    let extra_nodes = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8,enr:-LK4QFOFWca5ABQzxiCRcy37G7wy1K6zD4qMYBSN5ozzanwze_XVvXVhCk9JvF0cHXOBZrHK1E4vU7Gn-a0bHVczoDU6h2F0dG5ldHOIAAAAAAAAAACEZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhNIy-4iJc2VjcDI1NmsxoQJA3AXQJ6M3NpBWtJS3HPtbXG14t7qHjXuIaL6IOz89T4N0Y3CCIyiDdWRwgiMo";
    let extra_enr: Vec<&str> = extra_nodes.split(",").collect();

    // Construct vector of enr expected in config.
    let default_enr_str: Vec<&str> = default_enr.iter().map(|s| s.as_str()).collect();
    let mut expect_enr = Vec::new();
    expect_enr.extend_from_slice(&default_enr_str);
    expect_enr.extend_from_slice(&extra_enr);

    CommandLineTest::new()
        .flag("boot-nodes", Some(extra_nodes))
        .run_with_ip()
        .with_config(|config| {
            assert_eq!(config.boot_nodes.len(), expect_enr.len());
            for (i, enr) in config.boot_nodes.iter().enumerate() {
                assert_eq!(
                    enr.to_base64(),
                    expect_enr[i],
                    "ENR missmatch at index [{}]",
                    i
                );
            }
        })
}

#[test]
fn enr_port_flag() {
    let port = unused_udp_port().unwrap();
    CommandLineTest::new()
        .flag("enr-port", Some(port.to_string().as_str()))
        .run_with_ip()
        .with_config(|config| {
            assert_eq!(config.local_enr.udp4(), Some(port));
        })
}

#[test]
fn disable_packet_filter_flag() {
    CommandLineTest::new()
        .flag("disable-packet-filter", None)
        .run_with_ip()
        .with_config(|config| {
            assert_eq!(config.disable_packet_filter, true);
        });
}

#[test]
fn enable_enr_auto_update_flag() {
    CommandLineTest::new()
        .flag("enable-enr-auto-update", None)
        .run_with_ip()
        .with_config(|config| {
            assert_eq!(config.enable_enr_auto_update, true);
        });
}

#[test]
fn network_dir_flag() {
    // Save enr to temp dir.
    let enr = Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap();
    let tmp_dir = TempDir::new().unwrap();
    save_enr_to_disk(tmp_dir.path(), &enr).unwrap();

    CommandLineTest::new()
        .flag("network-dir", Some(tmp_dir.path().to_str().unwrap()))
        .run()
        .with_config(|config| assert_eq!(config.local_enr, enr))
}

fn save_enr_to_disk(dir: &Path, enr: &Enr) -> Result<(), String> {
    let mut file = File::create(dir.join(Path::new(ENR_FILENAME)))
        .map_err(|e| format!("Could not create ENR file: {:?}", e))?;
    file.write_all(enr.to_base64().as_bytes())
        .map_err(|e| format!("Could not write ENR to file: {:?}", e))
}
