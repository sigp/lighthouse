use beacon_node::ClientConfig as Config;

use eth2_libp2p::PeerId;
use serde_json::from_reader;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str::{from_utf8, FromStr};
use std::string::ToString;
use tempfile::TempDir;
use types::{Checkpoint, Epoch, Hash256};

const BEACON_CMD: &str = "beacon_node";
const CONFIG_NAME: &str = "bn_dump.json";
const DUMP_CONFIG_CMD: &str = "dump-config";
const IMMEDIATE_SHUTDOWN_CMD: &str = "immediate-shutdown";

/// Returns the `lighthouse beacon_node --immediate-shutdown` command
fn base_cmd() -> Command {
    let target_dir = env!("CARGO_BIN_EXE_lighthouse");
    let path = target_dir
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR");

    let mut cmd = Command::new(path);
    cmd.arg(BEACON_CMD)
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

// Framework for Command Line Testing
struct CommandLineTest {
    cmd: Command,
}
impl CommandLineTest {
    fn new() -> CommandLineTest {
        let base_cmd = base_cmd();
        CommandLineTest { cmd: base_cmd }
    }

    fn flag(mut self, flag: &str, value: Option<&str>) -> Self {
        // Build the command by adding the flag and any values
        self.cmd.arg(format!("--{}", flag));
        if let Some(value) = value {
            self.cmd.arg(value);
        }
        self
    }

    fn run(&mut self) -> CompletedTest {
        // Setup temp directories
        let tmp_dir = TempDir::new().expect("Unable to create temporary directory");
        let tmp_path: PathBuf = tmp_dir.path().join(CONFIG_NAME);

        // Add --datadir <temp_dir> --dump-config <temp_path> to cmd
        self.cmd
            .arg("--datadir")
            .arg(tmp_dir.path().as_os_str())
            .arg(format!("--{}", DUMP_CONFIG_CMD))
            .arg(tmp_path.as_os_str());

        // Run the command
        let _output = output_result(&mut self.cmd).expect("Unable to run command");

        // Grab the config
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
        .with_config_and_dir(|config, dir| assert_eq!(config.data_dir, dir.path().join("beacon")));
}

#[test]
fn staking_flag() {
    CommandLineTest::new()
        .flag("staking", None)
        .run()
        .with_config(|config| {
            assert!(config.http_api.enabled);
            assert!(config.sync_eth1_chain);
        });
}

#[test]
fn wss_checkpoint_flag() {
    let state = Some(Checkpoint {
        epoch: Epoch::new(1010),
        root: Hash256::from_str("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            .unwrap(),
    });
    CommandLineTest::new()
        .flag(
            "wss-checkpoint",
            Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:1010"),
        )
        .run()
        .with_config(|config| assert_eq!(config.chain.weak_subjectivity_checkpoint, state));
}
#[test]
fn max_skip_slots_flag() {
    CommandLineTest::new()
        .flag("max-skip-slots", Some("10"))
        .run()
        .with_config(|config| assert_eq!(config.chain.import_max_skip_slots, Some(10)));
}

#[test]
fn freezer_dir_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("freezer-dir", dir.path().as_os_str().to_str())
        .run()
        .with_config(|config| assert_eq!(config.freezer_db_path, Some(dir.path().to_path_buf())));
}

#[test]
fn graffiti_flag() {
    CommandLineTest::new()
        .flag("graffiti", Some("nice-graffiti"))
        .run()
        .with_config(|config| {
            assert_eq!(
                config.graffiti.to_string(),
                "0x6e6963652d677261666669746900000000000000000000000000000000000000"
            );
        });
}

#[test]
fn trusted_peers_flag() {
    let peers = vec![PeerId::random(), PeerId::random()];
    CommandLineTest::new()
        .flag(
            "trusted-peers",
            Some(format!("{},{}", peers[0].to_string(), peers[1].to_string()).as_str()),
        )
        .run()
        .with_config(|config| {
            assert_eq!(
                PeerId::from(config.network.trusted_peers[0].clone()).to_bytes(),
                peers[0].to_bytes()
            );
            assert_eq!(
                PeerId::from(config.network.trusted_peers[1].clone()).to_bytes(),
                peers[1].to_bytes()
            );
        });
}

// Tests for Eth1 flags
#[test]
fn dummy_eth1_flag() {
    CommandLineTest::new()
        .flag("dummy-eth1", None)
        .run()
        .with_config(|config| assert!(config.dummy_eth1_backend));
}
#[test]
fn eth1_flag() {
    CommandLineTest::new()
        .flag("eth1", None)
        .run()
        .with_config(|config| assert!(config.sync_eth1_chain));
}
#[test]
fn eth1_endpoints_flag() {
    CommandLineTest::new()
        .flag(
            "eth1-endpoints",
            Some("https://infura.io/v3/abc,http://localhost:8545"),
        )
        .run()
        .with_config(|config| {
            assert_eq!(
                config.eth1.endpoints,
                vec![
                    "https://infura.io/v3/abc".to_string(),
                    "http://localhost:8545".to_string()
                ]
            )
        });
}
#[test]
fn eth1_blocks_per_log_query_flag() {
    CommandLineTest::new()
        .flag("eth1-blocks-per-log-query", Some("500"))
        .run()
        .with_config(|config| assert_eq!(config.eth1.blocks_per_log_query, 500));
}
#[test]
fn eth1_purge_cache_flag() {
    CommandLineTest::new()
        .flag("eth1-purge-cache", None)
        .run()
        .with_config(|config| assert!(config.eth1.purge_cache));
}

// Tests for Network flags
#[test]
fn network_dir_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("network-dir", dir.path().as_os_str().to_str())
        .run()
        .with_config(|config| assert_eq!(config.network.network_dir, dir.path()));
}
#[test]
fn network_target_peers_flag() {
    CommandLineTest::new()
        .flag("target-peers", Some("55"))
        .run()
        .with_config(|config| {
            assert_eq!(config.network.target_peers, "55".parse::<usize>().unwrap());
        });
}
#[test]
fn network_subscribe_all_subnets_flag() {
    CommandLineTest::new()
        .flag("subscribe-all-subnets", None)
        .run()
        .with_config(|config| assert!(config.network.subscribe_all_subnets));
}
#[test]
fn network_import_all_attestations_flag() {
    CommandLineTest::new()
        .flag("import-all-attestations", None)
        .run()
        .with_config(|config| assert!(config.network.import_all_attestations));
}
#[test]
fn network_listen_address_flag() {
    let addr = "192.167.1.1".parse::<Ipv4Addr>().unwrap();
    CommandLineTest::new()
        .flag("listen-address", Some("192.167.1.1"))
        .run()
        .with_config(|config| assert_eq!(config.network.listen_address, addr));
}
#[test]
fn network_port_flag() {
    CommandLineTest::new()
        .flag("port", Some("9009"))
        .run()
        .with_config(|config| {
            assert_eq!(config.network.libp2p_port, 9009);
            assert_eq!(config.network.discovery_port, 9009);
        });
}
#[test]
fn network_discovery_port_flag() {
    CommandLineTest::new()
        .flag("discovery-port", Some("9011"))
        .run()
        .with_config(|config| assert_eq!(config.network.discovery_port, 9011));
}
#[test]
fn network_port_and_discovery_port_flags() {
    CommandLineTest::new()
        .flag("port", Some("9009"))
        .flag("discovery-port", Some("9011"))
        .run()
        .with_config(|config| {
            assert_eq!(config.network.libp2p_port, 9009);
            assert_eq!(config.network.discovery_port, 9011);
        });
}
#[test]
fn disable_discovery_flag() {
    CommandLineTest::new()
        .flag("disable-discovery", None)
        .run()
        .with_config(|config| assert!(config.network.disable_discovery));
}
#[test]
fn disable_upnp_flag() {
    CommandLineTest::new()
        .flag("disable-upnp", None)
        .run()
        .with_config(|config| assert!(!config.network.upnp_enabled));
}
#[test]
fn boot_nodes_flag() {
    let nodes = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8,\
                enr:-LK4QFOFWca5ABQzxiCRcy37G7wy1K6zD4qMYBSN5ozzanwze_XVvXVhCk9JvF0cHXOBZrHK1E4vU7Gn-a0bHVczoDU6h2F0dG5ldHOIAAAAAAAAAACEZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhNIy-4iJc2VjcDI1NmsxoQJA3AXQJ6M3NpBWtJS3HPtbXG14t7qHjXuIaL6IOz89T4N0Y3CCIyiDdWRwgiMo";
    let enr: Vec<&str> = nodes.split(',').collect();
    CommandLineTest::new()
        .flag("boot-nodes", Some(nodes))
        .run()
        .with_config(|config| {
            assert_eq!(config.network.boot_nodes_enr[0].to_base64(), enr[0]);
            assert_eq!(config.network.boot_nodes_enr[1].to_base64(), enr[1]);
        });
}
// // TODO - Add test for MultiAddr
#[test]
fn private_flag() {
    CommandLineTest::new()
        .flag("private", None)
        .run()
        .with_config(|config| assert!(config.network.private));
}
#[test]
fn zero_ports_flag() {
    CommandLineTest::new()
        .flag("zero-ports", None)
        .run()
        .with_config(|config| {
            assert_eq!(config.network.enr_address, None);
            assert_eq!(config.http_api.listen_port, 0);
            assert_eq!(config.http_metrics.listen_port, 0);
            // Around 1/65535 chance it fails
            assert_ne!(config.network.libp2p_port, 9000);
            // Around 1/65535 chance it fails
            assert_ne!(config.network.discovery_port, 9000);
        });
}

// Tests for ENR flags
#[test]
fn enr_udp_port_flags() {
    CommandLineTest::new()
        .flag("enr-udp-port", Some("9009"))
        .run()
        .with_config(|config| assert_eq!(config.network.enr_udp_port, Some(9009)));
}
#[test]
fn enr_tcp_port_flags() {
    CommandLineTest::new()
        .flag("enr-tcp-port", Some("9009"))
        .run()
        .with_config(|config| assert_eq!(config.network.enr_tcp_port, Some(9009)));
}
#[test]
fn enr_match_flag() {
    let addr = "192.167.1.1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("enr-match", None)
        .flag("listen-address", Some("192.167.1.1"))
        .flag("discovery-port", Some("9009"))
        .run()
        .with_config(|config| {
            assert_eq!(config.network.listen_address, addr);
            assert_eq!(config.network.enr_address, Some(addr));
            assert_eq!(config.network.discovery_port, 9009);
            assert_eq!(config.network.enr_udp_port, Some(9009));
        });
}
#[test]
fn enr_address_flag() {
    let addr = "192.167.1.1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("enr-address", Some("192.167.1.1"))
        .flag("enr-udp-port", Some("9009"))
        .run()
        .with_config(|config| {
            assert_eq!(config.network.enr_address, Some(addr));
            assert_eq!(config.network.enr_udp_port, Some(9009));
        });
}
#[test]
fn enr_address_dns_flag() {
    let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
    let ipv6addr = "::1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("enr-address", Some("localhost"))
        .flag("enr-udp-port", Some("9009"))
        .run()
        .with_config(|config| {
            assert!(
                config.network.enr_address == Some(addr)
                    || config.network.enr_address == Some(ipv6addr)
            );
            assert_eq!(config.network.enr_udp_port, Some(9009));
        });
}
#[test]
fn disable_enr_auto_update_flag() {
    CommandLineTest::new()
        .flag("disable-enr-auto-update", None)
        .run()
        .with_config(|config| assert!(config.network.discv5_config.enr_update));
}

// Tests for HTTP flags
#[test]
fn http_flag() {
    CommandLineTest::new()
        .flag("http", None)
        .run()
        .with_config(|config| assert!(config.http_api.enabled));
}
#[test]
fn http_address_flag() {
    let addr = "127.0.0.99".parse::<Ipv4Addr>().unwrap();
    CommandLineTest::new()
        .flag("http-address", Some("127.0.0.99"))
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
}
#[test]
fn http_port_flag() {
    CommandLineTest::new()
        .flag("http-port", Some("5059"))
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_port, 5059));
}
#[test]
fn http_allow_origin_flag() {
    CommandLineTest::new()
        .flag("http-allow-origin", Some("127.0.0.99"))
        .run()
        .with_config(|config| {
            assert_eq!(config.http_api.allow_origin, Some("127.0.0.99".to_string()));
        });
}
#[test]
fn http_allow_origin_all_flag() {
    CommandLineTest::new()
        .flag("http-allow-origin", Some("*"))
        .run()
        .with_config(|config| assert_eq!(config.http_api.allow_origin, Some("*".to_string())));
}

// Tests for Metrics flags
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
        .flag("metrics-port", Some("13123"))
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.listen_port, 13123));
}
#[test]
fn metrics_allow_origin_flag() {
    CommandLineTest::new()
        .flag("metrics-allow-origin", Some("localhost:5059"))
        .run()
        .with_config(|config| {
            assert_eq!(
                config.http_metrics.allow_origin,
                Some("localhost:5059".to_string())
            )
        });
}
#[test]
fn metrics_allow_origin_all_flag() {
    CommandLineTest::new()
        .flag("metrics-allow-origin", Some("*"))
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.allow_origin, Some("*".to_string())));
}

// Tests for Validator Monitor flags
#[test]
fn validator_monitor_auto_flag() {
    CommandLineTest::new()
        .flag("validator-monitor-auto", None)
        .run()
        .with_config(|config| assert!(config.validator_monitor_auto));
}
#[test]
fn validator_monitor_pubkeys_flag() {
    CommandLineTest::new()
        .flag("validator-monitor-pubkeys", Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,\
                                                0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
        .run()
        .with_config(|config| {
            assert_eq!(config.validator_monitor_pubkeys[0].to_string(), "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
            assert_eq!(config.validator_monitor_pubkeys[1].to_string(), "0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        });
}
#[test]
fn validator_monitor_file_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let mut file = File::create(dir.path().join("pubkeys.txt")).expect("Unable to create file");
    file.write_all(b"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,\
                0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .expect("Unable to write to file");
    CommandLineTest::new()
        .flag("validator-monitor-file", dir.path().join("pubkeys.txt").as_os_str().to_str())
        .run()
        .with_config(|config| {
            assert_eq!(config.validator_monitor_pubkeys[0].to_string(), "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
            assert_eq!(config.validator_monitor_pubkeys[1].to_string(), "0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        });
}

// Tests for Store flags
#[test]
fn slots_per_restore_point_flag() {
    CommandLineTest::new()
        .flag("slots-per-restore-point", Some("64"))
        .run()
        .with_config(|config| assert_eq!(config.store.slots_per_restore_point, 64));
}
#[test]
fn block_cache_size_flag() {
    CommandLineTest::new()
        .flag("block-cache-size", Some("4"))
        .run()
        .with_config(|config| assert_eq!(config.store.block_cache_size, 4_usize));
}
#[test]
fn auto_compact_db_flag() {
    CommandLineTest::new()
        .flag("auto-compact-db", Some("false"))
        .run()
        .with_config(|config| assert!(!config.store.compact_on_prune));
}
#[test]
fn compact_db_flag() {
    CommandLineTest::new()
        .flag("auto-compact-db", Some("false"))
        .flag("compact-db", None)
        .run()
        .with_config(|config| assert!(config.store.compact_on_init));
}

// Tests for Slasher flags
#[test]
fn slasher_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .run()
        .with_config_and_dir(|config, dir| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(
                    slasher_config.database_path,
                    dir.path().join("beacon").join("slasher_db")
                )
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_dir_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-dir", dir.path().as_os_str().to_str())
        .run()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.database_path, dir.path());
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_update_period_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-update-period", Some("100"))
        .run()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.update_period, 100);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_history_length_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-history-length", Some("10"))
        .run()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.history_length, 10);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_max_db_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("10"))
        .run()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.max_db_size_mbs, 10240);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_chunk_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-chunk-size", Some("10"))
        .run()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.chunk_size, 10);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_validator_chunk_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-validator-chunk-size", Some("10"))
        .run()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.validator_chunk_size, 10);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_broadcast_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-broadcast", None)
        .run()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert!(slasher_config.broadcast);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
