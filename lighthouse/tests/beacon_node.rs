use crate::exec::{CommandLineTestExec, CompletedTest};
use beacon_node::beacon_chain::chain_config::{
    DEFAULT_RE_ORG_CUTOFF_DENOMINATOR, DEFAULT_RE_ORG_HEAD_THRESHOLD,
    DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION, DEFAULT_SYNC_TOLERANCE_EPOCHS,
    DisallowedReOrgOffsets,
};
use beacon_node::beacon_chain::custody_context::NodeCustodyType;
use beacon_node::{
    ClientConfig as Config, beacon_chain::graffiti_calculator::GraffitiOrigin,
    beacon_chain::store::config::DatabaseBackend as BeaconNodeBackend,
};
use beacon_processor::BeaconProcessorConfig;
use lighthouse_network::PeerId;
use network_utils::unused_port::{
    unused_tcp4_port, unused_tcp6_port, unused_udp4_port, unused_udp6_port,
};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::string::ToString;
use std::time::Duration;
use tempfile::TempDir;
use types::non_zero_usize::new_non_zero_usize;
use types::{Address, Checkpoint, Epoch, Hash256, MainnetEthSpec};

const DEFAULT_EXECUTION_ENDPOINT: &str = "http://localhost:8551/";
const DEFAULT_EXECUTION_JWT_SECRET_KEY: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// These dummy ports should ONLY be used for `enr-xxx-port` flags that do not bind.
const DUMMY_ENR_TCP_PORT: u16 = 7777;
const DUMMY_ENR_UDP_PORT: u16 = 8888;
const DUMMY_ENR_QUIC_PORT: u16 = 9999;

const _: () =
    assert!(DUMMY_ENR_QUIC_PORT != 0 && DUMMY_ENR_TCP_PORT != 0 && DUMMY_ENR_UDP_PORT != 0);

/// Returns the `lighthouse beacon_node` command.
fn base_cmd() -> Command {
    let lighthouse_bin = env!("CARGO_BIN_EXE_lighthouse");
    let path = lighthouse_bin
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR");

    let mut cmd = Command::new(path);
    cmd.arg("beacon_node");
    cmd
}

// Wrapper around `Command` for easier Command Line Testing.
struct CommandLineTest {
    cmd: Command,
}
impl CommandLineTest {
    fn new() -> CommandLineTest {
        let mut base_cmd = base_cmd();

        base_cmd
            .arg("--execution-endpoint")
            .arg(DEFAULT_EXECUTION_ENDPOINT)
            .arg("--execution-jwt-secret-key")
            .arg(DEFAULT_EXECUTION_JWT_SECRET_KEY);
        CommandLineTest { cmd: base_cmd }
    }

    // Required for testing different JWT authentication methods.
    fn new_with_no_execution_endpoint() -> CommandLineTest {
        let base_cmd = base_cmd();
        CommandLineTest { cmd: base_cmd }
    }

    fn run_with_zero_port(&mut self) -> CompletedTest<Config> {
        // Required since Deneb was enabled on mainnet.
        self.set_allow_insecure_genesis_sync()
            .run_with_zero_port_and_no_genesis_sync()
    }

    fn run_with_zero_port_and_no_genesis_sync(&mut self) -> CompletedTest<Config> {
        self.set_zero_port().run()
    }

    fn set_allow_insecure_genesis_sync(&mut self) -> &mut Self {
        self.cmd.arg("--allow-insecure-genesis-sync");
        self
    }

    fn set_zero_port(&mut self) -> &mut Self {
        self.cmd.arg("-z");
        self
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
        .run_with_zero_port()
        .with_config_and_dir(|config, dir| {
            assert_eq!(*config.data_dir(), dir.path().join("beacon"))
        });
}

#[test]
fn staking_flag() {
    CommandLineTest::new()
        .flag("staking", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.http_api.enabled);
        });
}

#[test]
fn allow_insecure_genesis_sync_default() {
    CommandLineTest::new()
        .run_with_zero_port_and_no_genesis_sync()
        .with_config(|config| {
            assert!(!config.allow_insecure_genesis_sync);
        });
}

#[test]
#[should_panic]
fn insecure_genesis_sync_should_panic() {
    CommandLineTest::new()
        .set_zero_port()
        .run_with_immediate_shutdown(false);
}

#[test]
fn allow_insecure_genesis_sync_enabled() {
    CommandLineTest::new()
        .flag("allow-insecure-genesis-sync", None)
        .run_with_zero_port_and_no_genesis_sync()
        .with_config(|config| {
            assert!(config.allow_insecure_genesis_sync);
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
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.weak_subjectivity_checkpoint, state));
}
#[test]
fn max_skip_slots_flag() {
    CommandLineTest::new()
        .flag("max-skip-slots", Some("10"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.import_max_skip_slots, Some(10)));
}

#[test]
fn shuffling_cache_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.shuffling_cache_size,
                beacon_node::beacon_chain::shuffling_cache::DEFAULT_CACHE_SIZE
            )
        });
}

#[test]
fn shuffling_cache_set() {
    CommandLineTest::new()
        .flag("shuffling-cache-size", Some("500"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.shuffling_cache_size, 500));
}

#[test]
fn fork_choice_before_proposal_timeout_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.fork_choice_before_proposal_timeout_ms,
                beacon_node::beacon_chain::chain_config::DEFAULT_FORK_CHOICE_BEFORE_PROPOSAL_TIMEOUT
            )
        });
}

#[test]
fn fork_choice_before_proposal_timeout_zero() {
    CommandLineTest::new()
        .flag("fork-choice-before-proposal-timeout", Some("0"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.fork_choice_before_proposal_timeout_ms, 0));
}

#[test]
fn checkpoint_sync_url_timeout_flag() {
    CommandLineTest::new()
        .flag("checkpoint-sync-url-timeout", Some("300"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.checkpoint_sync_url_timeout, 300);
        });
}

#[test]
fn checkpoint_sync_url_timeout_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.checkpoint_sync_url_timeout, 180);
        });
}

#[test]
fn prepare_payload_lookahead_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.prepare_payload_lookahead,
                Duration::from_secs(4),
            )
        });
}

#[test]
fn prepare_payload_lookahead_shorter() {
    CommandLineTest::new()
        .flag("prepare-payload-lookahead", Some("1500"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.prepare_payload_lookahead,
                Duration::from_millis(1500)
            )
        });
}

#[test]
fn always_prepare_payload_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(!config.chain.always_prepare_payload));
}

#[test]
fn always_prepare_payload_override() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new_with_no_execution_endpoint()
        .flag("always-prepare-payload", None)
        .flag(
            "suggested-fee-recipient",
            Some("0x00000000219ab540356cbb839cbe05303d7705fa"),
        )
        .flag("execution-endpoint", Some("http://localhost:8551/"))
        .flag(
            "execution-jwt",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.always_prepare_payload));
}

#[test]
fn paranoid_block_proposal_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(!config.chain.paranoid_block_proposal));
}

#[test]
fn paranoid_block_proposal_on() {
    CommandLineTest::new()
        .flag("paranoid-block-proposal", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.paranoid_block_proposal));
}

#[test]
fn reset_payload_statuses_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(!config.chain.always_reset_payload_statuses));
}

#[test]
fn reset_payload_statuses_present() {
    CommandLineTest::new()
        .flag("reset-payload-statuses", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.always_reset_payload_statuses));
}

#[test]
fn freezer_dir_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("freezer-dir", dir.path().as_os_str().to_str())
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.freezer_db_path, Some(dir.path().to_path_buf())));
}

#[test]
fn graffiti_flag() {
    CommandLineTest::new()
        .flag("graffiti", Some("nice-graffiti"))
        .run_with_zero_port()
        .with_config(|config| {
            assert!(matches!(
                config.beacon_graffiti,
                GraffitiOrigin::UserSpecified(_)
            ));
            assert_eq!(
                config.beacon_graffiti.graffiti().to_string(),
                "0x6e6963652d677261666669746900000000000000000000000000000000000000",
            );
        });
}

#[test]
fn default_graffiti() {
    use types::GRAFFITI_BYTES_LEN;
    // test default graffiti when no graffiti flags are provided
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(matches!(
                config.beacon_graffiti,
                GraffitiOrigin::Calculated(_)
            ));
            let version_bytes = lighthouse_version::VERSION.as_bytes();
            let trimmed_len = std::cmp::min(version_bytes.len(), GRAFFITI_BYTES_LEN);
            let mut bytes = [0u8; GRAFFITI_BYTES_LEN];
            bytes[..trimmed_len].copy_from_slice(&version_bytes[..trimmed_len]);
            assert_eq!(config.beacon_graffiti.graffiti().0, bytes);
        });
}

#[test]
fn trusted_peers_flag() {
    let peers = [PeerId::random(), PeerId::random()];
    CommandLineTest::new()
        .flag(
            "trusted-peers",
            Some(format!("{},{}", peers[0], peers[1]).as_str()),
        )
        .run_with_zero_port()
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

#[test]
fn genesis_backfill_flag() {
    CommandLineTest::new()
        .flag("genesis-backfill", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.genesis_backfill));
}

/// The genesis backfill flag should be enabled if historic states flag is set.
#[test]
fn genesis_backfill_with_historic_flag() {
    CommandLineTest::new()
        .flag("reconstruct-historic-states", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.genesis_backfill));
}

#[test]
fn complete_blob_backfill_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(!config.chain.complete_blob_backfill));
}

#[test]
fn complete_blob_backfill_flag() {
    CommandLineTest::new()
        .flag("complete-blob-backfill", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.chain.complete_blob_backfill);
            assert!(!config.store.prune_blobs);
        });
}

// Even if `--prune-blobs true` is provided, `--complete-blob-backfill` should override it to false.
#[test]
fn complete_blob_backfill_and_prune_blobs_true() {
    CommandLineTest::new()
        .flag("complete-blob-backfill", None)
        .flag("prune-blobs", Some("true"))
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.chain.complete_blob_backfill);
            assert!(!config.store.prune_blobs);
        });
}

// Tests for Bellatrix flags.
fn run_bellatrix_execution_endpoints_flag_test(flag: &str) {
    use sensitive_url::SensitiveUrl;
    let urls = ["http://sigp.io/no-way:1337", "http://infura.not_real:4242"];
    // we don't support redundancy for execution-endpoints
    // only the first provided endpoint is parsed.

    let mut endpoint_arg = urls[0].to_string();
    for url in urls.iter().skip(1) {
        endpoint_arg.push(',');
        endpoint_arg.push_str(url);
    }

    let (_dirs, jwts): (Vec<_>, Vec<_>) = (0..2)
        .map(|i| {
            let dir = TempDir::new().expect("Unable to create temporary directory");
            let path = dir.path().join(format!("jwt-{}", i));
            (dir, path)
        })
        .unzip();

    let mut jwts_arg = jwts[0].as_os_str().to_str().unwrap().to_string();
    for jwt in jwts.iter().skip(1) {
        jwts_arg.push(',');
        jwts_arg.push_str(jwt.as_os_str().to_str().unwrap());
    }

    // this is way better but intersperse is still a nightly feature :/
    // let endpoint_arg: String = urls.into_iter().intersperse(",").collect();
    CommandLineTest::new_with_no_execution_endpoint()
        .flag(flag, Some(&endpoint_arg))
        .flag("execution-jwt", Some(&jwts_arg))
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert!(config.execution_endpoint.is_some());
            assert_eq!(
                config.execution_endpoint.as_ref().unwrap().clone(),
                SensitiveUrl::parse(urls[0]).unwrap()
            );
            // Only the first secret file should be used.
            assert_eq!(
                config.secret_file.as_ref().unwrap().clone(),
                jwts[0].clone()
            );
        });
}
#[test]
fn run_execution_jwt_secret_key_is_persisted() {
    let jwt_secret_key = "0x3cbc11b0d8fa16f3344eacfd6ff6430b9d30734450e8adcf5400f88d327dcb33";
    CommandLineTest::new_with_no_execution_endpoint()
        .flag("execution-endpoint", Some("http://localhost:8551/"))
        .flag("execution-jwt-secret-key", Some(jwt_secret_key))
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert_eq!(
                config.execution_endpoint.as_ref().unwrap().full.to_string(),
                "http://localhost:8551/"
            );
            let mut file_jwt_secret_key = String::new();
            File::open(config.secret_file.as_ref().unwrap())
                .expect("could not open jwt_secret_key file")
                .read_to_string(&mut file_jwt_secret_key)
                .expect("could not read from file");
            assert_eq!(file_jwt_secret_key, jwt_secret_key);
        });
}
#[test]
fn execution_timeout_multiplier_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new_with_no_execution_endpoint()
        .flag("execution-endpoint", Some("http://meow.cats"))
        .flag(
            "execution-jwt",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .flag("execution-timeout-multiplier", Some("3"))
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert_eq!(config.execution_timeout_multiplier, Some(3));
        });
}
#[test]
fn bellatrix_execution_endpoints_flag() {
    run_bellatrix_execution_endpoints_flag_test("execution-endpoints")
}
#[test]
fn bellatrix_execution_endpoint_flag() {
    run_bellatrix_execution_endpoints_flag_test("execution-endpoint")
}
#[test]
fn bellatrix_jwt_secrets_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let mut file = File::create(dir.path().join("jwtsecrets")).expect("Unable to create file");
    file.write_all(b"0x3cbc11b0d8fa16f3344eacfd6ff6430b9d30734450e8adcf5400f88d327dcb33")
        .expect("Unable to write to file");
    CommandLineTest::new_with_no_execution_endpoint()
        .flag("execution-endpoints", Some("http://localhost:8551/"))
        .flag(
            "jwt-secrets",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert_eq!(
                config.execution_endpoint.as_ref().unwrap().full.to_string(),
                "http://localhost:8551/"
            );
            assert_eq!(
                config.secret_file.as_ref().unwrap().clone(),
                dir.path().join("jwt-file")
            );
        });
}
#[test]
fn bellatrix_fee_recipient_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new_with_no_execution_endpoint()
        .flag("execution-endpoint", Some("http://meow.cats"))
        .flag(
            "execution-jwt",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .flag(
            "suggested-fee-recipient",
            Some("0x00000000219ab540356cbb839cbe05303d7705fa"),
        )
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert_eq!(
                config.suggested_fee_recipient,
                Some(Address::from_str("0x00000000219ab540356cbb839cbe05303d7705fa").unwrap())
            );
        });
}
fn run_payload_builder_flag_test(flag: &str, builders: &str) {
    use sensitive_url::SensitiveUrl;

    let all_builders: Vec<_> = builders
        .split(",")
        .map(|builder| SensitiveUrl::parse(builder).expect("valid builder url"))
        .collect();
    run_payload_builder_flag_test_with_config(flag, builders, None, None, |config| {
        let config = config.execution_layer.as_ref().unwrap();
        // Only first provided endpoint is parsed as we don't support
        // redundancy.
        assert_eq!(config.builder_url, all_builders.first().cloned());
    })
}
fn run_payload_builder_flag_test_with_config<F: Fn(&Config)>(
    flag: &str,
    builders: &str,
    additional_flag: Option<&str>,
    additional_flag_value: Option<&str>,
    f: F,
) {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let mut test = CommandLineTest::new_with_no_execution_endpoint();
    test.flag("execution-endpoint", Some("http://meow.cats"))
        .flag(
            "execution-jwt",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .flag(flag, Some(builders));
    if let Some(additional_flag_name) = additional_flag {
        test.flag(additional_flag_name, additional_flag_value);
    }
    test.run_with_zero_port().with_config(f);
}

#[test]
fn payload_builder_flags() {
    run_payload_builder_flag_test("builder", "http://meow.cats");
    run_payload_builder_flag_test("payload-builder", "http://meow.cats");
    run_payload_builder_flag_test("payload-builders", "http://meow.cats,http://woof.dogs");
}

#[test]
fn builder_fallback_flags() {
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-fallback-skips"),
        Some("7"),
        |config| {
            assert_eq!(config.chain.builder_fallback_skips, 7);
        },
    );
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-fallback-skips-per-epoch"),
        Some("11"),
        |config| {
            assert_eq!(config.chain.builder_fallback_skips_per_epoch, 11);
        },
    );
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-fallback-epochs-since-finalization"),
        Some("4"),
        |config| {
            assert_eq!(config.chain.builder_fallback_epochs_since_finalization, 4);
        },
    );
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-fallback-disable-checks"),
        None,
        |config| {
            assert!(config.chain.builder_fallback_disable_checks);
        },
    );
}

#[test]
fn builder_get_header_timeout() {
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-header-timeout"),
        Some("1500"),
        |config| {
            assert_eq!(
                config
                    .execution_layer
                    .as_ref()
                    .unwrap()
                    .builder_header_timeout,
                Some(Duration::from_millis(1500))
            );
        },
    );
}

#[test]
fn builder_user_agent() {
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        None,
        None,
        |config| {
            assert_eq!(
                config.execution_layer.as_ref().unwrap().builder_user_agent,
                None
            );
        },
    );
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-user-agent"),
        Some("anon"),
        |config| {
            assert_eq!(
                config
                    .execution_layer
                    .as_ref()
                    .unwrap()
                    .builder_user_agent
                    .as_ref()
                    .unwrap(),
                "anon"
            );
        },
    );
}

#[test]
fn test_builder_disable_ssz_flag() {
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        None,
        None,
        |config| {
            assert!(
                !config
                    .execution_layer
                    .as_ref()
                    .unwrap()
                    .disable_builder_ssz_requests,
            );
        },
    );
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-disable-ssz"),
        None,
        |config| {
            assert!(
                config
                    .execution_layer
                    .as_ref()
                    .unwrap()
                    .disable_builder_ssz_requests,
            );
        },
    );
}

fn run_jwt_optional_flags_test(jwt_flag: &str, jwt_id_flag: &str, jwt_version_flag: &str) {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let execution_endpoint = "http://meow.cats";
    let jwt_file = "jwt-file";
    let id = "bn-1";
    let version = "Lighthouse-v2.1.3";
    CommandLineTest::new_with_no_execution_endpoint()
        .flag("execution-endpoint", Some(execution_endpoint))
        .flag(jwt_flag, dir.path().join(jwt_file).as_os_str().to_str())
        .flag(jwt_id_flag, Some(id))
        .flag(jwt_version_flag, Some(version))
        .run_with_zero_port()
        .with_config(|config| {
            let el_config = config.execution_layer.as_ref().unwrap();
            assert_eq!(el_config.jwt_id, Some(id.to_string()));
            assert_eq!(el_config.jwt_version, Some(version.to_string()));
        });
}
#[test]
fn jwt_optional_flags() {
    run_jwt_optional_flags_test("execution-jwt", "execution-jwt-id", "execution-jwt-version");
}
#[test]
fn jwt_optional_alias_flags() {
    run_jwt_optional_flags_test("jwt-secrets", "jwt-id", "jwt-version");
}

// Tests for Network flags.
#[test]
fn network_dir_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("network-dir", dir.path().as_os_str().to_str())
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.network_dir, dir.path()));
}
#[test]
fn network_target_peers_flag() {
    CommandLineTest::new()
        .flag("target-peers", Some("55"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.target_peers, "55".parse::<usize>().unwrap());
        });
}
#[test]
fn network_subscribe_all_data_column_subnets_flag() {
    CommandLineTest::new()
        .flag("subscribe-all-data-column-subnets", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.node_custody_type, NodeCustodyType::Supernode)
        });
}
#[test]
fn network_supernode_flag() {
    CommandLineTest::new()
        .flag("supernode", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.node_custody_type, NodeCustodyType::Supernode)
        });
}
#[test]
fn network_semi_supernode_flag() {
    CommandLineTest::new()
        .flag("semi-supernode", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.node_custody_type,
                NodeCustodyType::SemiSupernode
            )
        });
}
#[test]
fn network_node_custody_type_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.node_custody_type, NodeCustodyType::Fullnode)
        });
}
#[test]
fn blob_publication_batches() {
    CommandLineTest::new()
        .flag("blob-publication-batches", Some("3"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.blob_publication_batches, 3));
}

#[test]
fn blob_publication_batch_interval() {
    CommandLineTest::new()
        .flag("blob-publication-batch-interval", Some("400"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.blob_publication_batch_interval,
                Duration::from_millis(400)
            )
        });
}

#[test]
fn network_subscribe_all_subnets_flag() {
    CommandLineTest::new()
        .flag("subscribe-all-subnets", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.network.subscribe_all_subnets));
}
#[test]
fn network_import_all_attestations_flag() {
    CommandLineTest::new()
        .flag("import-all-attestations", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.network.import_all_attestations));
}
#[test]
fn network_shutdown_after_sync_flag() {
    CommandLineTest::new()
        .flag("shutdown-after-sync", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.network.shutdown_after_sync));
}
#[test]
fn network_shutdown_after_sync_disabled_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(!config.network.shutdown_after_sync));
}
#[test]
fn network_listen_address_flag_v4() {
    let addr = "127.0.0.2".parse::<Ipv4Addr>().unwrap();
    CommandLineTest::new()
        .flag("listen-address", Some("127.0.0.2"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|addr| addr.addr),
                Some(addr)
            )
        });
}
#[test]
fn network_listen_address_flag_v6() {
    const ADDR: &str = "::1";
    let addr = ADDR.parse::<Ipv6Addr>().unwrap();
    CommandLineTest::new()
        .flag("listen-address", Some(ADDR))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|addr| addr.addr),
                Some(addr)
            )
        });
}
#[test]
fn network_listen_address_flag_dual_stack() {
    const V4_ADDR: &str = "127.0.0.1";
    const V6_ADDR: &str = "::1";
    let ipv6_addr = V6_ADDR.parse::<Ipv6Addr>().unwrap();
    let ipv4_addr = V4_ADDR.parse::<Ipv4Addr>().unwrap();
    CommandLineTest::new()
        .flag("listen-address", Some(V6_ADDR))
        .flag("listen-address", Some(V4_ADDR))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|addr| addr.addr),
                Some(ipv6_addr)
            );
            assert_eq!(
                config.network.listen_addrs().v4().map(|addr| addr.addr),
                Some(ipv4_addr)
            )
        });
}
#[test]
#[should_panic]
fn network_listen_address_flag_wrong_double_v4_value_config() {
    // It's actually possible to listen over multiple sockets in libp2p over the same ip version.
    // However this is not compatible with the single contactable address over each version in ENR.
    // Because of this, it's important to test this is disallowed.
    const V4_ADDR1: &str = "127.0.0.1";
    const V4_ADDR2: &str = "0.0.0.0";
    CommandLineTest::new()
        .flag("listen-address", Some(V4_ADDR1))
        .flag("listen-address", Some(V4_ADDR2))
        .run_with_zero_port();
}
#[test]
#[should_panic]
fn network_listen_address_flag_wrong_double_v6_value_config() {
    // It's actually possible to listen over multiple sockets in libp2p over the same ip version.
    // However this is not compatible with the single contactable address over each version in ENR.
    // Because of this, it's important to test this is disallowed.
    const V6_ADDR1: &str = "::3";
    const V6_ADDR2: &str = "::1";
    CommandLineTest::new()
        .flag("listen-address", Some(V6_ADDR1))
        .flag("listen-address", Some(V6_ADDR2))
        .run_with_zero_port();
}
#[test]
fn network_port_flag_over_ipv4() {
    let port = 0;
    CommandLineTest::new()
        .flag("port", Some(port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be 0 if tcp_port is given as 0.
                Some((port, 0, port))
            );
        });

    let port = unused_tcp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("port", Some(port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be (tcp_port + 1) if tcp_port is given as non-zero.
                Some((port, port + 1, port))
            );
        });
}
#[test]
fn network_port_flag_over_ipv6() {
    let port = 0;
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("port", Some(port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be 0 if tcp_port is given as 0.
                Some((port, 0, port))
            );
        });

    let port = unused_tcp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("port", Some(port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be (tcp_port + 1) if tcp_port is given as non-zero.
                Some((port, port + 1, port))
            );
        });
}
#[test]
fn network_port_flag_over_ipv4_and_ipv6() {
    let port = 0;
    let port6 = 0;
    CommandLineTest::new()
        .flag("listen-address", Some("127.0.0.1"))
        .flag("listen-address", Some("::1"))
        .flag("port", Some(port.to_string().as_str()))
        .flag("port6", Some(port6.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be 0 if tcp_port is given as 0.
                Some((port, 0, port))
            );
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be 0 if tcp_port is given as 0.
                Some((port6, 0, port6))
            );
        });

    let port = unused_tcp4_port().expect("Unable to find unused port.");
    let port6 = unused_tcp6_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("listen-address", Some("127.0.0.1"))
        .flag("listen-address", Some("::1"))
        .flag("port", Some(port.to_string().as_str()))
        .flag("port6", Some(port6.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be (tcp_port + 1) if tcp_port is given as non-zero.
                Some((port, port + 1, port))
            );
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.disc_port,
                    listen_addr.quic_port,
                    listen_addr.tcp_port
                )),
                // quic_port should be (tcp_port + 1) if tcp_port is given as non-zero.
                Some((port6, port6 + 1, port6))
            );
        });
}
#[test]
fn network_port_and_discovery_port_flags_over_ipv4() {
    let tcp4_port = 0;
    let disc4_port = 0;
    CommandLineTest::new()
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("discovery-port", Some(disc4_port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v4()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.disc_port)),
                Some((tcp4_port, disc4_port))
            );
        });
}
#[test]
fn network_port_and_discovery_port_flags_over_ipv6() {
    let tcp6_port = 0;
    let disc6_port = 0;
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("port", Some(tcp6_port.to_string().as_str()))
        .flag("discovery-port", Some(disc6_port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v6()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.disc_port)),
                Some((tcp6_port, disc6_port))
            );
        });
}
#[test]
fn network_port_and_discovery_port_flags_over_ipv4_and_ipv6() {
    let tcp4_port = 0;
    let disc4_port = 0;
    let tcp6_port = 0;
    let disc6_port = 0;
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("listen-address", Some("127.0.0.1"))
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("discovery-port", Some(disc4_port.to_string().as_str()))
        .flag("port6", Some(tcp6_port.to_string().as_str()))
        .flag("discovery-port6", Some(disc6_port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v4()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.disc_port)),
                Some((tcp4_port, disc4_port))
            );

            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v6()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.disc_port)),
                Some((tcp6_port, disc6_port))
            );
        });
}

#[test]
fn network_port_discovery_quic_port_flags_over_ipv4_and_ipv6() {
    let tcp4_port = 0;
    let disc4_port = 0;
    let quic4_port = 0;
    let tcp6_port = 0;
    let disc6_port = 0;
    let quic6_port = 0;
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("listen-address", Some("127.0.0.1"))
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("discovery-port", Some(disc4_port.to_string().as_str()))
        .flag("quic-port", Some(quic4_port.to_string().as_str()))
        .flag("port6", Some(tcp6_port.to_string().as_str()))
        .flag("discovery-port6", Some(disc6_port.to_string().as_str()))
        .flag("quic-port6", Some(quic6_port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.tcp_port,
                    listen_addr.disc_port,
                    listen_addr.quic_port
                )),
                Some((tcp4_port, disc4_port, quic4_port))
            );

            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.tcp_port,
                    listen_addr.disc_port,
                    listen_addr.quic_port
                )),
                Some((tcp6_port, disc6_port, quic6_port))
            );
        });
}

#[test]
fn disable_discovery_flag() {
    CommandLineTest::new()
        .flag("disable-discovery", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.network.disable_discovery));
}

#[test]
fn disable_quic_flag() {
    CommandLineTest::new()
        .flag("disable-quic", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.network.disable_quic_support));
}
#[test]
fn disable_peer_scoring_flag() {
    CommandLineTest::new()
        .flag("disable-peer-scoring", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.network.disable_peer_scoring));
}
#[test]
fn disable_upnp_flag() {
    CommandLineTest::new()
        .flag("disable-upnp", None)
        .run_with_zero_port()
        .with_config(|config| assert!(!config.network.upnp_enabled));
}
#[test]
fn disable_backfill_rate_limiting_flag() {
    CommandLineTest::new()
        .flag("disable-backfill-rate-limiting", None)
        .run_with_zero_port()
        .with_config(|config| assert!(!config.beacon_processor.enable_backfill_rate_limiting));
}
#[test]
fn default_backfill_rate_limiting_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(config.beacon_processor.enable_backfill_rate_limiting));
}
#[test]
fn default_boot_nodes() {
    let number_of_boot_nodes = 17;

    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            // Lighthouse Team (Sigma Prime)
            assert_eq!(config.network.boot_nodes_enr.len(), number_of_boot_nodes);
        });
}
#[test]
fn boot_nodes_flag() {
    let nodes = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8,\
                enr:-LK4QFOFWca5ABQzxiCRcy37G7wy1K6zD4qMYBSN5ozzanwze_XVvXVhCk9JvF0cHXOBZrHK1E4vU7Gn-a0bHVczoDU6h2F0dG5ldHOIAAAAAAAAAACEZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhNIy-4iJc2VjcDI1NmsxoQJA3AXQJ6M3NpBWtJS3HPtbXG14t7qHjXuIaL6IOz89T4N0Y3CCIyiDdWRwgiMo";
    let enr: Vec<&str> = nodes.split(',').collect();
    CommandLineTest::new()
        .flag("boot-nodes", Some(nodes))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.boot_nodes_enr[0].to_base64(), enr[0]);
            assert_eq!(config.network.boot_nodes_enr[1].to_base64(), enr[1]);
        });
}
#[test]
fn boot_nodes_multiaddr_flag() {
    let nodes = "/ip4/0.0.0.0/tcp/9000/p2p/16Uiu2HAkynrfLjeoAP7R3WFySad2NfduShkTpx8f8ygpSSfP1yen,\
                /ip4/192.167.55.55/tcp/9000/p2p/16Uiu2HAkynrfLjeoBP7R3WFyDad2NfduVhkWpx8f8ygpSSfP1yen";
    let multiaddr: Vec<&str> = nodes.split(',').collect();
    CommandLineTest::new()
        .flag("boot-nodes", Some(nodes))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.boot_nodes_multiaddr[0].to_string(),
                multiaddr[0]
            );
            assert_eq!(
                config.network.boot_nodes_multiaddr[1].to_string(),
                multiaddr[1]
            );
        });
}
#[test]
fn private_flag() {
    CommandLineTest::new()
        .flag("private", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.network.private);
            assert!(matches!(
                config.beacon_graffiti,
                GraffitiOrigin::UserSpecified(_)
            ));
            assert_eq!(
                config.beacon_graffiti.graffiti().to_string(),
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            );
        });
}
#[test]
fn zero_ports_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.http_api.listen_port, 0);
            assert_eq!(config.http_metrics.listen_port, 0);
        });
}
#[test]
fn network_load_flag() {
    CommandLineTest::new()
        .flag("network-load", Some("4"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.network_load, 4);
        });
}

// Tests for ENR flags.
#[test]
fn enr_udp_port_flag() {
    let port = DUMMY_ENR_UDP_PORT;
    assert!(port != 0);
    CommandLineTest::new()
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.enr_udp4_port.map(|port| port.get()),
                Some(port)
            )
        });
}
#[test]
fn enr_quic_port_flag() {
    let port = DUMMY_ENR_QUIC_PORT;
    CommandLineTest::new()
        .flag("enr-quic-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.enr_quic4_port.map(|port| port.get()),
                Some(port)
            )
        });
}
#[test]
fn enr_tcp_port_flag() {
    let port = DUMMY_ENR_TCP_PORT;
    CommandLineTest::new()
        .flag("enr-tcp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.enr_tcp4_port.map(|port| port.get()),
                Some(port)
            )
        });
}
#[test]
fn enr_udp6_port_flag() {
    let port = DUMMY_ENR_UDP_PORT;
    CommandLineTest::new()
        .flag("enr-udp6-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.enr_udp6_port.map(|port| port.get()),
                Some(port)
            )
        });
}
#[test]
fn enr_quic6_port_flag() {
    let port = DUMMY_ENR_QUIC_PORT;
    CommandLineTest::new()
        .flag("enr-quic6-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.enr_quic6_port.map(|port| port.get()),
                Some(port)
            )
        });
}
#[test]
fn enr_tcp6_port_flag() {
    let port = DUMMY_ENR_TCP_PORT;
    CommandLineTest::new()
        .flag("enr-tcp6-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.enr_tcp6_port.map(|port| port.get()),
                Some(port)
            )
        });
}
#[test]
fn enr_match_flag_over_ipv4() {
    let addr = "127.0.0.2".parse::<Ipv4Addr>().unwrap();

    let udp4_port = unused_udp4_port().expect("Unable to find unused port.");
    let tcp4_port = unused_tcp4_port().expect("Unable to find unused port.");

    CommandLineTest::new()
        .flag("enr-match", None)
        .flag("listen-address", Some("127.0.0.2"))
        .flag("discovery-port", Some(udp4_port.to_string().as_str()))
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.disc_port,
                    listen_addr.tcp_port
                )),
                Some((addr, udp4_port, tcp4_port))
            );
            assert_eq!(config.network.enr_address, (Some(addr), None));
            assert_eq!(
                config.network.enr_udp4_port.map(|port| port.get()),
                Some(udp4_port)
            );
        });
}
#[test]
fn enr_match_flag_over_ipv6() {
    const ADDR: &str = "::1";
    let addr = ADDR.parse::<Ipv6Addr>().unwrap();

    let udp6_port = unused_udp6_port().expect("Unable to find unused port.");
    let tcp6_port = unused_tcp6_port().expect("Unable to find unused port.");

    CommandLineTest::new()
        .flag("enr-match", None)
        .flag("listen-address", Some(ADDR))
        .flag("discovery-port", Some(udp6_port.to_string().as_str()))
        .flag("port", Some(tcp6_port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.disc_port,
                    listen_addr.tcp_port
                )),
                Some((addr, udp6_port, tcp6_port))
            );
            assert_eq!(config.network.enr_address, (None, Some(addr)));
            assert_eq!(
                config.network.enr_udp6_port.map(|port| port.get()),
                Some(udp6_port)
            );
        });
}
#[test]
fn enr_match_flag_over_ipv4_and_ipv6() {
    const IPV6_ADDR: &str = "::1";

    let udp6_port = unused_udp6_port().expect("Unable to find unused port.");
    let tcp6_port = unused_tcp6_port().expect("Unable to find unused port.");
    let ipv6_addr = IPV6_ADDR.parse::<Ipv6Addr>().unwrap();

    const IPV4_ADDR: &str = "127.0.0.1";
    let udp4_port = unused_udp4_port().expect("Unable to find unused port.");
    let tcp4_port = unused_tcp4_port().expect("Unable to find unused port.");
    let ipv4_addr = IPV4_ADDR.parse::<Ipv4Addr>().unwrap();

    CommandLineTest::new()
        .flag("enr-match", None)
        .flag("listen-address", Some(IPV4_ADDR))
        .flag("discovery-port", Some(udp4_port.to_string().as_str()))
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("listen-address", Some(IPV6_ADDR))
        .flag("discovery-port6", Some(udp6_port.to_string().as_str()))
        .flag("port6", Some(tcp6_port.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.disc_port,
                    listen_addr.tcp_port
                )),
                Some((ipv6_addr, udp6_port, tcp6_port))
            );
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.disc_port,
                    listen_addr.tcp_port
                )),
                Some((ipv4_addr, udp4_port, tcp4_port))
            );
            assert_eq!(
                config.network.enr_address,
                (Some(ipv4_addr), Some(ipv6_addr))
            );
            assert_eq!(
                config.network.enr_udp6_port.map(|port| port.get()),
                Some(udp6_port)
            );
            assert_eq!(
                config.network.enr_udp4_port.map(|port| port.get()),
                Some(udp4_port)
            );
        });
}
#[test]
fn enr_address_flag_with_ipv4() {
    let addr = "192.167.1.1".parse::<Ipv4Addr>().unwrap();
    let port = DUMMY_ENR_UDP_PORT;
    CommandLineTest::new()
        .flag("enr-address", Some("192.167.1.1"))
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.enr_address, (Some(addr), None));
            assert_eq!(
                config.network.enr_udp4_port.map(|port| port.get()),
                Some(port)
            );
        });
}
#[test]
fn enr_address_flag_with_ipv6() {
    let addr = "192.167.1.1".parse::<Ipv4Addr>().unwrap();
    let port = DUMMY_ENR_UDP_PORT;
    CommandLineTest::new()
        .flag("enr-address", Some("192.167.1.1"))
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.enr_address, (Some(addr), None));
            assert_eq!(
                config.network.enr_udp4_port.map(|port| port.get()),
                Some(port)
            );
        });
}
#[test]
fn enr_address_dns_flag() {
    let addr = Ipv4Addr::LOCALHOST;
    let ipv6addr = Ipv6Addr::LOCALHOST;
    let port = DUMMY_ENR_UDP_PORT;
    CommandLineTest::new()
        .flag("enr-address", Some("localhost"))
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert!(
                config.network.enr_address.0 == Some(addr)
                    || config.network.enr_address.1 == Some(ipv6addr)
            );
            assert_eq!(
                config.network.enr_udp4_port.map(|port| port.get()),
                Some(port)
            );
        });
}
#[test]
fn disable_enr_auto_update_flag() {
    CommandLineTest::new()
        .flag("disable-enr-auto-update", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.network.discv5_config.enr_update));
}

// Tests for HTTP flags.
#[test]
fn http_flag() {
    CommandLineTest::new()
        .flag("http", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.http_api.enabled));
}
#[test]
fn http_address_flag() {
    let addr = "127.0.0.99".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-address", Some("127.0.0.99"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
}
#[test]
fn http_address_ipv6_flag() {
    let addr = "::1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-address", Some("::1"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
}
#[test]
fn http_port_flag() {
    let port1 = 0;
    let port2 = 0;
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-port", Some(port1.to_string().as_str()))
        .flag("port", Some(port2.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_port, port1));
}

#[test]
fn empty_inbound_rate_limiter_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.inbound_rate_limiter_config,
                Some(lighthouse_network::rpc::config::InboundRateLimiterConfig::default())
            )
        });
}
#[test]
fn disable_inbound_rate_limiter_flag() {
    CommandLineTest::new()
        .flag("disable-inbound-rate-limiter", None)
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.inbound_rate_limiter_config, None));
}

#[test]
fn http_allow_origin_flag() {
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-allow-origin", Some("http://127.0.0.99"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.http_api.allow_origin,
                Some("http://127.0.0.99".to_string())
            );
        });
}
#[test]
fn http_allow_origin_all_flag() {
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-allow-origin", Some("*"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.allow_origin, Some("*".to_string())));
}

#[test]
fn http_enable_beacon_processor() {
    CommandLineTest::new()
        .flag("http", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.http_api.enable_beacon_processor));

    CommandLineTest::new()
        .flag("http", None)
        .flag("http-enable-beacon-processor", Some("true"))
        .run_with_zero_port()
        .with_config(|config| assert!(config.http_api.enable_beacon_processor));

    CommandLineTest::new()
        .flag("http", None)
        .flag("http-enable-beacon-processor", Some("false"))
        .run_with_zero_port()
        .with_config(|config| assert!(!config.http_api.enable_beacon_processor));
}
#[test]
fn http_tls_flags() {
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-enable-tls", None)
        .flag("http-tls-cert", Some("tests/tls/cert.pem"))
        .flag("http-tls-key", Some("tests/tls/key.rsa"))
        .run_with_zero_port()
        .with_config(|config| {
            let tls_config = config
                .http_api
                .tls_config
                .as_ref()
                .expect("tls_config was empty.");
            assert_eq!(tls_config.cert, Path::new("tests/tls/cert.pem"));
            assert_eq!(tls_config.key, Path::new("tests/tls/key.rsa"));
        });
}

// Tests for Metrics flags.
#[test]
fn metrics_flag() {
    CommandLineTest::new()
        .flag("metrics", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.http_metrics.enabled);
            assert!(config.network.metrics_enabled);
        });
}
#[test]
fn metrics_address_flag() {
    let addr = "127.0.0.99".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("metrics", None)
        .flag("metrics-address", Some("127.0.0.99"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_metrics.listen_addr, addr));
}
#[test]
fn metrics_address_ipv6_flag() {
    let addr = "::1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("metrics", None)
        .flag("metrics-address", Some("::1"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_metrics.listen_addr, addr));
}
#[test]
fn metrics_port_flag() {
    let port1 = 0;
    let port2 = 0;
    CommandLineTest::new()
        .flag("metrics", None)
        .flag("metrics-port", Some(port1.to_string().as_str()))
        .flag("port", Some(port2.to_string().as_str()))
        .flag("allow-insecure-genesis-sync", None)
        .run()
        .with_config(|config| assert_eq!(config.http_metrics.listen_port, port1));
}
#[test]
fn metrics_allow_origin_flag() {
    CommandLineTest::new()
        .flag("metrics", None)
        .flag("metrics-allow-origin", Some("http://localhost:5059"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.http_metrics.allow_origin,
                Some("http://localhost:5059".to_string())
            )
        });
}
#[test]
fn metrics_allow_origin_all_flag() {
    CommandLineTest::new()
        .flag("metrics", None)
        .flag("metrics-allow-origin", Some("*"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_metrics.allow_origin, Some("*".to_string())));
}

// Tests for Validator Monitor flags.
#[test]
fn validator_monitor_default_values() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(config.validator_monitor == <_>::default()));
}
#[test]
fn validator_monitor_auto_flag() {
    CommandLineTest::new()
        .flag("validator-monitor-auto", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.validator_monitor.auto_register));
}
#[test]
fn validator_monitor_pubkeys_flag() {
    CommandLineTest::new()
        .flag("validator-monitor-pubkeys", Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,\
                                                0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.validator_monitor.validators[0].to_string(), "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
            assert_eq!(config.validator_monitor.validators[1].to_string(), "0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
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
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.validator_monitor.validators[0].to_string(), "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
            assert_eq!(config.validator_monitor.validators[1].to_string(), "0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        });
}
#[test]
fn validator_monitor_metrics_threshold_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.validator_monitor.individual_tracking_threshold,
                // If this value changes make sure to update the help text for
                // the CLI command.
                64
            )
        });
}
#[test]
fn validator_monitor_metrics_threshold_custom() {
    CommandLineTest::new()
        .flag(
            "validator-monitor-individual-tracking-threshold",
            Some("42"),
        )
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.validator_monitor.individual_tracking_threshold, 42)
        });
}

// Tests for Store flags.
// DEPRECATED but should still be accepted.
#[test]
fn slots_per_restore_point_flag() {
    CommandLineTest::new()
        .flag("slots-per-restore-point", Some("64"))
        .run_with_zero_port();
}

#[test]
fn block_cache_size_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.block_cache_size, 0));
}
#[test]
fn block_cache_size_flag() {
    CommandLineTest::new()
        .flag("block-cache-size", Some("4"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.block_cache_size, 4));
}
#[test]
fn block_cache_size_zero() {
    CommandLineTest::new()
        .flag("block-cache-size", Some("0"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.block_cache_size, 0));
}
#[test]
fn state_cache_size_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.state_cache_size, new_non_zero_usize(128)));
}
#[test]
fn state_cache_size_flag() {
    CommandLineTest::new()
        .flag("state-cache-size", Some("64"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.state_cache_size, new_non_zero_usize(64)));
}
#[test]
fn state_cache_headroom_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.state_cache_headroom, new_non_zero_usize(1)));
}
#[test]
fn state_cache_headroom_flag() {
    CommandLineTest::new()
        .flag("state-cache-headroom", Some("16"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.store.state_cache_headroom, new_non_zero_usize(16))
        });
}
#[test]
fn historic_state_cache_size_flag() {
    CommandLineTest::new()
        .flag("historic-state-cache-size", Some("4"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.store.historic_state_cache_size,
                new_non_zero_usize(4)
            )
        });
}
#[test]
fn historic_state_cache_size_default() {
    use beacon_node::beacon_chain::store::config::DEFAULT_HISTORIC_STATE_CACHE_SIZE;
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.store.historic_state_cache_size,
                DEFAULT_HISTORIC_STATE_CACHE_SIZE
            );
        });
}
#[test]
fn hdiff_buffer_cache_size_flag() {
    CommandLineTest::new()
        .flag("hdiff-buffer-cache-size", Some("1"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.store.cold_hdiff_buffer_cache_size.get(), 1);
        });
}
#[test]
fn hdiff_buffer_cache_size_default() {
    use beacon_node::beacon_chain::store::config::DEFAULT_COLD_HDIFF_BUFFER_CACHE_SIZE;
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.store.cold_hdiff_buffer_cache_size,
                DEFAULT_COLD_HDIFF_BUFFER_CACHE_SIZE
            );
        });
}
#[test]
fn hot_hdiff_buffer_cache_size_default() {
    use beacon_node::beacon_chain::store::config::DEFAULT_HOT_HDIFF_BUFFER_CACHE_SIZE;
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.store.hot_hdiff_buffer_cache_size,
                DEFAULT_HOT_HDIFF_BUFFER_CACHE_SIZE
            );
        });
}
#[test]
fn hot_hdiff_buffer_cache_size_flag() {
    CommandLineTest::new()
        .flag("hot-hdiff-buffer-cache-size", Some("3"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.store.hot_hdiff_buffer_cache_size.get(), 3);
        });
}
#[test]
fn auto_compact_db_flag() {
    CommandLineTest::new()
        .flag("auto-compact-db", Some("false"))
        .run_with_zero_port()
        .with_config(|config| assert!(!config.store.compact_on_prune));
}
#[test]
fn compact_db_flag() {
    CommandLineTest::new()
        .flag("auto-compact-db", Some("false"))
        .flag("compact-db", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.store.compact_on_init));
}
#[test]
fn prune_payloads_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(config.store.prune_payloads));
}
#[test]
fn prune_payloads_on_startup_false() {
    CommandLineTest::new()
        .flag("prune-payloads", Some("false"))
        .run_with_zero_port()
        .with_config(|config| assert!(!config.store.prune_payloads));
}
#[test]
fn prune_blobs_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(config.store.prune_blobs));
}
#[test]
fn prune_blobs_on_startup_false() {
    CommandLineTest::new()
        .flag("prune-blobs", Some("false"))
        .run_with_zero_port()
        .with_config(|config| assert!(!config.store.prune_blobs));
}
#[test]
fn epochs_per_blob_prune_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.epochs_per_blob_prune, 256));
}
#[test]
fn epochs_per_blob_prune_on_startup_five() {
    CommandLineTest::new()
        .flag("epochs-per-blob-prune", Some("5"))
        .run_with_zero_port()
        .with_config(|config| assert!(config.store.epochs_per_blob_prune == 5));
}
#[test]
fn blob_prune_margin_epochs_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(config.store.blob_prune_margin_epochs == 0));
}
#[test]
fn blob_prune_margin_epochs_on_startup_ten() {
    CommandLineTest::new()
        .flag("blob-prune-margin-epochs", Some("10"))
        .run_with_zero_port()
        .with_config(|config| assert!(config.store.blob_prune_margin_epochs == 10));
}
#[test]
fn reconstruct_historic_states_flag() {
    CommandLineTest::new()
        .flag("reconstruct-historic-states", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.reconstruct_historic_states));
}
#[test]
fn no_reconstruct_historic_states_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(!config.chain.reconstruct_historic_states));
}
#[test]
fn epochs_per_migration_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.epochs_per_migration,
                beacon_node::beacon_chain::migrate::DEFAULT_EPOCHS_PER_MIGRATION
            )
        });
}
#[test]
fn epochs_per_migration_override() {
    CommandLineTest::new()
        .flag("epochs-per-migration", Some("128"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.epochs_per_migration, 128));
}
#[test]
fn malicious_withhold_count_flag() {
    CommandLineTest::new()
        .flag("malicious-withhold-count", Some("128"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.malicious_withhold_count, 128));
}

// Tests for Slasher flags.
// Using `--slasher-max-db-size` to work around https://github.com/sigp/lighthouse/issues/2342
#[test]
fn slasher_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .run_with_zero_port()
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
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-dir", dir.path().as_os_str().to_str())
        .run_with_zero_port()
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
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-update-period", Some("100"))
        .run_with_zero_port()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.update_period, 100);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_slot_offset_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-slot-offset", Some("11.25"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config.slasher.as_ref().unwrap();
            assert_eq!(slasher_config.slot_offset, 11.25);
        });
}
#[test]
#[should_panic]
fn slasher_slot_offset_nan_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-slot-offset", Some("NaN"))
        .run_with_zero_port();
}
#[test]
fn slasher_history_length_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-history-length", Some("2048"))
        .run_with_zero_port()
        .with_config(|config| {
            if let Some(slasher_config) = &config.slasher {
                assert_eq!(slasher_config.history_length, 2048);
            } else {
                panic!("Slasher config was parsed incorrectly");
            }
        });
}
#[test]
fn slasher_max_db_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("2"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert_eq!(slasher_config.max_db_size_mbs, 2048);
        });
}
#[test]
fn slasher_attestation_cache_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-att-cache-size", Some("10000"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert_eq!(
                slasher_config.attestation_root_cache_size,
                new_non_zero_usize(10000)
            );
        });
}
#[test]
fn slasher_chunk_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-chunk-size", Some("32"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert_eq!(slasher_config.chunk_size, 32);
        });
}
#[test]
fn slasher_validator_chunk_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-validator-chunk-size", Some("512"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert_eq!(slasher_config.validator_chunk_size, 512);
        });
}
#[test]
fn slasher_broadcast_flag_no_args() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert!(slasher_config.broadcast);
        });
}
#[test]
fn slasher_broadcast_flag_no_default() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert!(slasher_config.broadcast);
        });
}
#[test]
fn slasher_broadcast_flag_no_argument() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-broadcast", None)
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert!(slasher_config.broadcast);
        });
}
#[test]
fn slasher_broadcast_flag_true() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-broadcast", Some("true"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert!(slasher_config.broadcast);
        });
}
#[test]
fn slasher_broadcast_flag_false() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-broadcast", Some("false"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert!(!slasher_config.broadcast);
        });
}

#[cfg(feature = "slasher-lmdb")]
#[test]
fn slasher_backend_override_to_default() {
    // Hard to test this flag because all but one backend is disabled by default and the backend
    // called "disabled" results in a panic.
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-max-db-size", Some("1"))
        .flag("slasher-backend", Some("lmdb"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config.slasher.as_ref().unwrap();
            assert_eq!(slasher_config.backend, slasher::DatabaseBackend::Lmdb);
        });
}

#[test]
fn malloc_tuning_flag() {
    CommandLineTest::new()
        .flag("disable-malloc-tuning", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.http_metrics.allocator_metrics_enabled);
        });
}
#[test]
#[should_panic]
fn ensure_panic_on_failed_launch() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-chunk-size", Some("10"))
        .set_allow_insecure_genesis_sync()
        .set_zero_port()
        .run_with_immediate_shutdown(false)
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert_eq!(slasher_config.chunk_size, 10);
        });
}

#[test]
fn enable_proposer_re_orgs_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.re_org_head_threshold,
                Some(DEFAULT_RE_ORG_HEAD_THRESHOLD)
            );
            assert_eq!(
                config.chain.re_org_max_epochs_since_finalization,
                DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION,
            );
            assert_eq!(
                config.chain.re_org_cutoff(12),
                Duration::from_secs(12) / DEFAULT_RE_ORG_CUTOFF_DENOMINATOR
            );
        });
}

#[test]
fn disable_proposer_re_orgs() {
    CommandLineTest::new()
        .flag("disable-proposer-reorgs", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.re_org_head_threshold, None);
            assert_eq!(config.chain.re_org_parent_threshold, None)
        });
}

#[test]
fn proposer_re_org_parent_threshold() {
    CommandLineTest::new()
        .flag("proposer-reorg-parent-threshold", Some("90"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.re_org_parent_threshold.unwrap().0, 90));
}

#[test]
fn proposer_re_org_head_threshold() {
    CommandLineTest::new()
        .flag("proposer-reorg-threshold", Some("90"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.re_org_head_threshold.unwrap().0, 90));
}

#[test]
fn proposer_re_org_max_epochs_since_finalization() {
    CommandLineTest::new()
        .flag("proposer-reorg-epochs-since-finalization", Some("8"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.re_org_max_epochs_since_finalization.as_u64(),
                8
            )
        });
}

#[test]
fn proposer_re_org_cutoff() {
    CommandLineTest::new()
        .flag("proposer-reorg-cutoff", Some("500"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.re_org_cutoff(12), Duration::from_millis(500))
        });
}

#[test]
fn proposer_re_org_disallowed_offsets_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.re_org_disallowed_offsets,
                DisallowedReOrgOffsets::new::<MainnetEthSpec>(vec![0]).unwrap()
            )
        });
}

#[test]
fn proposer_re_org_disallowed_offsets_override() {
    CommandLineTest::new()
        .flag("proposer-reorg-disallowed-offsets", Some("1,2,3"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.re_org_disallowed_offsets,
                DisallowedReOrgOffsets::new::<MainnetEthSpec>(vec![1, 2, 3]).unwrap()
            )
        });
}

#[test]
#[should_panic]
fn proposer_re_org_disallowed_offsets_invalid() {
    CommandLineTest::new()
        .flag("proposer-reorg-disallowed-offsets", Some("32,33,34"))
        .run_with_zero_port();
}

#[test]
fn monitoring_endpoint() {
    CommandLineTest::new()
        .flag("monitoring-endpoint", Some("http://example:8000"))
        .flag("monitoring-endpoint-period", Some("30"))
        .run_with_zero_port()
        .with_config(|config| {
            let api_conf = config.monitoring_api.as_ref().unwrap();
            assert_eq!(api_conf.monitoring_endpoint.as_str(), "http://example:8000");
            assert_eq!(api_conf.update_period_secs, Some(30));
        });
}

// Tests for Logger flags.
#[test]
fn default_logfile_color_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.logger_config.logfile_color);
        });
}
#[test]
fn enabled_logfile_color_flag() {
    CommandLineTest::new()
        .flag("logfile-color", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.logger_config.logfile_color);
        });
}
#[test]
fn default_disable_log_timestamp_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.logger_config.disable_log_timestamp);
        });
}
#[test]
fn enabled_disable_log_timestamp_flag() {
    CommandLineTest::new()
        .flag("disable-log-timestamp", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.logger_config.disable_log_timestamp);
        });
}
#[test]
fn logfile_restricted_perms_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.logger_config.is_restricted);
        });
}
#[test]
fn logfile_no_restricted_perms_flag() {
    CommandLineTest::new()
        .flag("logfile-no-restricted-perms", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.logger_config.is_restricted);
        });
}
#[test]
fn logfile_format_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.logger_config.logfile_format, None));
}
#[test]
fn logfile_format_flag() {
    CommandLineTest::new()
        .flag("logfile-format", Some("JSON"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.logger_config.logfile_format,
                Some("JSON".to_string())
            )
        });
}

#[test]
fn light_client_server_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.network.enable_light_client_server);
            assert!(config.chain.enable_light_client_server);
        });
}

#[test]
fn light_client_server_enabled() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.network.enable_light_client_server);
            assert!(config.chain.enable_light_client_server);
        });
}

#[test]
fn light_client_server_disabled() {
    CommandLineTest::new()
        .flag("disable-light-client-server", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.network.enable_light_client_server);
            assert!(!config.chain.enable_light_client_server);
        });
}

#[test]
fn get_blobs_disabled() {
    CommandLineTest::new()
        .flag("disable-get-blobs", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.chain.disable_get_blobs);
        });
}

#[test]
fn get_blobs_enabled() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.chain.disable_get_blobs);
        });
}

#[test]
fn light_client_http_server_disabled() {
    CommandLineTest::new()
        .flag("http", None)
        .flag("disable-light-client-server", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.network.enable_light_client_server);
            assert!(!config.chain.enable_light_client_server);
        });
}

#[test]
fn sync_tolerance_epochs() {
    CommandLineTest::new()
        .flag("http", None)
        .flag("sync-tolerance-epochs", Some("0"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.sync_tolerance_epochs, 0);
        });
}

#[test]
fn sync_tolerance_epochs_default() {
    CommandLineTest::new()
        .flag("http", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.sync_tolerance_epochs,
                DEFAULT_SYNC_TOLERANCE_EPOCHS
            );
        });
}

#[test]
fn gui_flag() {
    CommandLineTest::new()
        .flag("gui", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.http_api.enabled);
            assert!(config.validator_monitor.auto_register);
        });
}

#[test]
fn multiple_http_enabled_flags() {
    CommandLineTest::new()
        .flag("gui", None)
        .flag("http", None)
        .flag("staking", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.http_api.enabled);
        });
}

#[test]
fn optimistic_finalized_sync_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.chain.optimistic_finalized_sync);
        });
}

#[test]
fn disable_optimistic_finalized_sync() {
    CommandLineTest::new()
        .flag("disable-optimistic-finalized-sync", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.chain.optimistic_finalized_sync);
        });
}

#[test]
fn invalid_gossip_verified_blocks_path_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.invalid_block_storage, None));
}

#[test]
fn invalid_gossip_verified_blocks_path() {
    let path = "/home/karlm/naughty-blocks";
    CommandLineTest::new()
        .flag("invalid-gossip-verified-blocks-path", Some(path))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.invalid_block_storage,
                Some(PathBuf::from(path))
            )
        });
}

#[test]
fn advertise_false_custody_group_count() {
    CommandLineTest::new()
        .flag("advertise-false-custody-group-count", Some("64"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.advertise_false_custody_group_count, Some(64))
        });
}

#[test]
fn beacon_processor() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.beacon_processor, <_>::default()));

    CommandLineTest::new()
        .flag("beacon-processor-max-workers", Some("1"))
        .flag("beacon-processor-work-queue-len", Some("2"))
        .flag("beacon-processor-reprocess-queue-len", Some("3"))
        .flag("beacon-processor-attestation-batch-size", Some("4"))
        .flag("beacon-processor-aggregate-batch-size", Some("5"))
        .flag("disable-backfill-rate-limiting", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.beacon_processor,
                BeaconProcessorConfig {
                    max_workers: 1,
                    max_work_event_queue_len: 2,
                    max_scheduled_work_queue_len: 3,
                    max_gossip_attestation_batch_size: 4,
                    max_gossip_aggregate_batch_size: 5,
                    enable_backfill_rate_limiting: false
                }
            )
        });
}

#[test]
#[should_panic]
fn beacon_processor_zero_workers() {
    CommandLineTest::new()
        .flag("beacon-processor-max-workers", Some("0"))
        .run_with_zero_port();
}

#[test]
fn http_sse_capacity_multiplier_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.sse_capacity_multiplier, 1));
}

#[test]
fn http_sse_capacity_multiplier_override() {
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-sse-capacity-multiplier", Some("10"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.sse_capacity_multiplier, 10));
}

#[test]
fn http_duplicate_block_status_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.http_api.duplicate_block_status_code.as_u16(), 202)
        });
}

#[test]
fn http_duplicate_block_status_override() {
    CommandLineTest::new()
        .flag("http", None)
        .flag("http-duplicate-block-status", Some("301"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.http_api.duplicate_block_status_code.as_u16(), 301)
        });
}

#[test]
fn genesis_state_url_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.genesis_state_url, None);
            assert_eq!(config.genesis_state_url_timeout, Duration::from_secs(300));
        });
}

#[test]
fn genesis_state_url_value() {
    CommandLineTest::new()
        .flag("genesis-state-url", Some("http://genesis.com"))
        .flag("genesis-state-url-timeout", Some("42"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.genesis_state_url.as_deref(),
                Some("http://genesis.com")
            );
            assert_eq!(config.genesis_state_url_timeout, Duration::from_secs(42));
        });
}

#[test]
fn beacon_node_backend_override() {
    CommandLineTest::new()
        .flag("beacon-node-backend", Some("leveldb"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.store.backend, BeaconNodeBackend::LevelDb);
        });
}

#[test]
fn block_publishing_delay_for_testing() {
    CommandLineTest::new()
        .flag("delay-block-publishing", Some("2.5"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.block_publishing_delay,
                Some(Duration::from_secs_f64(2.5f64))
            );
        });
}

#[test]
fn data_column_publishing_delay_for_testing() {
    CommandLineTest::new()
        .flag("delay-data-column-publishing", Some("3.5"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.chain.data_column_publishing_delay,
                Some(Duration::from_secs_f64(3.5f64))
            );
        });
}

#[test]
fn invalid_block_roots_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let mut file =
        File::create(dir.path().join("invalid-block-roots")).expect("Unable to create file");
    file.write_all(b"2db899881ed8546476d0b92c6aa9110bea9a4cd0dbeb5519eb0ea69575f1f359, 2db899881ed8546476d0b92c6aa9110bea9a4cd0dbeb5519eb0ea69575f1f358, 0x3db899881ed8546476d0b92c6aa9110bea9a4cd0dbeb5519eb0ea69575f1f358")
        .expect("Unable to write to file");
    CommandLineTest::new()
        .flag(
            "invalid-block-roots",
            dir.path().join("invalid-block-roots").as_os_str().to_str(),
        )
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.invalid_block_roots.len(), 3))
}

#[test]
fn invalid_block_roots_default_holesky() {
    use beacon_node::beacon_chain::chain_config::INVALID_HOLESKY_BLOCK_ROOT;
    CommandLineTest::new()
        .flag("network", Some("holesky"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.chain.invalid_block_roots.len(), 1);
            assert!(
                config
                    .chain
                    .invalid_block_roots
                    .contains(&*INVALID_HOLESKY_BLOCK_ROOT)
            );
        })
}

#[test]
fn invalid_block_roots_default_mainnet() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.chain.invalid_block_roots.is_empty());
        })
}
