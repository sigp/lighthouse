use beacon_node::ClientConfig as Config;

use crate::exec::{CommandLineTestExec, CompletedTest};
use beacon_node::beacon_chain::chain_config::{
    DisallowedReOrgOffsets, DEFAULT_RE_ORG_CUTOFF_DENOMINATOR,
    DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION, DEFAULT_RE_ORG_THRESHOLD,
};
use eth1::Eth1Endpoint;
use lighthouse_network::PeerId;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::string::ToString;
use std::time::Duration;
use tempfile::TempDir;
use types::{Address, Checkpoint, Epoch, ExecutionBlockHash, ForkName, Hash256, MainnetEthSpec};
use unused_port::{unused_tcp4_port, unused_tcp6_port, unused_udp4_port, unused_udp6_port};

const DEFAULT_ETH1_ENDPOINT: &str = "http://localhost:8545/";

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
        let base_cmd = base_cmd();
        CommandLineTest { cmd: base_cmd }
    }

    fn run_with_zero_port(&mut self) -> CompletedTest<Config> {
        self.cmd.arg("-z");
        self.run()
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
            assert!(config.sync_eth1_chain);
            assert_eq!(
                config.eth1.endpoint.get_endpoint().to_string(),
                DEFAULT_ETH1_ENDPOINT
            );
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
fn enable_lock_timeouts_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.enable_lock_timeouts));
}

#[test]
fn disable_lock_timeouts_flag() {
    CommandLineTest::new()
        .flag("disable-lock-timeouts", None)
        .run_with_zero_port()
        .with_config(|config| assert!(!config.chain.enable_lock_timeouts));
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
            assert_eq!(config.chain.checkpoint_sync_url_timeout, 60);
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
    CommandLineTest::new()
        .flag("always-prepare-payload", None)
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
fn count_unrealized_no_arg() {
    CommandLineTest::new()
        .flag("count-unrealized", None)
        // This flag should be ignored, so there's nothing to test but that the
        // client starts with the flag present.
        .run_with_zero_port();
}

#[test]
fn count_unrealized_false() {
    CommandLineTest::new()
        .flag("count-unrealized", Some("false"))
        // This flag should be ignored, so there's nothing to test but that the
        // client starts with the flag present.
        .run_with_zero_port();
}

#[test]
fn count_unrealized_true() {
    CommandLineTest::new()
        .flag("count-unrealized", Some("true"))
        // This flag should be ignored, so there's nothing to test but that the
        // client starts with the flag present.
        .run_with_zero_port();
}

#[test]
fn count_unrealized_full_no_arg() {
    CommandLineTest::new()
        .flag("count-unrealized-full", None)
        // This flag should be ignored, so there's nothing to test but that the
        // client starts with the flag present.
        .run_with_zero_port();
}

#[test]
fn count_unrealized_full_false() {
    CommandLineTest::new()
        .flag("count-unrealized-full", Some("false"))
        // This flag should be ignored, so there's nothing to test but that the
        // client starts with the flag present.
        .run_with_zero_port();
}

#[test]
fn count_unrealized_full_true() {
    CommandLineTest::new()
        .flag("count-unrealized-full", Some("true"))
        // This flag should be ignored, so there's nothing to test but that the
        // client starts with the flag present.
        .run_with_zero_port();
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
fn always_prefer_builder_payload_flag() {
    CommandLineTest::new()
        .flag("always-prefer-builder-payload", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.always_prefer_builder_payload));
}

#[test]
fn no_flag_sets_always_prefer_builder_payload_to_false() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(!config.always_prefer_builder_payload));
}

// Tests for Eth1 flags.
#[test]
fn dummy_eth1_flag() {
    CommandLineTest::new()
        .flag("dummy-eth1", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.dummy_eth1_backend));
}
#[test]
fn eth1_flag() {
    CommandLineTest::new()
        .flag("eth1", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.sync_eth1_chain));
}
#[test]
fn eth1_endpoints_flag() {
    CommandLineTest::new()
        .flag("eth1-endpoints", Some("http://localhost:9545"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.eth1.endpoint.get_endpoint().full.to_string(),
                "http://localhost:9545/"
            );
            assert_eq!(
                config.eth1.endpoint.get_endpoint().to_string(),
                "http://localhost:9545/"
            );
            assert!(config.sync_eth1_chain);
        });
}
#[test]
fn eth1_blocks_per_log_query_flag() {
    CommandLineTest::new()
        .flag("eth1-blocks-per-log-query", Some("500"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.eth1.blocks_per_log_query, 500));
}
#[test]
fn eth1_purge_cache_flag() {
    CommandLineTest::new()
        .flag("eth1-purge-cache", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.eth1.purge_cache));
}
#[test]
fn eth1_cache_follow_distance_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.eth1.cache_follow_distance, None);
            assert_eq!(config.eth1.cache_follow_distance(), 3 * 2048 / 4);
        });
}
#[test]
fn eth1_cache_follow_distance_manual() {
    CommandLineTest::new()
        .flag("eth1-cache-follow-distance", Some("128"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.eth1.cache_follow_distance, Some(128));
            assert_eq!(config.eth1.cache_follow_distance(), 128);
        });
}

// Tests for Bellatrix flags.
fn run_merge_execution_endpoints_flag_test(flag: &str) {
    use sensitive_url::SensitiveUrl;
    let urls = vec!["http://sigp.io/no-way:1337", "http://infura.not_real:4242"];
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
    CommandLineTest::new()
        .flag(flag, Some(&endpoint_arg))
        .flag("execution-jwt", Some(&jwts_arg))
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert_eq!(config.execution_endpoints.len(), 1);
            assert_eq!(
                config.execution_endpoints[0],
                SensitiveUrl::parse(&urls[0]).unwrap()
            );
            // Only the first secret file should be used.
            assert_eq!(config.secret_files, vec![jwts[0].clone()]);
        });
}
#[test]
fn run_execution_jwt_secret_key_is_persisted() {
    let jwt_secret_key = "0x3cbc11b0d8fa16f3344eacfd6ff6430b9d30734450e8adcf5400f88d327dcb33";
    CommandLineTest::new()
        .flag("execution-endpoint", Some("http://localhost:8551/"))
        .flag("execution-jwt-secret-key", Some(jwt_secret_key))
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert_eq!(
                config.execution_endpoints[0].full.to_string(),
                "http://localhost:8551/"
            );
            let mut file_jwt_secret_key = String::new();
            File::open(config.secret_files[0].clone())
                .expect("could not open jwt_secret_key file")
                .read_to_string(&mut file_jwt_secret_key)
                .expect("could not read from file");
            assert_eq!(file_jwt_secret_key, jwt_secret_key);
        });
}
#[test]
fn execution_timeout_multiplier_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
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
fn merge_execution_endpoints_flag() {
    run_merge_execution_endpoints_flag_test("execution-endpoints")
}
#[test]
fn merge_execution_endpoint_flag() {
    run_merge_execution_endpoints_flag_test("execution-endpoint")
}
fn run_execution_endpoints_overrides_eth1_endpoints_test(eth1_flag: &str, execution_flag: &str) {
    use sensitive_url::SensitiveUrl;

    let eth1_endpoint = "http://bad.bad";
    let execution_endpoint = "http://good.good";

    assert!(eth1_endpoint != execution_endpoint);

    let dir = TempDir::new().expect("Unable to create temporary directory");
    let jwt_path = dir.path().join("jwt-file");

    CommandLineTest::new()
        .flag(eth1_flag, Some(&eth1_endpoint))
        .flag(execution_flag, Some(&execution_endpoint))
        .flag("execution-jwt", jwt_path.as_os_str().to_str())
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.execution_layer.as_ref().unwrap().execution_endpoints,
                vec![SensitiveUrl::parse(execution_endpoint).unwrap()]
            );

            // The eth1 endpoint should have been set to the --execution-endpoint value in defiance
            // of --eth1-endpoints.
            assert_eq!(
                config.eth1.endpoint,
                Eth1Endpoint::Auth {
                    endpoint: SensitiveUrl::parse(execution_endpoint).unwrap(),
                    jwt_path: jwt_path.clone(),
                    jwt_id: None,
                    jwt_version: None,
                }
            );
        });
}
#[test]
fn execution_endpoints_overrides_eth1_endpoints() {
    run_execution_endpoints_overrides_eth1_endpoints_test("eth1-endpoints", "execution-endpoints");
}
#[test]
fn execution_endpoint_overrides_eth1_endpoint() {
    run_execution_endpoints_overrides_eth1_endpoints_test("eth1-endpoint", "execution-endpoint");
}
#[test]
fn merge_jwt_secrets_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    let mut file = File::create(dir.path().join("jwtsecrets")).expect("Unable to create file");
    file.write_all(b"0x3cbc11b0d8fa16f3344eacfd6ff6430b9d30734450e8adcf5400f88d327dcb33")
        .expect("Unable to write to file");
    CommandLineTest::new()
        .flag("execution-endpoints", Some("http://localhost:8551/"))
        .flag(
            "jwt-secrets",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .run_with_zero_port()
        .with_config(|config| {
            let config = config.execution_layer.as_ref().unwrap();
            assert_eq!(
                config.execution_endpoints[0].full.to_string(),
                "http://localhost:8551/"
            );
            assert_eq!(config.secret_files[0], dir.path().join("jwt-file"));
        });
}
#[test]
fn merge_fee_recipient_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
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
        assert_eq!(config.builder_url, all_builders.get(0).cloned());
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
    let mut test = CommandLineTest::new();
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
            assert_eq!(config.chain.builder_fallback_disable_checks, true);
        },
    );
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        Some("builder-profit-threshold"),
        Some("1000000000000000000000000"),
        |config| {
            assert_eq!(
                config
                    .execution_layer
                    .as_ref()
                    .unwrap()
                    .builder_profit_threshold,
                1000000000000000000000000
            );
        },
    );
    run_payload_builder_flag_test_with_config(
        "builder",
        "http://meow.cats",
        None,
        None,
        |config| {
            assert_eq!(
                config
                    .execution_layer
                    .as_ref()
                    .unwrap()
                    .builder_profit_threshold,
                0
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

fn run_jwt_optional_flags_test(jwt_flag: &str, jwt_id_flag: &str, jwt_version_flag: &str) {
    use sensitive_url::SensitiveUrl;

    let dir = TempDir::new().expect("Unable to create temporary directory");
    let execution_endpoint = "http://meow.cats";
    let jwt_file = "jwt-file";
    let id = "bn-1";
    let version = "Lighthouse-v2.1.3";
    CommandLineTest::new()
        .flag("execution-endpoint", Some(execution_endpoint.clone()))
        .flag(jwt_flag, dir.path().join(jwt_file).as_os_str().to_str())
        .flag(jwt_id_flag, Some(id))
        .flag(jwt_version_flag, Some(version))
        .run_with_zero_port()
        .with_config(|config| {
            let el_config = config.execution_layer.as_ref().unwrap();
            assert_eq!(el_config.jwt_id, Some(id.to_string()));
            assert_eq!(el_config.jwt_version, Some(version.to_string()));
            assert_eq!(
                config.eth1.endpoint,
                Eth1Endpoint::Auth {
                    endpoint: SensitiveUrl::parse(execution_endpoint).unwrap(),
                    jwt_path: dir.path().join(jwt_file),
                    jwt_id: Some(id.to_string()),
                    jwt_version: Some(version.to_string()),
                }
            );
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
#[test]
fn terminal_total_difficulty_override_flag() {
    use beacon_node::beacon_chain::types::Uint256;
    CommandLineTest::new()
        .flag("terminal-total-difficulty-override", Some("1337424242"))
        .run_with_zero_port()
        .with_spec::<MainnetEthSpec, _>(|spec| {
            assert_eq!(spec.terminal_total_difficulty, Uint256::from(1337424242))
        });
}
#[test]
fn terminal_block_hash_and_activation_epoch_override_flags() {
    CommandLineTest::new()
        .flag("terminal-block-hash-epoch-override", Some("1337"))
        .flag(
            "terminal-block-hash-override",
            Some("0x4242424242424242424242424242424242424242424242424242424242424242"),
        )
        .run_with_zero_port()
        .with_spec::<MainnetEthSpec, _>(|spec| {
            assert_eq!(
                spec.terminal_block_hash,
                ExecutionBlockHash::from_str(
                    "0x4242424242424242424242424242424242424242424242424242424242424242"
                )
                .unwrap()
            );
            assert_eq!(spec.terminal_block_hash_activation_epoch, 1337);
        });
}
#[test]
#[should_panic]
fn terminal_block_hash_missing_activation_epoch() {
    CommandLineTest::new()
        .flag(
            "terminal-block-hash-override",
            Some("0x4242424242424242424242424242424242424242424242424242424242424242"),
        )
        .run_with_zero_port();
}
#[test]
#[should_panic]
fn epoch_override_missing_terminal_block_hash() {
    CommandLineTest::new()
        .flag("terminal-block-hash-epoch-override", Some("1337"))
        .run_with_zero_port();
}
#[test]
fn safe_slots_to_import_optimistically_flag() {
    CommandLineTest::new()
        .flag("safe-slots-to-import-optimistically", Some("421337"))
        .run_with_zero_port()
        .with_spec::<MainnetEthSpec, _>(|spec| {
            assert_eq!(spec.safe_slots_to_import_optimistically, 421337)
        });
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
    let port = unused_tcp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("port", Some(port.to_string().as_str()))
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v4()
                    .map(|listen_addr| (listen_addr.udp_port, listen_addr.tcp_port)),
                Some((port, port))
            );
        });
}
#[test]
fn network_port_flag_over_ipv6() {
    let port = unused_tcp6_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("port", Some(port.to_string().as_str()))
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v6()
                    .map(|listen_addr| (listen_addr.udp_port, listen_addr.tcp_port)),
                Some((port, port))
            );
        });
}
#[test]
fn network_port_and_discovery_port_flags_over_ipv4() {
    let tcp4_port = unused_tcp4_port().expect("Unable to find unused port.");
    let udp4_port = unused_udp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("discovery-port", Some(udp4_port.to_string().as_str()))
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v4()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.udp_port)),
                Some((tcp4_port, udp4_port))
            );
        });
}
#[test]
fn network_port_and_discovery_port_flags_over_ipv6() {
    let tcp6_port = unused_tcp6_port().expect("Unable to find unused port.");
    let udp6_port = unused_udp6_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("port", Some(tcp6_port.to_string().as_str()))
        .flag("discovery-port", Some(udp6_port.to_string().as_str()))
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v6()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.udp_port)),
                Some((tcp6_port, udp6_port))
            );
        });
}
#[test]
fn network_port_and_discovery_port_flags_over_ipv4_and_ipv6() {
    let tcp4_port = unused_tcp4_port().expect("Unable to find unused port.");
    let udp4_port = unused_udp4_port().expect("Unable to find unused port.");
    let tcp6_port = unused_tcp6_port().expect("Unable to find unused port.");
    let udp6_port = unused_udp6_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("listen-address", Some("::1"))
        .flag("listen-address", Some("127.0.0.1"))
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("discovery-port", Some(udp4_port.to_string().as_str()))
        .flag("port6", Some(tcp6_port.to_string().as_str()))
        .flag("discovery-port6", Some(udp6_port.to_string().as_str()))
        .run()
        .with_config(|config| {
            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v4()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.udp_port)),
                Some((tcp4_port, udp4_port))
            );

            assert_eq!(
                config
                    .network
                    .listen_addrs()
                    .v6()
                    .map(|listen_addr| (listen_addr.tcp_port, listen_addr.udp_port)),
                Some((tcp6_port, udp6_port))
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
        .with_config(|config| assert!(!config.chain.enable_backfill_rate_limiting));
}
#[test]
fn default_backfill_rate_limiting_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert!(config.chain.enable_backfill_rate_limiting));
}
#[test]
fn default_boot_nodes() {
    let mainnet = vec![
    // Lighthouse Team (Sigma Prime)
    "enr:-Jq4QItoFUuug_n_qbYbU0OY04-np2wT8rUCauOOXNi0H3BWbDj-zbfZb7otA7jZ6flbBpx1LNZK2TDebZ9dEKx84LYBhGV0aDKQtTA_KgEAAAD__________4JpZIJ2NIJpcISsaa0ZiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMo",
    "enr:-Jq4QN_YBsUOqQsty1OGvYv48PMaiEt1AzGD1NkYQHaxZoTyVGqMYXg0K9c0LPNWC9pkXmggApp8nygYLsQwScwAgfgBhGV0aDKQtTA_KgEAAAD__________4JpZIJ2NIJpcISLosQxiXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMo",
    // EF Team
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
    // Teku team (Consensys)
    "enr:-KG4QOtcP9X1FbIMOe17QNMKqDxCpm14jcX5tiOE4_TyMrFqbmhPZHK_ZPG2Gxb1GE2xdtodOfx9-cgvNtxnRyHEmC0ghGV0aDKQ9aX9QgAAAAD__________4JpZIJ2NIJpcIQDE8KdiXNlY3AyNTZrMaEDhpehBDbZjM_L9ek699Y7vhUJ-eAdMyQW_Fil522Y0fODdGNwgiMog3VkcIIjKA",
    "enr:-KG4QDyytgmE4f7AnvW-ZaUOIi9i79qX4JwjRAiXBZCU65wOfBu-3Nb5I7b_Rmg3KCOcZM_C3y5pg7EBU5XGrcLTduQEhGV0aDKQ9aX9QgAAAAD__________4JpZIJ2NIJpcIQ2_DUbiXNlY3AyNTZrMaEDKnz_-ps3UUOfHWVYaskI5kWYO_vtYMGYCQRAR3gHDouDdGNwgiMog3VkcIIjKA",
    // Prysm team (Prysmatic Labs)
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",
    // Nimbus team
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
    "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM"
    ];

    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            // Lighthouse Team (Sigma Prime)
            assert_eq!(config.network.boot_nodes_enr[0].to_base64(), mainnet[0]);
            assert_eq!(config.network.boot_nodes_enr[1].to_base64(), mainnet[1]);
            // EF Team
            assert_eq!(config.network.boot_nodes_enr[2].to_base64(), mainnet[2]);
            assert_eq!(config.network.boot_nodes_enr[3].to_base64(), mainnet[3]);
            assert_eq!(config.network.boot_nodes_enr[4].to_base64(), mainnet[4]);
            assert_eq!(config.network.boot_nodes_enr[5].to_base64(), mainnet[5]);
            // Teku team (Consensys)
            assert_eq!(config.network.boot_nodes_enr[6].to_base64(), mainnet[6]);
            assert_eq!(config.network.boot_nodes_enr[7].to_base64(), mainnet[7]);
            // Prysm team (Prysmatic Labs)
            assert_eq!(config.network.boot_nodes_enr[8].to_base64(), mainnet[8]);
            assert_eq!(config.network.boot_nodes_enr[9].to_base64(), mainnet[9]);
            assert_eq!(config.network.boot_nodes_enr[10].to_base64(), mainnet[10]);
            // Nimbus team
            assert_eq!(config.network.boot_nodes_enr[11].to_base64(), mainnet[11]);
            assert_eq!(config.network.boot_nodes_enr[12].to_base64(), mainnet[12]);
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
        .with_config(|config| assert!(config.network.private));
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
    let port = unused_udp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.enr_udp4_port, Some(port)));
}
#[test]
fn enr_tcp_port_flag() {
    let port = unused_tcp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-tcp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.enr_tcp4_port, Some(port)));
}
#[test]
fn enr_udp6_port_flag() {
    let port = unused_udp6_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-udp6-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.enr_udp6_port, Some(port)));
}
#[test]
fn enr_tcp6_port_flag() {
    let port = unused_tcp6_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-tcp6-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.enr_tcp6_port, Some(port)));
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
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.udp_port,
                    listen_addr.tcp_port
                )),
                Some((addr, udp4_port, tcp4_port))
            );
            assert_eq!(config.network.enr_address, (Some(addr), None));
            assert_eq!(config.network.enr_udp4_port, Some(udp4_port));
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
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.udp_port,
                    listen_addr.tcp_port
                )),
                Some((addr, udp6_port, tcp6_port))
            );
            assert_eq!(config.network.enr_address, (None, Some(addr)));
            assert_eq!(config.network.enr_udp6_port, Some(udp6_port));
        });
}
#[test]
fn enr_match_flag_over_ipv4_and_ipv6() {
    const IPV6_ADDR: &str = "::1";
    let ipv6_addr = IPV6_ADDR.parse::<Ipv6Addr>().unwrap();
    let udp6_port = unused_udp6_port().expect("Unable to find unused port.");
    let tcp6_port = unused_tcp6_port().expect("Unable to find unused port.");
    const IPV4_ADDR: &str = "127.0.0.1";
    let ipv4_addr = IPV4_ADDR.parse::<Ipv4Addr>().unwrap();
    let udp4_port = unused_udp4_port().expect("Unable to find unused port.");
    let tcp4_port = unused_tcp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-match", None)
        .flag("listen-address", Some(IPV4_ADDR))
        .flag("discovery-port", Some(udp4_port.to_string().as_str()))
        .flag("port", Some(tcp4_port.to_string().as_str()))
        .flag("listen-address", Some(IPV6_ADDR))
        .flag("discovery-port6", Some(udp6_port.to_string().as_str()))
        .flag("port6", Some(tcp6_port.to_string().as_str()))
        .run()
        .with_config(|config| {
            assert_eq!(
                config.network.listen_addrs().v6().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.udp_port,
                    listen_addr.tcp_port
                )),
                Some((ipv6_addr, udp6_port, tcp6_port))
            );
            assert_eq!(
                config.network.listen_addrs().v4().map(|listen_addr| (
                    listen_addr.addr,
                    listen_addr.udp_port,
                    listen_addr.tcp_port
                )),
                Some((ipv4_addr, udp4_port, tcp4_port))
            );
            assert_eq!(
                config.network.enr_address,
                (Some(ipv4_addr), Some(ipv6_addr))
            );
            assert_eq!(config.network.enr_udp6_port, Some(udp6_port));
            assert_eq!(config.network.enr_udp4_port, Some(udp4_port));
        });
}
#[test]
fn enr_address_flag_with_ipv4() {
    let addr = "192.167.1.1".parse::<Ipv4Addr>().unwrap();
    let port = unused_udp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-address", Some("192.167.1.1"))
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.enr_address, (Some(addr), None));
            assert_eq!(config.network.enr_udp4_port, Some(port));
        });
}
#[test]
fn enr_address_flag_with_ipv6() {
    let addr = "192.167.1.1".parse::<Ipv4Addr>().unwrap();
    let port = unused_udp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-address", Some("192.167.1.1"))
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.network.enr_address, (Some(addr), None));
            assert_eq!(config.network.enr_udp4_port, Some(port));
        });
}
#[test]
fn enr_address_dns_flag() {
    let addr = Ipv4Addr::LOCALHOST;
    let ipv6addr = Ipv6Addr::LOCALHOST;
    let port = unused_udp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("enr-address", Some("localhost"))
        .flag("enr-udp-port", Some(port.to_string().as_str()))
        .run_with_zero_port()
        .with_config(|config| {
            assert!(
                config.network.enr_address.0 == Some(addr)
                    || config.network.enr_address.1 == Some(ipv6addr)
            );
            assert_eq!(config.network.enr_udp4_port, Some(port));
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
        .flag("http-address", Some("127.0.0.99"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
}
#[test]
fn http_address_ipv6_flag() {
    let addr = "::1".parse::<IpAddr>().unwrap();
    CommandLineTest::new()
        .flag("http-address", Some("::1"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.listen_addr, addr));
}
#[test]
fn http_port_flag() {
    let port1 = unused_tcp4_port().expect("Unable to find unused port.");
    let port2 = unused_tcp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("http-port", Some(port1.to_string().as_str()))
        .flag("port", Some(port2.to_string().as_str()))
        .run()
        .with_config(|config| assert_eq!(config.http_api.listen_port, port1));
}
#[test]
fn empty_self_limiter_flag() {
    // Test that empty rate limiter is accepted using the default rate limiting configurations.
    CommandLineTest::new()
        .flag("self-limiter", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.network.outbound_rate_limiter_config,
                Some(lighthouse_network::rpc::config::OutboundRateLimiterConfig::default())
            )
        });
}
#[test]
fn http_allow_origin_flag() {
    CommandLineTest::new()
        .flag("http-allow-origin", Some("127.0.0.99"))
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.http_api.allow_origin, Some("127.0.0.99".to_string()));
        });
}
#[test]
fn http_allow_origin_all_flag() {
    CommandLineTest::new()
        .flag("http-allow-origin", Some("*"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.allow_origin, Some("*".to_string())));
}
#[test]
fn http_allow_sync_stalled_flag() {
    CommandLineTest::new()
        .flag("http-allow-sync-stalled", None)
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.allow_sync_stalled, true));
}
#[test]
fn http_tls_flags() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("http-enable-tls", None)
        .flag(
            "http-tls-cert",
            dir.path().join("certificate.crt").as_os_str().to_str(),
        )
        .flag(
            "http-tls-key",
            dir.path().join("private.key").as_os_str().to_str(),
        )
        .run_with_zero_port()
        .with_config(|config| {
            let tls_config = config
                .http_api
                .tls_config
                .as_ref()
                .expect("tls_config was empty.");
            assert_eq!(tls_config.cert, dir.path().join("certificate.crt"));
            assert_eq!(tls_config.key, dir.path().join("private.key"));
        });
}

#[test]
fn http_spec_fork_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.spec_fork_name, None));
}

#[test]
fn http_spec_fork_override() {
    CommandLineTest::new()
        .flag("http-spec-fork", Some("altair"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.http_api.spec_fork_name, Some(ForkName::Altair)));
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
    let port1 = unused_tcp4_port().expect("Unable to find unused port.");
    let port2 = unused_tcp4_port().expect("Unable to find unused port.");
    CommandLineTest::new()
        .flag("metrics", None)
        .flag("metrics-port", Some(port1.to_string().as_str()))
        .flag("port", Some(port2.to_string().as_str()))
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
fn validator_monitor_auto_flag() {
    CommandLineTest::new()
        .flag("validator-monitor-auto", None)
        .run_with_zero_port()
        .with_config(|config| assert!(config.validator_monitor_auto));
}
#[test]
fn validator_monitor_pubkeys_flag() {
    CommandLineTest::new()
        .flag("validator-monitor-pubkeys", Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,\
                                                0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
        .run_with_zero_port()
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
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(config.validator_monitor_pubkeys[0].to_string(), "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
            assert_eq!(config.validator_monitor_pubkeys[1].to_string(), "0xbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        });
}
#[test]
fn validator_monitor_metrics_threshold_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert_eq!(
                config.validator_monitor_individual_tracking_threshold,
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
            assert_eq!(config.validator_monitor_individual_tracking_threshold, 42)
        });
}

// Tests for Store flags.
#[test]
fn slots_per_restore_point_flag() {
    CommandLineTest::new()
        .flag("slots-per-restore-point", Some("64"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.slots_per_restore_point, 64));
}
#[test]
fn slots_per_restore_point_update_prev_default() {
    use beacon_node::beacon_chain::store::config::{
        DEFAULT_SLOTS_PER_RESTORE_POINT, PREV_DEFAULT_SLOTS_PER_RESTORE_POINT,
    };

    CommandLineTest::new()
        .flag("slots-per-restore-point", Some("2048"))
        .run_with_zero_port()
        .with_config_and_dir(|config, dir| {
            // Check that 2048 is the previous default.
            assert_eq!(
                config.store.slots_per_restore_point,
                PREV_DEFAULT_SLOTS_PER_RESTORE_POINT
            );

            // Restart the BN with the same datadir and the new default SPRP. It should
            // allow this.
            CommandLineTest::new()
                .flag("datadir", Some(&dir.path().display().to_string()))
                .flag("zero-ports", None)
                .run_with_no_datadir()
                .with_config(|config| {
                    // The dumped config will have the new default 8192 value, but the fact that
                    // the BN started and ran (with the same datadir) means that the override
                    // was successful.
                    assert_eq!(
                        config.store.slots_per_restore_point,
                        DEFAULT_SLOTS_PER_RESTORE_POINT
                    );
                });
        })
}

#[test]
fn block_cache_size_flag() {
    CommandLineTest::new()
        .flag("block-cache-size", Some("4"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.store.block_cache_size, 4_usize));
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
        .with_config(|config| assert!(config.store.epochs_per_blob_prune == 1));
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

// Tests for Slasher flags.
#[test]
fn slasher_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
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
        .flag("slasher-slot-offset", Some("NaN"))
        .run_with_zero_port();
}
#[test]
fn slasher_history_length_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
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
        .flag("slasher-max-db-size", Some("10"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert_eq!(slasher_config.max_db_size_mbs, 10240);
        });
}
#[test]
fn slasher_attestation_cache_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-att-cache-size", Some("10000"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config
                .slasher
                .as_ref()
                .expect("Unable to parse Slasher config");
            assert_eq!(slasher_config.attestation_root_cache_size, 10000);
        });
}
#[test]
fn slasher_chunk_size_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
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
fn slasher_broadcast_flag() {
    CommandLineTest::new()
        .flag("slasher", None)
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
fn slasher_backend_default() {
    CommandLineTest::new()
        .flag("slasher", None)
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config.slasher.as_ref().unwrap();
            assert_eq!(slasher_config.backend, slasher::DatabaseBackend::Mdbx);
        });
}

#[test]
fn slasher_backend_override_to_default() {
    // Hard to test this flag because all but one backend is disabled by default and the backend
    // called "disabled" results in a panic.
    CommandLineTest::new()
        .flag("slasher", None)
        .flag("slasher-backend", Some("mdbx"))
        .run_with_zero_port()
        .with_config(|config| {
            let slasher_config = config.slasher.as_ref().unwrap();
            assert_eq!(slasher_config.backend, slasher::DatabaseBackend::Mdbx);
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
        .run_with_zero_port()
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
                config.chain.re_org_threshold,
                Some(DEFAULT_RE_ORG_THRESHOLD)
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
        .with_config(|config| assert_eq!(config.chain.re_org_threshold, None));
}

#[test]
fn proposer_re_org_threshold() {
    CommandLineTest::new()
        .flag("proposer-reorg-threshold", Some("90"))
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.chain.re_org_threshold.unwrap().0, 90));
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
        .flag("--proposer-reorg-disallowed-offsets", Some("1,2,3"))
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
        .flag("--proposer-reorg-disallowed-offsets", Some("32,33,34"))
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
fn default_log_color_flag() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| {
            assert!(!config.logger_config.log_color);
        });
}
#[test]
fn enabled_log_color_flag() {
    CommandLineTest::new()
        .flag("log-color", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.logger_config.log_color);
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
            assert!(config.logger_config.is_restricted == false);
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
fn sync_eth1_chain_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.sync_eth1_chain, false));
}

#[test]
fn sync_eth1_chain_execution_endpoints_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("execution-endpoints", Some("http://localhost:8551/"))
        .flag(
            "execution-jwt",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.sync_eth1_chain, true));
}

#[test]
fn sync_eth1_chain_disable_deposit_contract_sync_flag() {
    let dir = TempDir::new().expect("Unable to create temporary directory");
    CommandLineTest::new()
        .flag("disable-deposit-contract-sync", None)
        .flag("execution-endpoints", Some("http://localhost:8551/"))
        .flag(
            "execution-jwt",
            dir.path().join("jwt-file").as_os_str().to_str(),
        )
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.sync_eth1_chain, false));
}

#[test]
fn light_client_server_default() {
    CommandLineTest::new()
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.enable_light_client_server, false));
}

#[test]
fn light_client_server_enabled() {
    CommandLineTest::new()
        .flag("light-client-server", None)
        .run_with_zero_port()
        .with_config(|config| assert_eq!(config.network.enable_light_client_server, true));
}

#[test]
fn gui_flag() {
    CommandLineTest::new()
        .flag("gui", None)
        .run_with_zero_port()
        .with_config(|config| {
            assert!(config.http_api.enabled);
            assert!(config.validator_monitor_auto);
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
