#![cfg(test)]
use environment::{Environment, EnvironmentBuilder};
use eth1::{Config, Eth1Endpoint, Service};
use eth1::{DepositCache, DEFAULT_CHAIN_ID};
use eth1_test_rig::{AnvilEth1Instance, Http, Middleware, Provider};
use execution_layer::http::{deposit_methods::*, HttpJsonRpc, Log};
use merkle_proof::verify_merkle_proof;
use sensitive_url::SensitiveUrl;
use slog::Logger;
use sloggers::{null::NullLoggerBuilder, Build};
use std::ops::Range;
use std::time::Duration;
use tree_hash::TreeHash;
use types::{DepositData, EthSpec, Hash256, Keypair, MainnetEthSpec, MinimalEthSpec, Signature};

const DEPOSIT_CONTRACT_TREE_DEPTH: usize = 32;

pub fn null_logger() -> Logger {
    let log_builder = NullLoggerBuilder;
    log_builder.build().expect("should build logger")
}

pub fn new_env() -> Environment<MinimalEthSpec> {
    EnvironmentBuilder::minimal()
        .multi_threaded_tokio_runtime()
        .expect("should start tokio runtime")
        .null_logger()
        .expect("should start null logger")
        .build()
        .expect("should build env")
}

fn timeout() -> Duration {
    Duration::from_secs(2)
}

fn random_deposit_data() -> DepositData {
    let keypair = Keypair::random();

    let mut deposit = DepositData {
        pubkey: keypair.pk.into(),
        withdrawal_credentials: Hash256::zero(),
        amount: 32_000_000_000,
        signature: Signature::empty().into(),
    };

    deposit.signature = deposit.create_signature(&keypair.sk, &MainnetEthSpec::default_spec());

    deposit
}

/// Blocking operation to get the deposit logs from the `deposit_contract`.
async fn blocking_deposit_logs(
    client: &HttpJsonRpc,
    eth1: &AnvilEth1Instance,
    range: Range<u64>,
) -> Vec<Log> {
    client
        .get_deposit_logs_in_range(&eth1.deposit_contract.address(), range, timeout())
        .await
        .expect("should get logs")
}

/// Blocking operation to get the deposit root from the `deposit_contract`.
async fn blocking_deposit_root(
    client: &HttpJsonRpc,
    eth1: &AnvilEth1Instance,
    block_number: u64,
) -> Option<Hash256> {
    client
        .get_deposit_root(&eth1.deposit_contract.address(), block_number, timeout())
        .await
        .expect("should get deposit root")
}

/// Blocking operation to get the deposit count from the `deposit_contract`.
async fn blocking_deposit_count(
    client: &HttpJsonRpc,
    eth1: &AnvilEth1Instance,
    block_number: u64,
) -> Option<u64> {
    client
        .get_deposit_count(&eth1.deposit_contract.address(), block_number, timeout())
        .await
        .expect("should get deposit count")
}

async fn get_block_number(client: &Provider<Http>) -> u64 {
    client
        .get_block_number()
        .await
        .map(|v| v.as_u64())
        .expect("should get block number")
}

async fn new_anvil_instance() -> Result<AnvilEth1Instance, String> {
    AnvilEth1Instance::new(DEFAULT_CHAIN_ID.into()).await
}

mod eth1_cache {
    use super::*;
    use types::{EthSpec, MainnetEthSpec};

    #[tokio::test]
    async fn simple_scenario() {
        async {
            let log = null_logger();

            for follow_distance in 0..3 {
                let eth1 = new_anvil_instance()
                    .await
                    .expect("should start eth1 environment");
                let deposit_contract = &eth1.deposit_contract;
                let anvil_client = eth1.json_rpc_client();

                let initial_block_number = get_block_number(&anvil_client).await;

                let config = Config {
                    endpoint: Eth1Endpoint::NoAuth(
                        SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                    ),
                    deposit_contract_address: deposit_contract.address(),
                    lowest_cached_block_number: initial_block_number,
                    follow_distance,
                    ..Config::default()
                };
                let cache_follow_distance = config.cache_follow_distance();

                let service =
                    Service::new(config, log.clone(), MainnetEthSpec::default_spec()).unwrap();

                // Create some blocks and then consume them, performing the test `rounds` times.
                for round in 0..2 {
                    let blocks = 4;

                    let initial = if round == 0 {
                        initial_block_number
                    } else {
                        service
                            .blocks()
                            .read()
                            .highest_block_number()
                            .map(|n| n + cache_follow_distance)
                            .expect("should have a latest block after the first round")
                    };

                    for _ in 0..blocks {
                        eth1.anvil.evm_mine().await.expect("should mine block");
                    }

                    service
                        .update_deposit_cache(None)
                        .await
                        .expect("should update deposit cache");
                    service
                        .update_block_cache(None)
                        .await
                        .expect("should update block cache");

                    service
                        .update_block_cache(None)
                        .await
                        .expect("should update cache when nothing has changed");

                    assert_eq!(
                        service
                            .blocks()
                            .read()
                            .highest_block_number()
                            .map(|n| n + cache_follow_distance),
                        Some(initial + blocks),
                        "should update {} blocks in round {} (follow {} i.e. {})",
                        blocks,
                        round,
                        follow_distance,
                        cache_follow_distance
                    );
                }
            }
        }
        .await;
    }

    /// Tests the case where we attempt to download more blocks than will fit in the cache.

    #[tokio::test]
    async fn big_skip() {
        async {
            let log = null_logger();

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let cache_len = 4;

            let service = Service::new(
                Config {
                    endpoint: Eth1Endpoint::NoAuth(
                        SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                    ),
                    deposit_contract_address: deposit_contract.address(),
                    lowest_cached_block_number: get_block_number(&anvil_client).await,
                    follow_distance: 0,
                    block_cache_truncation: Some(cache_len),
                    ..Config::default()
                },
                log,
                MainnetEthSpec::default_spec(),
            )
            .unwrap();

            let blocks = cache_len * 2;

            for _ in 0..blocks {
                eth1.anvil.evm_mine().await.expect("should mine block")
            }

            service
                .update_deposit_cache(None)
                .await
                .expect("should update deposit cache");
            service
                .update_block_cache(None)
                .await
                .expect("should update block cache");

            assert_eq!(
                service.block_cache_len(),
                cache_len,
                "should not grow cache beyond target"
            );
        }
        .await;
    }

    /// Tests to ensure that the cache gets pruned when doing multiple downloads smaller than the
    /// cache size.
    #[tokio::test]
    async fn pruning() {
        async {
            let log = null_logger();

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let cache_len = 4;

            let service = Service::new(
                Config {
                    endpoint: Eth1Endpoint::NoAuth(
                        SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                    ),
                    deposit_contract_address: deposit_contract.address(),
                    lowest_cached_block_number: get_block_number(&anvil_client).await,
                    follow_distance: 0,
                    block_cache_truncation: Some(cache_len),
                    ..Config::default()
                },
                log,
                MainnetEthSpec::default_spec(),
            )
            .unwrap();

            for _ in 0..4u8 {
                for _ in 0..cache_len / 2 {
                    eth1.anvil.evm_mine().await.expect("should mine block")
                }
                service
                    .update_deposit_cache(None)
                    .await
                    .expect("should update deposit cache");
                service
                    .update_block_cache(None)
                    .await
                    .expect("should update block cache");
            }

            assert_eq!(
                service.block_cache_len(),
                cache_len,
                "should not grow cache beyond target"
            );
        }
        .await;
    }

    #[tokio::test]
    async fn double_update() {
        async {
            let log = null_logger();

            let n = 16;

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let service = Service::new(
                Config {
                    endpoint: Eth1Endpoint::NoAuth(
                        SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                    ),
                    deposit_contract_address: deposit_contract.address(),
                    lowest_cached_block_number: get_block_number(&anvil_client).await,
                    follow_distance: 0,
                    ..Config::default()
                },
                log,
                MainnetEthSpec::default_spec(),
            )
            .unwrap();

            for _ in 0..n {
                eth1.anvil.evm_mine().await.expect("should mine block")
            }

            futures::try_join!(
                service.update_deposit_cache(None),
                service.update_deposit_cache(None)
            )
            .expect("should perform two simultaneous updates of deposit cache");
            futures::try_join!(
                service.update_block_cache(None),
                service.update_block_cache(None)
            )
            .expect("should perform two simultaneous updates of block cache");

            assert!(service.block_cache_len() >= n, "should grow the cache");
        }
        .await;
    }
}

mod deposit_tree {

    use super::*;

    #[tokio::test]
    async fn updating() {
        async {
            let log = null_logger();

            let n = 4;

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let start_block = get_block_number(&anvil_client).await;

            let service = Service::new(
                Config {
                    endpoint: Eth1Endpoint::NoAuth(
                        SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                    ),
                    deposit_contract_address: deposit_contract.address(),
                    deposit_contract_deploy_block: start_block,
                    follow_distance: 0,
                    ..Config::default()
                },
                log,
                MainnetEthSpec::default_spec(),
            )
            .unwrap();

            for round in 0..3 {
                let deposits: Vec<_> = (0..n).map(|_| random_deposit_data()).collect();

                for deposit in &deposits {
                    deposit_contract
                        .deposit(deposit.clone())
                        .await
                        .expect("should perform a deposit");
                }

                service
                    .update_deposit_cache(None)
                    .await
                    .expect("should perform update");

                service
                    .update_deposit_cache(None)
                    .await
                    .expect("should perform update when nothing has changed");

                let first = n * round;
                let last = n * (round + 1);

                let (_root, local_deposits) = service
                    .deposits()
                    .read()
                    .cache
                    .get_deposits(first, last, last)
                    .unwrap_or_else(|_| panic!("should get deposits in round {}", round));

                assert_eq!(
                    local_deposits.len(),
                    n as usize,
                    "should get the right number of deposits in round {}",
                    round
                );

                assert_eq!(
                    local_deposits
                        .iter()
                        .map(|d| d.data.clone())
                        .collect::<Vec<_>>(),
                    deposits.to_vec(),
                    "obtained deposits should match those submitted in round {}",
                    round
                );
            }
        }
        .await;
    }

    #[tokio::test]
    async fn double_update() {
        async {
            let log = null_logger();

            let n = 8;

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let start_block = get_block_number(&anvil_client).await;

            let service = Service::new(
                Config {
                    endpoint: Eth1Endpoint::NoAuth(
                        SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                    ),
                    deposit_contract_address: deposit_contract.address(),
                    deposit_contract_deploy_block: start_block,
                    lowest_cached_block_number: start_block,
                    follow_distance: 0,
                    ..Config::default()
                },
                log,
                MainnetEthSpec::default_spec(),
            )
            .unwrap();

            let deposits: Vec<_> = (0..n).map(|_| random_deposit_data()).collect();

            for deposit in &deposits {
                deposit_contract
                    .deposit(deposit.clone())
                    .await
                    .expect("should perform a deposit");
            }

            futures::try_join!(
                service.update_deposit_cache(None),
                service.update_deposit_cache(None)
            )
            .expect("should perform two updates concurrently");

            assert_eq!(service.deposit_cache_len(), n);
        }
        .await;
    }

    #[tokio::test]
    async fn cache_consistency() {
        async {
            let n = 8;

            let spec = &MainnetEthSpec::default_spec();

            let deposits: Vec<_> = (0..n).map(|_| random_deposit_data()).collect();

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");

            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let mut deposit_roots = vec![];
            let mut deposit_counts = vec![];

            let client =
                HttpJsonRpc::new(SensitiveUrl::parse(&eth1.endpoint()).unwrap(), None).unwrap();

            // Perform deposits to the smart contract, recording it's state along the way.
            for deposit in &deposits {
                deposit_contract
                    .deposit(deposit.clone())
                    .await
                    .expect("should perform a deposit");
                let block_number = get_block_number(&anvil_client).await;
                deposit_roots.push(
                    blocking_deposit_root(&client, &eth1, block_number)
                        .await
                        .expect("should get root if contract exists"),
                );
                deposit_counts.push(
                    blocking_deposit_count(&client, &eth1, block_number)
                        .await
                        .expect("should get count if contract exists"),
                );
            }

            let mut tree = DepositCache::default();

            // Pull all the deposit logs from the contract.
            let block_number = get_block_number(&anvil_client).await;
            let logs: Vec<_> = blocking_deposit_logs(&client, &eth1, 0..block_number)
                .await
                .iter()
                .map(|raw| raw.to_deposit_log(spec).expect("should parse deposit log"))
                .inspect(|log| {
                    tree.insert_log(log.clone())
                        .expect("should add consecutive logs");
                })
                .collect();

            // Check the logs for invariants.
            for i in 0..logs.len() {
                let log = &logs[i];
                assert_eq!(
                    log.deposit_data, deposits[i],
                    "log {} should have correct deposit data",
                    i
                );
                assert_eq!(log.index, i as u64, "log {} should have correct index", i);
            }

            // For each deposit test some more invariants
            for i in 0..n {
                // Ensure the deposit count from the smart contract was as expected.
                assert_eq!(
                    deposit_counts[i],
                    i as u64 + 1,
                    "deposit count should be accurate"
                );

                // Ensure that the root from the deposit tree matches what the contract reported.
                let (root, deposits) = tree
                    .get_deposits(0, i as u64, deposit_counts[i])
                    .expect("should get deposits");
                assert_eq!(
                    root, deposit_roots[i],
                    "tree deposit root {} should match the contract",
                    i
                );

                // Ensure that the deposits all prove into the root from the smart contract.
                let deposit_root = deposit_roots[i];
                for (j, deposit) in deposits.iter().enumerate() {
                    assert!(
                        verify_merkle_proof(
                            deposit.data.tree_hash_root(),
                            &deposit.proof,
                            DEPOSIT_CONTRACT_TREE_DEPTH + 1,
                            j,
                            deposit_root
                        ),
                        "deposit merkle proof should prove into deposit contract root"
                    )
                }
            }
        }
        .await;
    }
}

/// Tests for the base HTTP requests and response handlers.
mod http {
    use super::*;

    async fn get_block(client: &HttpJsonRpc, block_number: u64) -> Block {
        client
            .get_block(BlockQuery::Number(block_number), timeout())
            .await
            .expect("should get block number")
    }

    #[tokio::test]
    async fn incrementing_deposits() {
        async {
            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();
            let client =
                HttpJsonRpc::new(SensitiveUrl::parse(&eth1.endpoint()).unwrap(), None).unwrap();

            let block_number = get_block_number(&anvil_client).await;
            let logs = blocking_deposit_logs(&client, &eth1, 0..block_number).await;
            assert_eq!(logs.len(), 0);

            let mut old_root = blocking_deposit_root(&client, &eth1, block_number).await;
            let mut old_block = get_block(&client, block_number).await;
            let mut old_block_number = block_number;

            assert_eq!(
                blocking_deposit_count(&client, &eth1, block_number).await,
                Some(0),
                "should have deposit count zero"
            );

            for i in 1..=8 {
                eth1.anvil
                    .increase_time(1)
                    .await
                    .expect("should be able to increase time on anvil");

                deposit_contract
                    .deposit(random_deposit_data())
                    .await
                    .expect("should perform a deposit");

                // Check the logs.
                let block_number = get_block_number(&anvil_client).await;
                let logs = blocking_deposit_logs(&client, &eth1, 0..block_number).await;
                assert_eq!(logs.len(), i, "the number of logs should be as expected");

                // Check the deposit count.
                assert_eq!(
                    blocking_deposit_count(&client, &eth1, block_number).await,
                    Some(i as u64),
                    "should have a correct deposit count"
                );

                // Check the deposit root.
                let new_root = blocking_deposit_root(&client, &eth1, block_number).await;
                assert_ne!(
                    new_root, old_root,
                    "deposit root should change with each deposit"
                );
                old_root = new_root;

                // Check the block hash.
                let new_block = get_block(&client, block_number).await;
                assert_ne!(
                    new_block.hash, old_block.hash,
                    "block hash should change with each deposit"
                );

                // Check to ensure the timestamp is increasing
                assert!(
                    old_block.timestamp <= new_block.timestamp,
                    "block timestamp should increase"
                );

                old_block = new_block.clone();

                // Check the block number.
                assert!(
                    block_number > old_block_number,
                    "block number should increase"
                );
                old_block_number = block_number;

                // Check to ensure the block root is changing
                assert_ne!(
                    new_root,
                    Some(new_block.hash),
                    "the deposit root should be different to the block hash"
                );
            }
        }
        .await;
    }
}

mod fast {
    use super::*;

    // Adds deposits into deposit cache and matches deposit_count and deposit_root
    // with the deposit count and root computed from the deposit cache.
    #[tokio::test]
    async fn deposit_cache_query() {
        async {
            let log = null_logger();

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let now = get_block_number(&anvil_client).await;
            let spec = MainnetEthSpec::default_spec();
            let service = Service::new(
                Config {
                    endpoint: Eth1Endpoint::NoAuth(
                        SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                    ),
                    deposit_contract_address: deposit_contract.address(),
                    deposit_contract_deploy_block: now,
                    lowest_cached_block_number: now,
                    follow_distance: 0,
                    block_cache_truncation: None,
                    ..Config::default()
                },
                log,
                spec.clone(),
            )
            .unwrap();
            let client =
                HttpJsonRpc::new(SensitiveUrl::parse(&eth1.endpoint()).unwrap(), None).unwrap();
            let n = 10;
            let deposits: Vec<_> = (0..n).map(|_| random_deposit_data()).collect();
            for deposit in &deposits {
                deposit_contract
                    .deposit(deposit.clone())
                    .await
                    .expect("should perform a deposit");
                // Mine an extra block between deposits to test for corner cases
                eth1.anvil.evm_mine().await.expect("should mine block");
            }

            service
                .update_deposit_cache(None)
                .await
                .expect("should perform update");

            assert!(
                service.deposit_cache_len() >= n,
                "should have imported n deposits"
            );

            for block_num in 0..=get_block_number(&anvil_client).await {
                let expected_deposit_count =
                    blocking_deposit_count(&client, &eth1, block_num).await;
                let expected_deposit_root = blocking_deposit_root(&client, &eth1, block_num).await;

                let deposit_count = service
                    .deposits()
                    .read()
                    .cache
                    .get_deposit_count_from_cache(block_num);
                let deposit_root = service
                    .deposits()
                    .read()
                    .cache
                    .get_deposit_root_from_cache(block_num);
                assert_eq!(
                    expected_deposit_count, deposit_count,
                    "deposit count from cache should match queried"
                );
                assert_eq!(
                    expected_deposit_root, deposit_root,
                    "deposit root from cache should match queried"
                );
            }
        }
        .await;
    }
}

mod persist {
    use super::*;
    #[tokio::test]
    async fn test_persist_caches() {
        async {
            let log = null_logger();

            let eth1 = new_anvil_instance()
                .await
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let anvil_client = eth1.json_rpc_client();

            let now = get_block_number(&anvil_client).await;
            let config = Config {
                endpoint: Eth1Endpoint::NoAuth(
                    SensitiveUrl::parse(eth1.endpoint().as_str()).unwrap(),
                ),
                deposit_contract_address: deposit_contract.address(),
                deposit_contract_deploy_block: now,
                lowest_cached_block_number: now,
                follow_distance: 0,
                block_cache_truncation: None,
                ..Config::default()
            };
            let service =
                Service::new(config.clone(), log.clone(), MainnetEthSpec::default_spec()).unwrap();
            let n = 10;
            let deposits: Vec<_> = (0..n).map(|_| random_deposit_data()).collect();
            for deposit in &deposits {
                deposit_contract
                    .deposit(deposit.clone())
                    .await
                    .expect("should perform a deposit");
            }

            service
                .update_deposit_cache(None)
                .await
                .expect("should perform update");

            assert!(
                service.deposit_cache_len() >= n,
                "should have imported n deposits"
            );

            let deposit_count = service.deposit_cache_len();

            service
                .update_block_cache(None)
                .await
                .expect("should perform update");

            assert!(
                service.block_cache_len() >= n,
                "should have imported n eth1 blocks"
            );

            let block_count = service.block_cache_len();

            let eth1_bytes = service.as_bytes();

            // Drop service and recover from bytes
            drop(service);

            let recovered_service =
                Service::from_bytes(&eth1_bytes, config, log, MainnetEthSpec::default_spec())
                    .unwrap();
            assert_eq!(
                recovered_service.block_cache_len(),
                block_count,
                "Should have equal cached blocks as before recovery"
            );
            assert_eq!(
                recovered_service.deposit_cache_len(),
                deposit_count,
                "Should have equal cached deposits as before recovery"
            );
        }
        .await;
    }
}
