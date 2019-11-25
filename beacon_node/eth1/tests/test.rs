#![cfg(test)]
use environment::{Environment, EnvironmentBuilder};
use eth1::http::{get_deposit_count, get_deposit_logs_in_range, get_deposit_root, Block, Log};
use eth1::{Config, Service};
use eth1::{DepositCache, DepositLog};
use eth1_test_rig::GanacheEth1Instance;
use exit_future;
use futures::Future;
use merkle_proof::verify_merkle_proof;
use std::ops::Range;
use std::time::Duration;
use tokio::runtime::Runtime;
use tree_hash::TreeHash;
use types::{DepositData, EthSpec, Hash256, Keypair, MainnetEthSpec, MinimalEthSpec, Signature};
use web3::{transports::Http, Web3};

const DEPOSIT_CONTRACT_TREE_DEPTH: usize = 32;

pub fn new_env() -> Environment<MinimalEthSpec> {
    EnvironmentBuilder::minimal()
        // Use a single thread, so that when all tests are run in parallel they don't have so many
        // threads.
        .single_thread_tokio_runtime()
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
        signature: Signature::empty_signature().into(),
    };

    deposit.signature = deposit.create_signature(&keypair.sk, &MainnetEthSpec::default_spec());

    deposit
}

/// Blocking operation to get the deposit logs from the `deposit_contract`.
fn blocking_deposit_logs(
    runtime: &mut Runtime,
    eth1: &GanacheEth1Instance,
    range: Range<u64>,
) -> Vec<Log> {
    runtime
        .block_on(get_deposit_logs_in_range(
            &eth1.endpoint(),
            &eth1.deposit_contract.address(),
            range,
            timeout(),
        ))
        .expect("should get logs")
}

/// Blocking operation to get the deposit root from the `deposit_contract`.
fn blocking_deposit_root(
    runtime: &mut Runtime,
    eth1: &GanacheEth1Instance,
    block_number: u64,
) -> Option<Hash256> {
    runtime
        .block_on(get_deposit_root(
            &eth1.endpoint(),
            &eth1.deposit_contract.address(),
            block_number,
            timeout(),
        ))
        .expect("should get deposit root")
}

/// Blocking operation to get the deposit count from the `deposit_contract`.
fn blocking_deposit_count(
    runtime: &mut Runtime,
    eth1: &GanacheEth1Instance,
    block_number: u64,
) -> Option<u64> {
    runtime
        .block_on(get_deposit_count(
            &eth1.endpoint(),
            &eth1.deposit_contract.address(),
            block_number,
            timeout(),
        ))
        .expect("should get deposit count")
}

fn get_block_number(runtime: &mut Runtime, web3: &Web3<Http>) -> u64 {
    runtime
        .block_on(web3.eth().block_number().map(|v| v.as_u64()))
        .expect("should get block number")
}

mod auto_update {
    use super::*;

    #[test]
    fn can_auto_update() {
        let mut env = new_env();
        let log = env.core_context().log;
        let runtime = env.runtime();

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let now = get_block_number(runtime, &web3);

        let service = Service::new(
            Config {
                endpoint: eth1.endpoint(),
                deposit_contract_address: deposit_contract.address(),
                deposit_contract_deploy_block: now,
                lowest_cached_block_number: now,
                follow_distance: 0,
                block_cache_truncation: None,
                ..Config::default()
            },
            log,
        );

        // NOTE: this test is sensitive to the response speed of the external web3 server. If
        // you're experiencing failures, try increasing the update_interval.
        let update_interval = Duration::from_millis(2_000);

        assert_eq!(
            service.block_cache_len(),
            0,
            "should have imported no blocks"
        );
        assert_eq!(
            service.deposit_cache_len(),
            0,
            "should have imported no deposits"
        );

        let (_exit, signal) = exit_future::signal();

        runtime.executor().spawn(service.auto_update(signal));

        let n = 4;

        for _ in 0..n {
            deposit_contract
                .deposit(runtime, random_deposit_data())
                .expect("should do first deposits");
        }

        std::thread::sleep(update_interval * 5);

        assert!(
            service.deposit_cache_len() >= n,
            "should have imported n deposits"
        );

        for _ in 0..n {
            deposit_contract
                .deposit(runtime, random_deposit_data())
                .expect("should do second deposits");
        }

        std::thread::sleep(update_interval * 4);

        assert!(
            service.block_cache_len() >= n * 2,
            "should have imported all blocks"
        );
        assert!(
            service.deposit_cache_len() >= n * 2,
            "should have imported all deposits, not {}",
            service.deposit_cache_len()
        );
    }
}

mod eth1_cache {
    use super::*;

    #[test]
    fn simple_scenario() {
        let mut env = new_env();
        let log = env.core_context().log;
        let runtime = env.runtime();

        for follow_distance in 0..2 {
            let eth1 = runtime
                .block_on(GanacheEth1Instance::new())
                .expect("should start eth1 environment");
            let deposit_contract = &eth1.deposit_contract;
            let web3 = eth1.web3();

            let initial_block_number = get_block_number(runtime, &web3);

            let service = Service::new(
                Config {
                    endpoint: eth1.endpoint(),
                    deposit_contract_address: deposit_contract.address(),
                    lowest_cached_block_number: initial_block_number,
                    follow_distance,
                    ..Config::default()
                },
                log.clone(),
            );

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
                        .map(|n| n + follow_distance)
                        .expect("should have a latest block after the first round")
                };

                for _ in 0..blocks {
                    runtime
                        .block_on(eth1.ganache.evm_mine())
                        .expect("should mine block");
                }

                runtime
                    .block_on(service.update_block_cache())
                    .expect("should update cache");

                runtime
                    .block_on(service.update_block_cache())
                    .expect("should update cache when nothing has changed");

                assert_eq!(
                    service
                        .blocks()
                        .read()
                        .highest_block_number()
                        .map(|n| n + follow_distance),
                    Some(initial + blocks),
                    "should update {} blocks in round {} (follow {})",
                    blocks,
                    round,
                    follow_distance,
                );
            }
        }
    }

    /// Tests the case where we attempt to download more blocks than will fit in the cache.
    #[test]
    fn big_skip() {
        let mut env = new_env();
        let log = env.core_context().log;
        let runtime = env.runtime();

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let cache_len = 4;

        let service = Service::new(
            Config {
                endpoint: eth1.endpoint(),
                deposit_contract_address: deposit_contract.address(),
                lowest_cached_block_number: get_block_number(runtime, &web3),
                follow_distance: 0,
                block_cache_truncation: Some(cache_len),
                ..Config::default()
            },
            log,
        );

        let blocks = cache_len * 2;

        for _ in 0..blocks {
            runtime
                .block_on(eth1.ganache.evm_mine())
                .expect("should mine block")
        }

        runtime
            .block_on(service.update_block_cache())
            .expect("should update cache");

        assert_eq!(
            service.block_cache_len(),
            cache_len,
            "should not grow cache beyond target"
        );
    }

    /// Tests to ensure that the cache gets pruned when doing multiple downloads smaller than the
    /// cache size.
    #[test]
    fn pruning() {
        let mut env = new_env();
        let log = env.core_context().log;
        let runtime = env.runtime();

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let cache_len = 4;

        let service = Service::new(
            Config {
                endpoint: eth1.endpoint(),
                deposit_contract_address: deposit_contract.address(),
                lowest_cached_block_number: get_block_number(runtime, &web3),
                follow_distance: 0,
                block_cache_truncation: Some(cache_len),
                ..Config::default()
            },
            log,
        );

        for _ in 0..4 {
            for _ in 0..cache_len / 2 {
                runtime
                    .block_on(eth1.ganache.evm_mine())
                    .expect("should mine block")
            }
            runtime
                .block_on(service.update_block_cache())
                .expect("should update cache");
        }

        assert_eq!(
            service.block_cache_len(),
            cache_len,
            "should not grow cache beyond target"
        );
    }

    #[test]
    fn double_update() {
        let mut env = new_env();
        let log = env.core_context().log;
        let runtime = env.runtime();

        let n = 16;

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let service = Service::new(
            Config {
                endpoint: eth1.endpoint(),
                deposit_contract_address: deposit_contract.address(),
                lowest_cached_block_number: get_block_number(runtime, &web3),
                follow_distance: 0,
                ..Config::default()
            },
            log,
        );

        for _ in 0..n {
            runtime
                .block_on(eth1.ganache.evm_mine())
                .expect("should mine block")
        }

        runtime
            .block_on(
                service
                    .update_block_cache()
                    .join(service.update_block_cache()),
            )
            .expect("should perform two simultaneous updates");

        assert!(service.block_cache_len() >= n, "should grow the cache");
    }
}

mod deposit_tree {
    use super::*;

    #[test]
    fn updating() {
        let mut env = new_env();
        let log = env.core_context().log;
        let runtime = env.runtime();

        let n = 4;

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let start_block = get_block_number(runtime, &web3);

        let service = Service::new(
            Config {
                endpoint: eth1.endpoint(),
                deposit_contract_address: deposit_contract.address(),
                deposit_contract_deploy_block: start_block,
                follow_distance: 0,
                ..Config::default()
            },
            log,
        );

        for round in 0..3 {
            let deposits: Vec<_> = (0..n).into_iter().map(|_| random_deposit_data()).collect();

            for deposit in &deposits {
                deposit_contract
                    .deposit(runtime, deposit.clone())
                    .expect("should perform a deposit");
            }

            runtime
                .block_on(service.update_deposit_cache())
                .expect("should perform update");

            runtime
                .block_on(service.update_deposit_cache())
                .expect("should perform update when nothing has changed");

            let first = n * round;
            let last = n * (round + 1);

            let (_root, local_deposits) = service
                .deposits()
                .read()
                .cache
                .get_deposits(first..last, last, 32)
                .expect(&format!("should get deposits in round {}", round));

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

    #[test]
    fn double_update() {
        let mut env = new_env();
        let log = env.core_context().log;
        let runtime = env.runtime();

        let n = 8;

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let start_block = get_block_number(runtime, &web3);

        let service = Service::new(
            Config {
                endpoint: eth1.endpoint(),
                deposit_contract_address: deposit_contract.address(),
                deposit_contract_deploy_block: start_block,
                lowest_cached_block_number: start_block,
                follow_distance: 0,
                ..Config::default()
            },
            log,
        );

        let deposits: Vec<_> = (0..n).into_iter().map(|_| random_deposit_data()).collect();

        for deposit in &deposits {
            deposit_contract
                .deposit(runtime, deposit.clone())
                .expect("should perform a deposit");
        }

        runtime
            .block_on(
                service
                    .update_deposit_cache()
                    .join(service.update_deposit_cache()),
            )
            .expect("should perform two updates concurrently");

        assert_eq!(service.deposit_cache_len(), n);
    }

    #[test]
    fn cache_consistency() {
        let mut env = new_env();
        let runtime = env.runtime();

        let n = 8;

        let deposits: Vec<_> = (0..n).into_iter().map(|_| random_deposit_data()).collect();

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let mut deposit_roots = vec![];
        let mut deposit_counts = vec![];

        // Perform deposits to the smart contract, recording it's state along the way.
        for deposit in &deposits {
            deposit_contract
                .deposit(runtime, deposit.clone())
                .expect("should perform a deposit");
            let block_number = get_block_number(runtime, &web3);
            deposit_roots.push(
                blocking_deposit_root(runtime, &eth1, block_number)
                    .expect("should get root if contract exists"),
            );
            deposit_counts.push(
                blocking_deposit_count(runtime, &eth1, block_number)
                    .expect("should get count if contract exists"),
            );
        }

        let mut tree = DepositCache::default();

        // Pull all the deposit logs from the contract.
        let block_number = get_block_number(runtime, &web3);
        let logs: Vec<_> = blocking_deposit_logs(runtime, &eth1, 0..block_number)
            .iter()
            .map(|raw| DepositLog::from_log(raw).expect("should parse deposit log"))
            .inspect(|log| {
                tree.insert_log(log.clone())
                    .expect("should add consecutive logs")
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
                .get_deposits(0..i as u64, deposit_counts[i], DEPOSIT_CONTRACT_TREE_DEPTH)
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
                        Hash256::from_slice(&deposit.data.tree_hash_root()),
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
}

/// Tests for the base HTTP requests and response handlers.
mod http {
    use super::*;

    fn get_block(runtime: &mut Runtime, eth1: &GanacheEth1Instance, block_number: u64) -> Block {
        runtime
            .block_on(eth1::http::get_block(
                &eth1.endpoint(),
                block_number,
                timeout(),
            ))
            .expect("should get block number")
    }

    #[test]
    fn incrementing_deposits() {
        let mut env = new_env();
        let runtime = env.runtime();

        let eth1 = runtime
            .block_on(GanacheEth1Instance::new())
            .expect("should start eth1 environment");
        let deposit_contract = &eth1.deposit_contract;
        let web3 = eth1.web3();

        let block_number = get_block_number(runtime, &web3);
        let logs = blocking_deposit_logs(runtime, &eth1, 0..block_number);
        assert_eq!(logs.len(), 0);

        let mut old_root = blocking_deposit_root(runtime, &eth1, block_number);
        let mut old_block = get_block(runtime, &eth1, block_number);
        let mut old_block_number = block_number;

        assert_eq!(
            blocking_deposit_count(runtime, &eth1, block_number),
            Some(0),
            "should have deposit count zero"
        );

        for i in 1..=8 {
            runtime
                .block_on(eth1.ganache.increase_time(1))
                .expect("should be able to increase time on ganache");

            deposit_contract
                .deposit(runtime, random_deposit_data())
                .expect("should perform a deposit");

            // Check the logs.
            let block_number = get_block_number(runtime, &web3);
            let logs = blocking_deposit_logs(runtime, &eth1, 0..block_number);
            assert_eq!(logs.len(), i, "the number of logs should be as expected");

            // Check the deposit count.
            assert_eq!(
                blocking_deposit_count(runtime, &eth1, block_number),
                Some(i as u64),
                "should have a correct deposit count"
            );

            // Check the deposit root.
            let new_root = blocking_deposit_root(runtime, &eth1, block_number);
            assert_ne!(
                new_root, old_root,
                "deposit root should change with each deposit"
            );
            old_root = new_root;

            // Check the block hash.
            let new_block = get_block(runtime, &eth1, block_number);
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
}
