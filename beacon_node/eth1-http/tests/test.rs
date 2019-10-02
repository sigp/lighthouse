#![cfg(test)]
//! NOTE: These tests will not pass unless ganache-cli is running on `ENDPOINT` (see below).
//!
//! You can start a suitable instance using the `ganache_test_node.sh` script in the `scripts`
//! dir in the root of the `lighthouse` repo.
use eth1_http::http::{
    get_block_hash, get_block_number, get_deposit_count, get_deposit_logs_in_range,
    get_deposit_root, Log,
};
use eth1_http::{DepositLog, DepositTree};
use eth1_test_rig::DepositContract;
use std::ops::Range;
use std::time::Duration;
use tokio::runtime::Runtime;
use types::{DepositData, Epoch, EthSpec, Fork, Hash256, Keypair, MainnetEthSpec, Signature};

const ENDPOINT: &str = "http://localhost:8545";
const DEPOSIT_CONTRACT_TREE_DEPTH: usize = 32;

fn runtime() -> Runtime {
    Runtime::new().expect("should create runtime")
}

fn timeout() -> Duration {
    Duration::from_secs(1)
}

fn random_deposit_data() -> DepositData {
    let keypair = Keypair::random();

    let mut deposit = DepositData {
        pubkey: keypair.pk.into(),
        withdrawal_credentials: Hash256::zero(),
        amount: 32_000_000_000,
        signature: Signature::empty_signature().into(),
    };

    deposit.signature = deposit.create_signature(
        &keypair.sk,
        Epoch::new(0),
        &Fork::default(),
        &MainnetEthSpec::default_spec(),
    );

    deposit
}

/// Blocking operation to get the block number from `ENDPOINT`.
fn blocking_block_number() -> u64 {
    runtime()
        .block_on(get_block_number(ENDPOINT, timeout()))
        .expect("should get block number")
}

/// Blocking operation to get the deposit logs from the `deposit_contract`.
fn blocking_deposit_logs(deposit_contract: &DepositContract, range: Range<u64>) -> Vec<Log> {
    runtime()
        .block_on(get_deposit_logs_in_range(
            ENDPOINT,
            &deposit_contract.address(),
            range,
            timeout(),
        ))
        .expect("should get logs")
}

/// Blocking operation to get the deposit root from the `deposit_contract`.
fn blocking_deposit_root(deposit_contract: &DepositContract, block_number: u64) -> Hash256 {
    runtime()
        .block_on(get_deposit_root(
            ENDPOINT,
            &deposit_contract.address(),
            block_number,
            timeout(),
        ))
        .expect("should get deposit root")
}

/// Blocking operation to get the deposit count from the `deposit_contract`.
fn blocking_deposit_count(deposit_contract: &DepositContract, block_number: u64) -> u64 {
    runtime()
        .block_on(get_deposit_count(
            ENDPOINT,
            &deposit_contract.address(),
            block_number,
            timeout(),
        ))
        .expect("should get deposit count")
}

mod deposit_tree {
    use super::*;

    #[test]
    fn consistency() {
        let n = 8;

        let deposits: Vec<_> = (0..n).into_iter().map(|_| random_deposit_data()).collect();

        let deposit_contract =
            DepositContract::deploy(ENDPOINT).expect("should deploy deposit contract");

        let mut deposit_roots = vec![];
        let mut deposit_counts = vec![];
        let mut block_numbers = vec![];

        for deposit in &deposits {
            deposit_contract
                .deposit(deposit.clone())
                .expect("should perform a deposit");
            let block_number = blocking_block_number();
            block_numbers.push(block_number);
            deposit_roots.push(blocking_deposit_root(&deposit_contract, block_number));
            deposit_counts.push(blocking_deposit_count(&deposit_contract, block_number));
        }

        let mut tree = DepositTree::new();

        let block_number = blocking_block_number();
        let logs: Vec<_> = blocking_deposit_logs(&deposit_contract, 0..block_number)
            .iter()
            .map(|raw| DepositLog::from_log(raw).expect("should parse deposit log"))
            .inspect(|log| {
                tree.insert_log(log.clone())
                    .expect("should add consecutive logs")
            })
            .collect();

        for i in 0..logs.len() {
            let log = &logs[i];
            assert_eq!(
                log.deposit_data, deposits[i],
                "log {} should have correct deposit data",
                i
            );
            assert_eq!(log.index, i as u64, "log {} should have correct index", i);
            assert_eq!(
                log.block_number, block_numbers[i],
                "log {} should have correct block number",
                i
            );
        }

        for i in 0..n {
            assert_eq!(
                deposit_counts[i],
                i as u64 + 1,
                "deposit count should be accurate"
            );
            let (root, _) = tree
                .get_deposits(0..0, deposit_counts[i], DEPOSIT_CONTRACT_TREE_DEPTH)
                .expect("should get deposits");
            assert_eq!(
                root, deposit_roots[i],
                "tree deposit root {} should match the contract",
                i
            );
        }
    }
}

/// Tests for the base HTTP requests and response handlers.
mod http {
    use super::*;

    fn blocking_block_hash(block_number: u64) -> Hash256 {
        runtime()
            .block_on(get_block_hash(ENDPOINT, block_number, timeout()))
            .expect("should get block number")
    }

    #[test]
    fn incrementing_deposits() {
        let deposit_contract =
            DepositContract::deploy(ENDPOINT).expect("should deploy deposit contract");

        let block_number = blocking_block_number();
        let logs = blocking_deposit_logs(&deposit_contract, 0..block_number);
        assert_eq!(logs.len(), 0);

        let mut old_root = blocking_deposit_root(&deposit_contract, block_number);
        let mut old_block_hash = blocking_block_hash(block_number);
        let mut old_block_number = block_number;

        assert_eq!(
            blocking_deposit_count(&deposit_contract, block_number),
            0,
            "should have deposit count zero"
        );

        for i in 1..=8 {
            deposit_contract
                .deposit(random_deposit_data())
                .expect("should perform a deposit");

            // Check the logs.
            let block_number = blocking_block_number();
            let logs = blocking_deposit_logs(&deposit_contract, 0..block_number);
            assert_eq!(logs.len(), i, "the number of logs should be as expected");

            // Check the deposit count.
            assert_eq!(
                blocking_deposit_count(&deposit_contract, block_number),
                i as u64,
                "should have a correct deposit count"
            );

            // Check the deposit root.
            let new_root = blocking_deposit_root(&deposit_contract, block_number);
            assert_ne!(
                new_root, old_root,
                "deposit root should change with each deposit"
            );
            old_root = new_root;

            // Check the block hash.
            let new_block_hash = blocking_block_hash(block_number);
            assert_ne!(
                new_block_hash, old_block_hash,
                "block hash should change with each deposit"
            );
            old_block_hash = new_block_hash;

            // Check the block number.
            assert!(
                block_number > old_block_number,
                "block number should increase"
            );
            old_block_number = block_number;

            assert_ne!(
                new_root, new_block_hash,
                "the deposit root should be different to the block hash"
            )
        }
    }
}
