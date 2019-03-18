// Initialisation functions to generate a new BeaconChain.
// Note: A new version of ClientTypes may need to be implemented for the lighthouse
// testnet. These are examples. Also. there is code duplication which can/should be cleaned up.

use crate::BeaconChain;
use bls;
use db::stores::{BeaconBlockStore, BeaconStateStore};
use db::{DiskDB, MemoryDB};
use fork_choice::BitwiseLMDGhost;
use slot_clock::SystemTimeSlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use types::{ChainSpec, Deposit, DepositData, DepositInput, Eth1Data, Hash256, Keypair};

//TODO: Correct this for prod
//TODO: Account for historical db
pub fn initialise_beacon_chain(
    chain_spec: &ChainSpec,
    db_name: Option<&PathBuf>,
) -> Arc<BeaconChain<DiskDB, SystemTimeSlotClock, BitwiseLMDGhost<DiskDB>>> {
    // set up the db
    let db = Arc::new(DiskDB::open(
        db_name.expect("Database directory must be included"),
        None,
    ));
    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));

    // Slot clock
    let genesis_time = 1_549_935_547; // 12th Feb 2018 (arbitrary value in the past).
    let slot_clock = SystemTimeSlotClock::new(genesis_time, chain_spec.seconds_per_slot)
        .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());

    /*
     * Generate some random data to start a chain with.
     *
     * This is will need to be replace for production usage.
     */
    let latest_eth1_data = Eth1Data {
        deposit_root: Hash256::zero(),
        block_hash: Hash256::zero(),
    };
    let keypairs: Vec<Keypair> = (0..10)
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| Keypair::random())
        .collect();
    let initial_validator_deposits = keypairs
        .iter()
        .map(|keypair| Deposit {
            branch: vec![], // branch verification is not chain_specified.
            index: 0,       // index verification is not chain_specified.
            deposit_data: DepositData {
                amount: 32_000_000_000, // 32 ETH (in Gwei)
                timestamp: genesis_time - 1,
                deposit_input: DepositInput {
                    pubkey: keypair.pk.clone(),
                    withdrawal_credentials: Hash256::zero(), // Withdrawal not possible.
                    proof_of_possession: bls::create_proof_of_possession(&keypair),
                },
            },
        })
        .collect();

    // Genesis chain
    // TODO:Remove the expect here. Propagate errors and handle somewhat gracefully.
    Arc::new(
        BeaconChain::genesis(
            state_store.clone(),
            block_store.clone(),
            slot_clock,
            genesis_time,
            latest_eth1_data,
            initial_validator_deposits,
            chain_spec.clone(),
            fork_choice,
        )
        .expect("Cannot initialise a beacon chain. Exiting"),
    )
}

/// Initialisation of a test beacon chain, uses an in memory db with fixed genesis time.
pub fn initialise_test_beacon_chain(
    chain_spec: &ChainSpec,
    _db_name: Option<&PathBuf>,
) -> Arc<BeaconChain<MemoryDB, SystemTimeSlotClock, BitwiseLMDGhost<MemoryDB>>> {
    let db = Arc::new(MemoryDB::open());
    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));

    // Slot clock
    let genesis_time = 1_549_935_547; // 12th Feb 2018 (arbitrary value in the past).
    let slot_clock = SystemTimeSlotClock::new(genesis_time, chain_spec.seconds_per_slot)
        .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());

    /*
     * Generate some random data to start a chain with.
     *
     * This is will need to be replace for production usage.
     */
    let latest_eth1_data = Eth1Data {
        deposit_root: Hash256::zero(),
        block_hash: Hash256::zero(),
    };
    let keypairs: Vec<Keypair> = (0..8)
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| Keypair::random())
        .collect();
    let initial_validator_deposits = keypairs
        .iter()
        .map(|keypair| Deposit {
            branch: vec![], // branch verification is not chain_specified.
            index: 0,       // index verification is not chain_specified.
            deposit_data: DepositData {
                amount: 32_000_000_000, // 32 ETH (in Gwei)
                timestamp: genesis_time - 1,
                deposit_input: DepositInput {
                    pubkey: keypair.pk.clone(),
                    withdrawal_credentials: Hash256::zero(), // Withdrawal not possible.
                    proof_of_possession: bls::create_proof_of_possession(&keypair),
                },
            },
        })
        .collect();

    // Genesis chain
    // TODO: Handle error correctly
    Arc::new(
        BeaconChain::genesis(
            state_store.clone(),
            block_store.clone(),
            slot_clock,
            genesis_time,
            latest_eth1_data,
            initial_validator_deposits,
            chain_spec.clone(),
            fork_choice,
        )
        .expect("Cannot generate beacon chain"),
    )
}
