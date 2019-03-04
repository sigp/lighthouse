// Initialisation functions to generate a new BeaconChain.

pub fn initialise_test_chain(
    config: &ClientConfig,
) -> Arc<BeaconChain<MemoryDB, SystemTimeSlotClock, BitwiseLMDGhost>> {
    let spec = config.spec;
    // Slot clock
    let genesis_time = 1_549_935_547; // 12th Feb 2018 (arbitrary value in the past).
    let slot_clock = SystemTimeSlotClock::new(genesis_time, spec.slot_duration)
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
            branch: vec![], // branch verification is not specified.
            index: 0,       // index verification is not specified.
            deposit_data: DepositData {
                amount: 32_000_000_000, // 32 ETH (in Gwei)
                timestamp: genesis_time - 1,
                deposit_input: DepositInput {
                    pubkey: keypair.pk.clone(),
                    withdrawal_credentials: Hash256::zero(), // Withdrawal not possible.
                    proof_of_possession: create_proof_of_possession(&keypair),
                },
            },
        })
        .collect();

    // Genesis chain
    Arc::new(BeaconChain::genesis(
        state_store.clone(),
        block_store.clone(),
        slot_clock,
        genesis_time,
        latest_eth1_data,
        initial_validator_deposits,
        spec,
        fork_choice,
    ));
}
