use bls::{create_proof_of_possession, get_withdrawal_credentials};
use log::debug;
use rayon::prelude::*;
use types::*;

/// Generates `validator_count` deposits using randomly generated keypairs and some default specs
/// for the deposits.
pub fn generate_deposits_with_random_keypairs(
    validator_count: usize,
    genesis_time: u64,
    spec: &ChainSpec,
) -> (Vec<Keypair>, Vec<Deposit>) {
    debug!(
        "Generating {} random validator keypairs...",
        validator_count
    );

    let keypairs: Vec<Keypair> = (0..validator_count)
        .collect::<Vec<usize>>()
        .par_iter()
        .map(|_| Keypair::random())
        .collect();

    debug!(
        "Generating {} validator deposits from random keypairs...",
        validator_count
    );

    let initial_validator_deposits =
        keypairs
            .par_iter()
            .map(|keypair| Deposit {
                branch: vec![], // branch verification is not specified.
                index: 0,       // index verification is not specified.
                deposit_data: DepositData {
                    amount: 32_000_000_000, // 32 ETH (in Gwei)
                    timestamp: genesis_time - 1,
                    deposit_input: DepositInput {
                        pubkey: keypair.pk.clone(),
                        // Validator can withdraw using their main keypair.
                        withdrawal_credentials: Hash256::from_slice(
                            &get_withdrawal_credentials(
                                &keypair.pk,
                                spec.bls_withdrawal_prefix_byte,
                            )[..],
                        ),
                        proof_of_possession: create_proof_of_possession(&keypair),
                    },
                },
            })
            .collect();

    (keypairs, initial_validator_deposits)
}
