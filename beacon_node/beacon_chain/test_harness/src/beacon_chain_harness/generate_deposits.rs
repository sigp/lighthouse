use bls::get_withdrawal_credentials;
use log::debug;
use rayon::prelude::*;
use types::*;

/// Generates a `Deposit` for each keypairs
pub fn generate_deposits_from_keypairs(
    keypairs: &[Keypair],
    genesis_time: u64,
    domain: u64,
    spec: &ChainSpec,
) -> Vec<Deposit> {
    debug!(
        "Generating {} validator deposits from random keypairs...",
        keypairs.len()
    );

    let initial_validator_deposits = keypairs
        .par_iter()
        .map(|keypair| {
            let withdrawal_credentials = Hash256::from_slice(
                &get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte)[..],
            );
            Deposit {
                branch: vec![], // branch verification is not specified.
                index: 0,       // index verification is not specified.
                deposit_data: DepositData {
                    amount: 32_000_000_000, // 32 ETH (in Gwei)
                    timestamp: genesis_time - 1,
                    deposit_input: DepositInput {
                        pubkey: keypair.pk.clone(),
                        // Validator can withdraw using their main keypair.
                        withdrawal_credentials: withdrawal_credentials.clone(),
                        proof_of_possession: DepositInput::create_proof_of_possession(
                            &keypair,
                            &withdrawal_credentials,
                            domain,
                        ),
                    },
                },
            }
        })
        .collect();

    initial_validator_deposits
}
