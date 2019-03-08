use bls::{create_proof_of_possession, get_withdrawal_credentials};
use int_to_bytes::int_to_bytes48;
use log::debug;
use rayon::prelude::*;
use types::*;

/// Generates `validator_count` deposits using keypairs where the secret key is the index of the
/// validator.
///
/// For example, the first validator has a secret key of `int_to_bytes48(1)`, the second has
/// `int_to_bytes48(2)` and so on. (We skip `0` as it generates a weird looking public key and is
/// probably invalid).
pub fn generate_deposits_with_deterministic_keypairs(
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
        .map(|&i| {
            let secret = int_to_bytes48(i as u64 + 1);
            let sk = SecretKey::from_bytes(&secret).unwrap();
            let pk = PublicKey::from_secret_key(&sk);
            Keypair { sk, pk }
        })
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
