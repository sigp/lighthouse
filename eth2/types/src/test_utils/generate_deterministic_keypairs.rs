use crate::*;
use int_to_bytes::int_to_bytes48;
use log::debug;
use rayon::prelude::*;

/// Generates `validator_count` keypairs where the secret key is the index of the
/// validator.
///
/// For example, the first validator has a secret key of `int_to_bytes48(1)`, the second has
/// `int_to_bytes48(2)` and so on. (We skip `0` as it generates a weird looking public key and is
/// probably invalid).
pub fn generate_deterministic_keypairs(validator_count: usize) -> Vec<Keypair> {
    debug!(
        "Generating {} deterministic validator keypairs...",
        validator_count
    );

    let keypairs: Vec<Keypair> = (0..validator_count)
        .collect::<Vec<usize>>()
        .par_iter()
        .map(|&i| generate_deterministic_keypair(i))
        .collect();
    keypairs
}

/// Generates a single deterministic keypair, where the secret key is `validator_index`.
///
/// This is used for testing only, and not to be used in production!
pub fn generate_deterministic_keypair(validator_index: usize) -> Keypair {
    let secret = int_to_bytes48(validator_index as u64 + 1000);
    let sk = SecretKey::from_bytes(&secret).unwrap();
    let pk = PublicKey::from_secret_key(&sk);
    Keypair { sk, pk }
}
