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
        .map(|&i| {
            let secret = int_to_bytes48(i as u64 + 1);
            let sk = SecretKey::from_bytes(&secret).unwrap();
            let pk = PublicKey::from_secret_key(&sk);
            Keypair { sk, pk }
        })
        .collect();

    keypairs
}
