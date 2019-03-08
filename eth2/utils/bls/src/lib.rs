extern crate bls_aggregates;
extern crate ssz;

mod aggregate_public_key;
mod aggregate_signature;
mod keypair;
mod public_key;
mod secret_key;
mod signature;

pub use crate::aggregate_public_key::AggregatePublicKey;
pub use crate::aggregate_signature::AggregateSignature;
pub use crate::keypair::Keypair;
pub use crate::public_key::PublicKey;
pub use crate::secret_key::SecretKey;
pub use crate::signature::Signature;

pub const BLS_AGG_SIG_BYTE_SIZE: usize = 96;

use hashing::hash;
use ssz::ssz_encode;

/// For some signature and public key, ensure that the signature message was the public key and it
/// was signed by the secret key that corresponds to that public key.
pub fn verify_proof_of_possession(sig: &Signature, pubkey: &PublicKey) -> bool {
    // TODO: replace this function with state.validate_proof_of_possession
    // https://github.com/sigp/lighthouse/issues/239
    sig.verify(&ssz_encode(pubkey), 0, &pubkey)
}

// TODO: Update this method
// https://github.com/sigp/lighthouse/issues/239
pub fn create_proof_of_possession(keypair: &Keypair) -> Signature {
    Signature::new(&ssz_encode(&keypair.pk), 0, &keypair.sk)
}

/// Returns the withdrawal credentials for a given public key.
pub fn get_withdrawal_credentials(pubkey: &PublicKey, prefix_byte: u8) -> Vec<u8> {
    let hashed = hash(&ssz_encode(pubkey));
    let mut prefixed = vec![prefix_byte];
    prefixed.extend_from_slice(&hashed[1..]);

    prefixed
}

pub fn bls_verify_aggregate(
    pubkey: &AggregatePublicKey,
    message: &[u8],
    signature: &AggregateSignature,
    domain: u64,
) -> bool {
    signature.verify(message, domain, pubkey)
}
