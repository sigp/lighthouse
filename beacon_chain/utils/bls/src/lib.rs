extern crate bls_aggregates;
extern crate hashing;
extern crate ssz;

mod aggregate_signature;
mod signature;

pub use aggregate_signature::AggregateSignature;
pub use signature::Signature;

pub use self::bls_aggregates::AggregatePublicKey;
pub use self::bls_aggregates::Keypair;
pub use self::bls_aggregates::PublicKey;
pub use self::bls_aggregates::SecretKey;

pub const BLS_AGG_SIG_BYTE_SIZE: usize = 97;

use hashing::proof_of_possession_hash;

/// For some signature and public key, ensure that the signature message was the public key and it
/// was signed by the secret key that corresponds to that public key.
pub fn verify_proof_of_possession(sig: &Signature, pubkey: &PublicKey) -> bool {
    let hash = proof_of_possession_hash(&pubkey.as_bytes());
    sig.verify_hashed(&hash, &pubkey)
}

pub fn create_proof_of_possession(keypair: &Keypair) -> Signature {
    let hash = proof_of_possession_hash(&keypair.pk.as_bytes());
    Signature::new_hashed(&hash, &keypair.sk)
}
