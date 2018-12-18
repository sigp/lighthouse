extern crate bls_aggregates;
extern crate hashing;

pub use self::bls_aggregates::AggregatePublicKey;
pub use self::bls_aggregates::AggregateSignature;
pub use self::bls_aggregates::Keypair;
pub use self::bls_aggregates::PublicKey;
pub use self::bls_aggregates::SecretKey;
pub use self::bls_aggregates::Signature;

pub const BLS_AGG_SIG_BYTE_SIZE: usize = 97;

use hashing::canonical_hash;
use std::default::Default;

fn extend_if_needed(hash: &mut Vec<u8>) {
    // NOTE: bls_aggregates crate demands 48 bytes, this may be removed as we get closer to production
    hash.resize(48, Default::default())
}

/// For some signature and public key, ensure that the signature message was the public key and it
/// was signed by the secret key that corresponds to that public key.
pub fn verify_proof_of_possession(sig: &Signature, pubkey: &PublicKey) -> bool {
    let mut hash = canonical_hash(&pubkey.as_bytes());
    extend_if_needed(&mut hash);
    sig.verify_hashed(&hash, &pubkey)
}

pub fn create_proof_of_possession(keypair: &Keypair) -> Signature {
    let mut hash = canonical_hash(&keypair.pk.as_bytes());
    extend_if_needed(&mut hash);
    Signature::new_hashed(&hash, &keypair.sk)
}
