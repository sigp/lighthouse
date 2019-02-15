extern crate bls_aggregates;
extern crate hashing;
extern crate ssz;

mod aggregate_signature;
mod keypair;
mod public_key;
mod secret_key;
mod signature;

pub use crate::aggregate_signature::AggregateSignature;
pub use crate::keypair::Keypair;
pub use crate::public_key::PublicKey;
pub use crate::secret_key::SecretKey;
pub use crate::signature::Signature;

pub use self::bls_aggregates::AggregatePublicKey;

pub const BLS_AGG_SIG_BYTE_SIZE: usize = 97;

use hashing::hash;
use ssz::ssz_encode;
use std::default::Default;

fn extend_if_needed(hash: &mut Vec<u8>) {
    // NOTE: bls_aggregates crate demands 48 bytes, this may be removed as we get closer to production
    hash.resize(48, Default::default())
}

/// For some signature and public key, ensure that the signature message was the public key and it
/// was signed by the secret key that corresponds to that public key.


pub fn create_proof_of_possession(keypair: &Keypair) -> Signature {
    Signature::new(&ssz_encode(&keypair.pk), 0, &keypair.sk)
}

pub fn bls_verify_aggregate(
    pubkey: &AggregatePublicKey,
    message: &[u8],
    signature: &AggregateSignature,
    domain: u64,
) -> bool {
    // TODO: add domain
    signature.verify(message, domain, pubkey)
}
