extern crate milagro_bls;
extern crate ssz;

#[macro_use]
mod macros;
mod keypair;
mod public_key_bytes;
mod secret_key;
mod signature_bytes;
mod signature_set;

pub use crate::keypair::Keypair;
pub use crate::public_key_bytes::PublicKeyBytes;
pub use crate::secret_key::SecretKey;
pub use crate::signature_bytes::SignatureBytes;
pub use milagro_bls::{compress_g2, hash_on_g2, G1Point};
pub use signature_set::{verify_signature_sets, SignatureSet, SignedMessage};

#[cfg(feature = "fake_crypto")]
mod fake_aggregate_public_key;
#[cfg(feature = "fake_crypto")]
mod fake_aggregate_signature;
#[cfg(feature = "fake_crypto")]
mod fake_public_key;
#[cfg(feature = "fake_crypto")]
mod fake_signature;

#[cfg(not(feature = "fake_crypto"))]
mod aggregate_public_key;
#[cfg(not(feature = "fake_crypto"))]
mod aggregate_signature;
#[cfg(not(feature = "fake_crypto"))]
mod public_key;
#[cfg(not(feature = "fake_crypto"))]
mod signature;

#[cfg(feature = "fake_crypto")]
pub use fakes::*;
#[cfg(feature = "fake_crypto")]
mod fakes {
    pub use crate::fake_aggregate_public_key::FakeAggregatePublicKey as AggregatePublicKey;
    pub use crate::fake_aggregate_signature::FakeAggregateSignature as AggregateSignature;
    pub use crate::fake_public_key::FakePublicKey as PublicKey;
    pub use crate::fake_signature::FakeSignature as Signature;
}

#[cfg(not(feature = "fake_crypto"))]
pub use reals::*;
#[cfg(not(feature = "fake_crypto"))]
mod reals {
    pub use crate::aggregate_public_key::AggregatePublicKey;
    pub use crate::aggregate_signature::AggregateSignature;
    pub use crate::public_key::PublicKey;
    pub use crate::signature::Signature;
}

pub const BLS_AGG_SIG_BYTE_SIZE: usize = 96;
pub const BLS_SIG_BYTE_SIZE: usize = 96;
pub const BLS_SECRET_KEY_BYTE_SIZE: usize = 48;
pub const BLS_PUBLIC_KEY_BYTE_SIZE: usize = 48;

use eth2_hashing::hash;
use ssz::ssz_encode;

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
