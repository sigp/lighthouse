//! This library provides a wrapper around several BLS implementations to provide
//! Lighthouse-specific functionality.
//!
//! This crate should not perform direct cryptographic operations, instead it should do these via
//! external libraries. However, seeing as it is an interface to a real cryptographic library, it
//! may contain logic that affects the outcomes of cryptographic operations.
//!
//! A source of complexity in this crate is that *multiple* BLS implementations (a.k.a. "backends")
//! are supported via compile-time flags. There are three backends supported via features:
//!
//! - `supranational`: the pure-assembly, highly optimized version from the `blst` crate.
//! - `milagro`: the classic pure-Rust `milagro_bls` crate.
//! - `fake_crypto`: an always-returns-valid implementation that is only useful for testing
//!     scenarios which intend to *ignore* real cryptography.
//!
//! This crate uses traits to reduce code-duplication between the two implementations. For example,
//! the `GenericPublicKey` struct exported from this crate is generic across the `TPublicKey` trait
//! (i.e., `PublicKey<TPublicKey>`). `TPublicKey` is implemented by all three backends (see the
//! `impls.rs` module). When compiling with the `milagro` feature, we export
//! `type PublicKey = GenericPublicKey<milagro::PublicKey>`.

#[macro_use]
mod macros;
mod generic_aggregate_public_key;
mod generic_aggregate_signature;
mod generic_keypair;
mod generic_public_key;
mod generic_public_key_bytes;
mod generic_secret_key;
mod generic_signature;
mod generic_signature_bytes;
mod generic_signature_set;
mod get_withdrawal_credentials;
mod zeroize_hash;

pub mod impls;

pub use generic_public_key::{INFINITY_PUBLIC_KEY, PUBLIC_KEY_BYTES_LEN};
pub use generic_secret_key::SECRET_KEY_BYTES_LEN;
pub use generic_signature::{INFINITY_SIGNATURE, SIGNATURE_BYTES_LEN};
pub use get_withdrawal_credentials::get_withdrawal_credentials;
pub use zeroize_hash::ZeroizeHash;

use blst::BLST_ERROR as BlstError;
#[cfg(feature = "milagro")]
use milagro_bls::AmclError;

pub type Hash256 = ethereum_types::H256;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// An error was raised from the Milagro BLS library.
    #[cfg(feature = "milagro")]
    MilagroError(AmclError),
    /// An error was raised from the Supranational BLST BLS library.
    BlstError(BlstError),
    /// The provided bytes were an incorrect length.
    InvalidByteLength { got: usize, expected: usize },
    /// The provided secret key bytes were an incorrect length.
    InvalidSecretKeyLength { got: usize, expected: usize },
    /// The public key represents the point at infinity, which is invalid.
    InvalidInfinityPublicKey,
    /// The secret key is all zero bytes, which is invalid.
    InvalidZeroSecretKey,
}

#[cfg(feature = "milagro")]
impl From<AmclError> for Error {
    fn from(e: AmclError) -> Error {
        Error::MilagroError(e)
    }
}

impl From<BlstError> for Error {
    fn from(e: BlstError) -> Error {
        Error::BlstError(e)
    }
}

/// Generic implementations which are only generally useful for docs.
pub mod generics {
    pub use crate::generic_aggregate_public_key::GenericAggregatePublicKey;
    pub use crate::generic_aggregate_signature::GenericAggregateSignature;
    pub use crate::generic_keypair::GenericKeypair;
    pub use crate::generic_public_key::GenericPublicKey;
    pub use crate::generic_public_key_bytes::GenericPublicKeyBytes;
    pub use crate::generic_secret_key::GenericSecretKey;
    pub use crate::generic_signature::GenericSignature;
    pub use crate::generic_signature_bytes::GenericSignatureBytes;
}

/// Defines all the fundamental BLS points which should be exported by this crate by making
/// concrete the generic type parameters using the points from some external BLS library (e.g.,
/// Milagro, BLST).
macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            use crate::generics::*;

            pub use bls_variant::{verify_signature_sets, SignatureSet};

            pub type PublicKey = GenericPublicKey<bls_variant::PublicKey>;
            pub type PublicKeyBytes = GenericPublicKeyBytes<bls_variant::PublicKey>;
            pub type AggregatePublicKey =
                GenericAggregatePublicKey<bls_variant::PublicKey, bls_variant::AggregatePublicKey>;
            pub type Signature = GenericSignature<bls_variant::PublicKey, bls_variant::Signature>;
            pub type AggregateSignature = GenericAggregateSignature<
                bls_variant::PublicKey,
                bls_variant::AggregatePublicKey,
                bls_variant::Signature,
                bls_variant::AggregateSignature,
            >;
            pub type SignatureBytes =
                GenericSignatureBytes<bls_variant::PublicKey, bls_variant::Signature>;
            pub type SecretKey = GenericSecretKey<
                bls_variant::Signature,
                bls_variant::PublicKey,
                bls_variant::SecretKey,
            >;
            pub type Keypair = GenericKeypair<
                bls_variant::PublicKey,
                bls_variant::SecretKey,
                bls_variant::Signature,
            >;
        }
    };
}

#[cfg(feature = "milagro")]
define_mod!(milagro_implementations, crate::impls::milagro::types);
define_mod!(blst_implementations, crate::impls::blst::types);
#[cfg(feature = "fake_crypto")]
define_mod!(
    fake_crypto_implementations,
    crate::impls::fake_crypto::types
);

#[cfg(all(feature = "milagro", not(feature = "fake_crypto"),))]
pub use milagro_implementations::*;

#[cfg(all(
    feature = "supranational",
    not(feature = "fake_crypto"),
    not(feature = "milagro")
))]
pub use blst_implementations::*;

#[cfg(feature = "fake_crypto")]
pub use fake_crypto_implementations::*;
