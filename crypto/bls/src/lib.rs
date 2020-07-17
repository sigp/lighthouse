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
//! the `PublicKey` struct exported from this crate is generic across the `TPublicKey` trait (i.e.,
//! `PublicKey<TPublicKey>`). `TPublicKey` is implemented by all three backends (see the `impls.rs`
//! module). When compiling with the `milagro` feature, we export `PublicKey<milagro::PublicKey>`.

#[macro_use]
mod macros;
mod aggregate_public_key;
mod aggregate_signature;
mod get_withdrawal_credentials;
mod impls;
mod keypair;
mod public_key;
mod public_key_bytes;
mod secret_hash;
mod secret_key;
mod signature;
mod signature_bytes;
mod signature_set;

pub use get_withdrawal_credentials::get_withdrawal_credentials;
pub use impls::*;
pub use public_key::PUBLIC_KEY_BYTES_LEN;
pub use secret_hash::SecretHash;
pub use secret_key::SECRET_KEY_BYTES_LEN;
pub use signature::SIGNATURE_BYTES_LEN;

use blst::BLST_ERROR as BlstError;
use milagro_bls::AmclError;

pub type Hash256 = ethereum_types::H256;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// An error was raised from the Milagro BLS library.
    MilagroError(AmclError),
    /// An error was raised from the Supranational BLST BLS library.
    BlstError(BlstError),
    /// The provided bytes were an incorrect length.
    InvalidByteLength { got: usize, expected: usize },
    /// The provided secret key bytes were an incorrect length.
    InvalidSecretKeyLength { got: usize, expected: usize },
}

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
