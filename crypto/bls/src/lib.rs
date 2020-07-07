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
    MilagroError(AmclError),
    BlstError(BlstError),
    InvalidByteLength { got: usize, expected: usize },
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
