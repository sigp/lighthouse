#[macro_use]
mod macros;
mod impls;
mod keypair;
mod public_key;
mod public_key_bytes;
mod secret_key;
mod signature;
mod signature_bytes;

pub use impls::*;
pub use public_key::PUBLIC_KEY_BYTES_LEN;
pub use secret_key::SECRET_KEY_BYTES_LEN;
pub use signature::{MSG_SIZE, SIGNATURE_BYTES_LEN};

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    HerumiError(bls_eth_rust::BlsError),
    MilagroError(milagro_bls::DecodeError),
    InvalidByteLength { got: usize, expected: usize },
}

impl From<bls_eth_rust::BlsError> for Error {
    fn from(e: bls_eth_rust::BlsError) -> Error {
        Error::HerumiError(e)
    }
}

impl From<milagro_bls::DecodeError> for Error {
    fn from(e: milagro_bls::DecodeError) -> Error {
        Error::MilagroError(e)
    }
}
