#[macro_use]
mod macros;
mod fake_crypto;
mod herumi;
mod milagro;
mod public_key;
mod secret_key;
mod signature;

pub use public_key::PUBLIC_KEY_BYTES_LEN;
pub use signature::{MSG_SIZE, SIGNATURE_BYTES_LEN};

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    HerumiError(bls_eth_rust::BlsError),
    MilagroError(milagro_bls::DecodeError),
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

#[cfg(feature = "herumi")]
pub use herumi_implementations::*;

pub mod herumi_implementations {
    pub type PublicKey = crate::public_key::PublicKey<bls_eth_rust::PublicKey>;
    pub type Signature =
        crate::signature::Signature<bls_eth_rust::PublicKey, bls_eth_rust::Signature>;
}

#[cfg(feature = "fake_crypto")]
pub use fake_crypto_implementations::*;

pub mod fake_crypto_implementations {
    pub type PublicKey = crate::public_key::PublicKey<crate::fake_crypto::PublicKey>;
    pub type Signature =
        crate::signature::Signature<crate::fake_crypto::PublicKey, crate::fake_crypto::Signature>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
