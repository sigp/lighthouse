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

macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            pub type PublicKey = crate::public_key::PublicKey<bls_variant::PublicKey>;
            pub type Signature =
                crate::signature::Signature<bls_variant::PublicKey, bls_variant::Signature>;
            pub type SecretKey =
                crate::secret_key::SecretKey<bls_variant::Signature, bls_variant::SecretKey>;
        }
    };
}

define_mod!(herumi_implementations, crate::herumi);
#[cfg(feature = "herumi")]
pub use herumi_implementations::*;

define_mod!(fake_crypto_implementations, crate::fake_crypto);
#[cfg(feature = "fake_crypto")]
pub use fake_crypto_implementations::*;

define_mod!(milagro_implementations, crate::milagro);
#[cfg(feature = "milagro")]
pub use milagro_implementations::*;
