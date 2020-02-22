#[macro_use]
mod macros;
mod herumi;
mod public_key;
mod signature;

pub use public_key::PUBLIC_KEY_BYTES_LEN;

pub use herumi_implementations::*;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    HerumiError(bls_eth_rust::BlsError),
}

impl From<bls_eth_rust::BlsError> for Error {
    fn from(e: bls_eth_rust::BlsError) -> Error {
        Error::HerumiError(e)
    }
}

mod herumi_implementations {
    pub type PublicKey = crate::public_key::PublicKey<bls_eth_rust::PublicKey>;
    pub type Signature =
        crate::signature::Signature<bls_eth_rust::PublicKey, bls_eth_rust::Signature>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
