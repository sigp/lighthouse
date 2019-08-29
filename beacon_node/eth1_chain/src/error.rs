use ethabi::Error as AbiError;
use ssz;
use web3;

#[derive(Debug)]
pub enum Eth1Error {
    /// Errors that occur on interaction with an Eth1 node.
    Web3Error(web3::error::Error),
    /// Web3 request timeout.
    Timeout,
    /// Error on interacting with a contract on Eth1.
    ContractError(web3::contract::Error),
    /// Decoding error.
    DecodingError,
}

impl From<web3::error::Error> for Eth1Error {
    fn from(err: web3::error::Error) -> Self {
        Eth1Error::Web3Error(err)
    }
}

impl From<web3::contract::Error> for Eth1Error {
    fn from(err: web3::contract::Error) -> Self {
        Eth1Error::ContractError(err)
    }
}

impl From<AbiError> for Eth1Error {
    fn from(err: AbiError) -> Self {
        Eth1Error::ContractError(err.into())
    }
}

impl From<ssz::DecodeError> for Eth1Error {
    fn from(_err: ssz::DecodeError) -> Self {
        Eth1Error::DecodingError
    }
}
