use ethabi::Error as AbiError;
use ssz;
use web3;

#[derive(Debug)]
pub enum Error {
    /// Errors that occur on interaction with an Eth1 node.
    Web3Error(web3::error::Error),
    /// Web3 request timeout.
    Timeout,
    /// Error on interacting with a contract on Eth1.
    ContractError(web3::contract::Error),
    /// Decoding error.
    DecodingError,
    /// Invalid parameters
    InvalidParam,
    /// Invalid data
    InvalidData,
    /// Missing deposit index
    MissingDeposit(u64),
}

impl From<web3::error::Error> for Error {
    fn from(err: web3::error::Error) -> Self {
        Error::Web3Error(err)
    }
}

impl From<web3::contract::Error> for Error {
    fn from(err: web3::contract::Error) -> Self {
        Error::ContractError(err)
    }
}

impl From<AbiError> for Error {
    fn from(err: AbiError) -> Self {
        Error::ContractError(err.into())
    }
}

impl From<ssz::DecodeError> for Error {
    fn from(_err: ssz::DecodeError) -> Self {
        Error::DecodingError
    }
}

pub type Result<T> = std::result::Result<T, Error>;
