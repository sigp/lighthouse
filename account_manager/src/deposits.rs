use crate::local_validator::LocalValidator;
use clap::{App, Arg, ArgMatches};
use clap_utils;
use deposit_contract::DEPOSIT_GAS;
use ethsign::{KeyFile, Protected, SecretKey};
use futures::Future;
use std::io;
use std::path::PathBuf;
use web3::{
    transports::Http,
    types::{Address, TransactionRequest, U256},
    Transport, Web3,
};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("deposit")
        .about("Create a validator and have it deposit to the Eth1 chain.")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .short("d")
                .value_name("DATA_DIRECTORY")
                .help("The path where the validator directories will be created. Defaults to ~/.lighthouse/validators")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("eth1-keystore")
                .long("eth1-keystore")
                .short("k")
                .value_name("KEYSTORE_PATH")
                .help("Path to an Eth1 keystore to sign the transaction")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("eth1-password")
                .long("eth1-password")
                .short("p")
                .value_name("PASSWORD")
                .help("The password for the --eth1-keystore file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .short("c")
                .value_name("DEPOSIT_COUNT")
                .help("The number of deposits to create, regardless of how many already exist")
                .conflicts_with("limit")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("limit")
                .long("limit")
                .short("l")
                .value_name("VALIDATOR_LIMIT")
                .help("Observe the number of validators in --datadir, only creating enough to ensure the given limit")
                .conflicts_with("count")
                .takes_value(true),
        )
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let datadir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "datadir",
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let eth1_keystore_dir: PathBuf = clap_utils::parse_required(matches, "eth1-keystore")?;
    let eth1_keystore_pass: String = clap_utils::parse_required(matches, "eth1-password")?;
    let count: Option<usize> = clap_utils::parse_optional(matches, "count")?;
    let limit: Option<usize> = clap_utils::parse_optional(matches, "limit")?;

    todo!()
}

pub enum Error {
    /// There was an error reading the eth1 key-store crypto keysj.
    KeystoreCryptoError(ethsign::Error),
    /// There was an Error reading the key-store from disk.
    KeystoreOpenError(io::Error),
    /// There was an Error parsing the key-store JSON.
    KeystoreJsonError(serde_json::Error),
    KeystoreEth1AddressTooShort,
    KeystoreMissingSecretKey,
    Eth1AddressUnknown,
    DepositAmountUnknown,
    DepositDataUnknown,
    FailedToSubmitDepositTx(web3::Error),
}

impl From<ethsign::Error> for Error {
    fn from(e: ethsign::Error) -> Self {
        Error::KeystoreCryptoError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::KeystoreOpenError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::KeystoreJsonError(e)
    }
}

struct ValidatorDepositor<T: Transport> {
    web3: Web3<T>,
    eth1_secret_key: SecretKey,
    eth1_keystore_address: Address,
    eth1_deposit_contract: Address,
}

impl<T: Transport> ValidatorDepositor<T> {
    pub fn new(
        transport: T,
        eth1_deposit_contract: Address,
        keystore_path: PathBuf,
        keystore_password: Protected,
    ) -> Result<Self, Error> {
        let file = std::fs::File::open(keystore_path)?;
        let key: KeyFile = serde_json::from_reader(file)?;
        let eth1_secret_key = key.to_secret_key(&keystore_password)?;
        let eth1_keystore_address = key
            .address
            .map::<Result<_, Error>, _>(|bytes| {
                let slice = bytes
                    .0
                    .get(0..20)
                    .ok_or_else(|| Error::KeystoreEth1AddressTooShort)?;
                Ok(Address::from_slice(slice))
            })
            .ok_or_else(|| Error::KeystoreMissingSecretKey)??;

        Ok(Self {
            web3: Web3::new(transport),
            eth1_secret_key,
            eth1_keystore_address,
            eth1_deposit_contract,
        })
    }

    fn submit_deposit(
        &self,
        deposit_amount: u64,
        deposit_data: Vec<u8>,
    ) -> impl Future<Item = (), Error = Error> {
        self.web3
            .eth()
            .send_transaction(TransactionRequest {
                from: self.eth1_keystore_address,
                to: Some(self.eth1_deposit_contract),
                gas: Some(DEPOSIT_GAS.into()),
                gas_price: None,
                value: Some(deposit_amount.into()),
                data: Some(deposit_data.into()),
                nonce: None,
                condition: None,
            })
            .map(|_tx| ())
            .map_err(Error::FailedToSubmitDepositTx)
    }
}

/*
pub fn deposit_validators(matches: &ArgMatches) -> Result<(), String> {
    let datadir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "datadir",
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let eth1_keystore_dir: PathBuf = clap_utils::parse_required(matches, "eth1-keystore")?;
    let eth1_keystore_pass: String = clap_utils::parse_required(matches, "eth1-password")?;
    let count: Option<usize> = clap_utils::parse_optional(matches, "count")?;
    let limit: Option<usize> = clap_utils::parse_optional(matches, "limit")?;

    /*
    let  = match (count, limit) {
        (Some(_), Some(_)) => Err("Cannot supply count and limit")
    }?;
    */

    Ok(())
}
*/
