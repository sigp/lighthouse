use bls::{PublicKeyBytes, SignatureBytes};
use ethabi::{decode, ParamType, Token};
use parking_lot::RwLock;
use slog::{error, o, info};
use std::collections::BTreeMap;
use std::marker::Send;
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;
use types::DepositData;
use web3::contract::{Contract, Options};
use web3::futures::Future;
use web3::transports::WebSocket;
use web3::types::FilterBuilder;
use web3::types::*;
use web3::Web3;

use crate::error::{Error, Result};
use crate::types::Eth1DataFetcher;

// ABI bytes.
const ABI: &'static [u8] = include_bytes!("../abi/v0.8.3_validator_registration.json");

// Keccak256 hash of "DepositEvent" in bytes for passing to log filter.
const DEPOSIT_CONTRACT_HASH: &str =
    r"649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";

/// Wrapper around web3 api.
/// Transport hardcoded to ws since its needed for subscribing to logs.
#[derive(Clone, Debug)]
pub struct Web3DataFetcher {
    event_loop: Arc<web3::transports::EventLoopHandle>,
    /// Websocket transport object. Needed for logs subscription.
    web3: Arc<web3::api::Web3<web3::transports::ws::WebSocket>>,
    /// Deposit Contract
    contract: Contract<web3::transports::ws::WebSocket>,
    /// Timeout for eth1 requests in seconds.
    timeout: u64,
    log: slog::Logger,
}

impl Web3DataFetcher {
    /// Create a new Web3 object.
    pub fn new(
        endpoint: &str,
        deposit_contract_addr: &str,
        timeout: u64,
        log: &slog::Logger,
    ) -> Result<Self> {
        let log = log.new(o!("eth1_chain" => "web3_fetcher"));
        let (event_loop, transport) = WebSocket::new(endpoint)?;
        let web3 = Web3::new(transport);
        let contract = Contract::from_json(
            web3.eth(),
            deposit_contract_addr.parse().map_err(|_| {
                Error::Web3Error(web3::error::Error::Decoder(
                    "Failed to parse deposit contract address".to_string(),
                ))
            })?,
            &ABI,
        )?;
        Ok(Web3DataFetcher {
            event_loop: Arc::new(event_loop),
            web3: Arc::new(web3),
            contract: contract,
            timeout: timeout,
            log: log,
        })
    }
}

impl Eth1DataFetcher for Web3DataFetcher {
    /// Get block_number of current block.
    fn get_current_block_number(&self) -> Box<dyn Future<Item = U256, Error = Error> + Send> {
        let log = self.log.clone();
        Box::new(
            self.web3
                .eth()
                .block_number()
                .map_err(move |e| {
                    error!(
                        log,
                        "Error getting block number";
                        "error" => format!("{:?}", e),
                    );
                    Error::Web3Error(e)
                })
                .timeout(Duration::from_secs(self.timeout))
                .map_err(|_| Error::Timeout),
        )
    }

    /// Get block hash at given height.
    fn get_block_hash_by_height(
        &self,
        height: u64,
    ) -> Box<dyn Future<Item = Option<H256>, Error = Error> + Send> {
        let log = self.log.clone();
        Box::new(
            self.web3
                .eth()
                .block(BlockId::Number(BlockNumber::Number(height)))
                .map(|x| x.and_then(|b| b.hash))
                .map_err(move |e| {
                    error!(
                        log,
                        "Error getting block hash";
                        "error" => format!("{:?}", e),
                    );
                    Error::Web3Error(e)
                })
                .timeout(Duration::from_secs(self.timeout))
                .map_err(|_| Error::Timeout),
        )
    }

    /// Get block height given the hash.
    fn get_block_height_by_hash(
        &self,
        hash: H256,
    ) -> Box<dyn Future<Item = Option<U128>, Error = Error> + Send> {
        let log = self.log.clone();
        Box::new(
            self.web3
                .eth()
                .block(BlockId::Hash(hash))
                .map(|x| x.and_then(|b| b.number))
                .map_err(move |e| {
                    error!(
                        log,
                        "Error getting block number";
                        "error" => format!("{:?}", e),
                    );
                    Error::Web3Error(e)
                })
                .timeout(Duration::from_secs(self.timeout))
                .map_err(|_| Error::Timeout),
        )
    }

    /// Get `deposit_count` from deposit contract at given eth1 block number.
    fn get_deposit_count(
        &self,
        block_number: Option<BlockNumber>,
    ) -> Box<dyn Future<Item = Result<u64>, Error = Error> + Send> {
        let log = self.log.clone();
        Box::new(
            self.contract
                .query(
                    "get_deposit_count",
                    (),
                    None,
                    Options::default(),
                    block_number,
                )
                .map(|x| {
                    let data: Vec<u8> = x;
                    vec_to_u64_le(&data).ok_or(Error::ContractError(
                        web3::contract::Error::InvalidOutputType(
                            "Error parsing deposit count from deposit contract".to_string(),
                        ),
                    ))
                })
                .map_err(move |e| {
                    error!(
                        log,
                        "Error getting deposit count";
                        "error" => format!("{:?}", e),
                    );
                    Error::ContractError(e)
                })
                .timeout(Duration::from_secs(self.timeout))
                .map_err(|_| Error::Timeout),
        )
    }

    /// Get `deposit_root` from deposit contract at given eth1 block number.
    fn get_deposit_root(
        &self,
        block_number: Option<BlockNumber>,
    ) -> Box<dyn Future<Item = H256, Error = Error> + Send> {
        let log = self.log.clone();
        Box::new(
            self.contract
                .query(
                    "get_hash_tree_root",
                    (),
                    None,
                    Options::default(),
                    block_number,
                )
                .map(|x: Vec<u8>| H256::from_slice(&x))
                .map_err(move |e| {
                    error!(
                        log,
                        "Error getting deposit root";
                        "error" => format!("{:?}", e),
                    );
                    Error::ContractError(e)
                })
                .timeout(Duration::from_secs(self.timeout))
                .map_err(|_| Error::Timeout),
        )
    }

    /// Get `DepositEvent` events in given range.
    fn get_deposit_logs_in_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
        cache: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send> {
        let log = self.log.clone();
        let filter = FilterBuilder::default()
            .address(vec![self.contract.address()])
            .topics(
                Some(vec![DEPOSIT_CONTRACT_HASH
                    .parse()
                    .expect("Invalid deposit contract hash")]),
                None,
                None,
                None,
            )
            .from_block(start_block)
            .to_block(end_block)
            .build();
        info!(
            &log,
            "Getting deposit logs in range {:?} to {:?}", start_block, end_block
        );
        let future = self
            .web3
            .eth()
            .logs(filter)
            .and_then(move |logs| Ok(logs)) // Additional `and_then` to convert error type.
            .map_err(move |e| {
                error!(
                    log,
                    "Error getting deposit logs";
                    "error" => format!("{:?}", e),
                );
                Error::Web3Error(e)
            })
            .and_then(move |logs| {
                for log in logs {
                    let parsed_logs = parse_deposit_logs(log)?;
                    let mut logs = cache.write();
                    logs.insert(parsed_logs.0, parsed_logs.1);
                }
                Ok(())
            })
            .timeout(Duration::from_secs(self.timeout))
            .map_err(|_| Error::Timeout);
        Box::new(future)
    }
}

// Converts a valid vector to a u64.
pub fn vec_to_u64_le(bytes: &[u8]) -> Option<u64> {
    let mut array = [0; 8];
    if bytes.len() == 8 {
        let bytes = &bytes[..array.len()];
        array.copy_from_slice(bytes);
        Some(u64::from_le_bytes(array))
    } else {
        None
    }
}

/// Parse contract logs.
pub fn parse_logs(log: Log, types: &[ParamType]) -> Result<Vec<Token>> {
    decode(types, &log.data.0).map_err(|e| e.into())
}

/// Parse logs from deposit contract.
/// Returns (DepositIndex, DepositData)
pub fn parse_deposit_logs(log: Log) -> Result<(u64, DepositData)> {
    let deposit_event_params = &[
        ParamType::FixedBytes(48), // pubkey
        ParamType::FixedBytes(32), // withdrawal_credentials
        ParamType::FixedBytes(8),  // amount
        ParamType::FixedBytes(96), // signature
        ParamType::FixedBytes(8),  // index
    ];
    let parsed_logs = parse_logs(log, deposit_event_params)?;
    // Convert from tokens to Vec<u8>.
    let params = parsed_logs
        .into_iter()
        .map(|x| match x {
            Token::FixedBytes(v) => Some(v),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::ContractError(
            web3::contract::Error::InvalidOutputType(
                "Invalid token in deposit contract logs".to_string(),
            ),
        ))?;

    // Deposit contract events should have exactly 5 parameters.
    if params.len() == 5 {
        Ok((
            vec_to_u64_le(&params[4]).ok_or(Error::ContractError(
                web3::contract::Error::InvalidOutputType(
                    "Error parsing deposit index from deposit contract logs".to_string(),
                ),
            ))?,
            DepositData {
                pubkey: PublicKeyBytes::from_bytes(&params[0])?,
                withdrawal_credentials: H256::from_slice(&params[1]),
                amount: vec_to_u64_le(&params[2]).ok_or(Error::ContractError(
                    web3::contract::Error::InvalidOutputType(
                        "Error parsing deposit amount from deposit contract logs".to_string(),
                    ),
                ))?,
                signature: SignatureBytes::from_bytes(&params[3])?,
            },
        ))
    } else {
        Err(Error::ContractError(
            web3::contract::Error::InvalidOutputType(
                "Invalid number of parameters in deposit contract log".to_string(),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use slog::{o, Drain};

    fn setup_log() -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(drain, o!())
    }

    fn setup() -> Web3DataFetcher {
        let config = Config::default();
        let w3 = Web3DataFetcher::new(&config.endpoint, &config.address, config.timeout, &setup_log());
        return w3.unwrap();
    }

    #[test]
    fn test_get_current_block_number() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let block_number = runtime.block_on(w3.get_current_block_number());
        assert!(block_number.is_ok());
    }

    #[test]
    fn test_get_block() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let block_hash = w3.get_block_hash_by_height(1);
        let block_hash = runtime.block_on(block_hash).unwrap();
        assert!(block_hash.is_some());
    }

    #[test]
    fn test_deposit_count() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let deposit_count = w3.get_deposit_count(None);
        let deposit_count = runtime.block_on(deposit_count).unwrap();
        assert!(deposit_count.is_ok());
    }

    #[test]
    fn test_deposit_root() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let deposit_root = w3.get_deposit_root(None);
        let _deposit_root = runtime.block_on(deposit_root).unwrap();
    }

}
