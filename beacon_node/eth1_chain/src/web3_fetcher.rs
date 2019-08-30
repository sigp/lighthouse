use bls::{PublicKeyBytes, SignatureBytes};
use ethabi::{decode, ParamType, Token};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::marker::Send;
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;
use types::DepositData;
use web3::contract::{Contract, Options};
use web3::futures::{Future, Stream};
use web3::transports::WebSocket;
use web3::types::FilterBuilder;
use web3::types::*;
use web3::Web3;

use crate::error::{Error, Result};
use crate::types::{ContractConfig, Eth1DataFetcher};

/// Wrapper around web3 api.
/// Transport hardcoded to ws since its needed for subscribing to logs.
#[derive(Clone, Debug)]
pub struct Web3DataFetcher {
    event_loop: Arc<web3::transports::EventLoopHandle>,
    /// Websocket transport object. Needed for logs subscription.
    web3: Arc<web3::api::Web3<web3::transports::ws::WebSocket>>,
    /// Deposit Contract
    contract: Contract<web3::transports::ws::WebSocket>,
}

impl Web3DataFetcher {
    /// Create a new Web3 object.
    pub fn new(endpoint: &str, deposit_contract: ContractConfig) -> Web3DataFetcher {
        let (event_loop, transport) = WebSocket::new(endpoint).unwrap();
        let web3 = Web3::new(transport);
        let contract =
            Contract::from_json(web3.eth(), deposit_contract.address, &deposit_contract.abi)
                .expect("Invalid contract address/abi");
        Web3DataFetcher {
            event_loop: Arc::new(event_loop),
            web3: Arc::new(web3),
            contract: contract,
        }
    }

    /// Return filter for subscribing to `DepositEvent` event.
    fn get_deposit_logs_filter(&self) -> Filter {
        /// Keccak256 hash of "DepositEvent" in bytes for passing to log filter.
        const DEPOSIT_CONTRACT_HASH: &str =
            "649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";
        let filter = FilterBuilder::default()
            .address(vec![self.contract.address()])
            .topics(
                Some(vec![DEPOSIT_CONTRACT_HASH.parse().unwrap()]),
                None,
                None,
                None,
            )
            .build();
        filter
    }
}

impl Eth1DataFetcher for Web3DataFetcher {
    /// Get block_number of current block.
    fn get_current_block_number(&self) -> Box<dyn Future<Item = U256, Error = Error> + Send> {
        Box::new(
            self.web3
                .eth()
                .block_number()
                .map_err(|e| {
                    println!("Error getting block number");
                    Error::Web3Error(e)
                })
                .timeout(Duration::from_secs(10))
                .map_err(|_| {
                    println!("Timed out getting block_number");
                    Error::Timeout
                }),
        )
    }

    /// Get block hash at given height.
    fn get_block_hash_by_height(
        &self,
        height: u64,
    ) -> Box<dyn Future<Item = Option<H256>, Error = Error> + Send> {
        Box::new(
            self.web3
                .eth()
                .block(BlockId::Number(BlockNumber::Number(height)))
                .map(|x| x.and_then(|b| b.hash))
                .map_err(|e| {
                    println!("Error getting block hash");
                    Error::Web3Error(e)
                })
                .timeout(Duration::from_secs(10))
                .map_err(|_| {
                    println!("Timed out getting block_hash");
                    Error::Timeout
                }),
        )
    }

    /// Get `deposit_count` from deposit contract at given eth1 block number.
    fn get_deposit_count(
        &self,
        block_number: Option<BlockNumber>,
    ) -> Box<dyn Future<Item = Result<u64>, Error = Error> + Send> {
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
                    vec_to_u64_le(&data)
                })
                .map_err(|e| {
                    println!("Error getting deposit count");
                    Error::ContractError(e)
                })
                .timeout(Duration::from_secs(10))
                .map_err(|_| {
                    println!("Timed out getting deposit count");
                    Error::Timeout
                }),
        )
    }

    /// Get `deposit_root` from deposit contract at given eth1 block number.
    fn get_deposit_root(
        &self,
        block_number: Option<BlockNumber>,
    ) -> Box<dyn Future<Item = H256, Error = Error> + Send> {
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
                .map_err(|e| {
                    println!("Error getting deposit root");
                    Error::ContractError(e)
                })
                .timeout(Duration::from_secs(10))
                .map_err(|_| {
                    println!("Timed out getting deposit root");
                    Error::Timeout
                }),
        )
    }

    /// Returns a future which subscribes to `DepositEvent` events and inserts the
    /// parsed deposit into the passed cache structure everytime an event is emitted.
    fn get_deposit_logs_subscription(
        &self,
        cache: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send> {
        let filter: Filter = self.get_deposit_logs_filter();
        let event_future = self
            .web3
            .eth_subscribe()
            .subscribe_logs(filter)
            .and_then(move |sub| {
                sub.for_each(move |log| {
                    let parsed_logs = parse_deposit_logs(log).unwrap();
                    let mut logs = cache.write();
                    println!("New log is {:?}", parsed_logs.1);
                    logs.insert(parsed_logs.0, parsed_logs.1);
                    Ok(())
                })
            })
            .map_err(|e| {
                println!("Error processing logs");
                Error::Web3Error(e)
            });
        Box::new(event_future)
    }
}

// Converts a valid vector to a u64.
pub fn vec_to_u64_le(bytes: &[u8]) -> Result<u64> {
    let mut array = [0; 8];
    if bytes.len() == 8 {
        let bytes = &bytes[..array.len()];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    } else {
        Err(Error::DecodingError)
    }
}

/// Parse contract logs.
pub fn parse_logs(log: Log, types: &[ParamType]) -> Result<Vec<Token>> {
    decode(types, &log.data.0).map_err(|e| e.into())
}

/// Parse logs from deposit contract.
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
        .ok_or(Error::DecodingError)?;

    // Event should have exactly 5 parameters.
    if params.len() == 5 {
        Ok((
            vec_to_u64_le(&params[4])?,
            DepositData {
                pubkey: PublicKeyBytes::from_bytes(&params[0]).unwrap(),
                withdrawal_credentials: H256::from_slice(&params[1]),
                amount: vec_to_u64_le(&params[2])?,
                signature: SignatureBytes::from_bytes(&params[3])?,
            },
        ))
    } else {
        Err(Error::DecodingError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Running tests using ganache-cli instance with config
    // from https://github.com/ChainSafe/lodestar#starting-private-eth1-chain

    fn setup() -> Web3DataFetcher {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        return w3;
    }

    #[test]
    fn test_get_current_block_number() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let block_number = runtime.block_on(w3.get_current_block_number());
        println!("{:?}", block_number);
        assert!(block_number.is_ok());
    }

    #[test]
    fn test_get_block() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let block_hash = w3.get_block_hash_by_height(1);
        let block_hash = runtime.block_on(block_hash).unwrap();
        println!("{:?}", block_hash);
        assert!(block_hash.is_some());
    }

    #[test]
    fn test_deposit_count() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let deposit_count = w3.get_deposit_count(None);
        let deposit_count = runtime.block_on(deposit_count).unwrap();
        println!("{:?}", deposit_count);
        assert!(deposit_count.is_ok());
    }

    #[test]
    fn test_deposit_root() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        let w3 = setup();
        let deposit_root = w3.get_deposit_root(None);
        let deposit_root = runtime.block_on(deposit_root).unwrap();
        println!("{:?}", deposit_root);
    }

}
