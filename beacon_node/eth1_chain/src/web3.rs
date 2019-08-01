use bls::{PublicKey, Signature};
use ethabi::{decode, ParamType, Token};
use types::DepositData;
use web3::contract::{Contract, Options};
use web3::futures::Future;
use web3::transports::WebSocket;
use web3::types::FilterBuilder;
use web3::types::*;
use web3::Web3;

use crate::eth1::Eth1DataFetcher;

/// Config for an Eth1 chain contract.
#[derive(Debug, Clone)]
pub struct ContractConfig {
    /// Deployed address in eth1 chain.
    pub address: Address,
    /// Contract abi.
    pub abi: Vec<u8>,
}

/// Wrapper around web3 api.
pub struct Web3DataFetcher {
    _event_loop: web3::transports::EventLoopHandle,
    web3: web3::api::Web3<web3::transports::ws::WebSocket>,
    /// Deposit contract config.
    contract: ContractConfig,
}

impl Web3DataFetcher {
    /// Create a new Web3 object.
    pub fn new(endpoint: &str, deposit_contract: ContractConfig) -> Web3DataFetcher {
        let (event_loop, transport) = WebSocket::new(endpoint).unwrap();
        let web3 = Web3::new(transport);
        Web3DataFetcher {
            _event_loop: event_loop,
            web3,
            contract: deposit_contract,
        }
    }
}

impl Eth1DataFetcher for Web3DataFetcher {
    /// Get block_number of current block.
    fn get_current_block_number(&self) -> Option<U256> {
        let block_future = self.web3.eth().block_number();
        let block = block_future.wait().ok()?;
        Some(block)
    }

    /// Get block hash at given height.
    fn get_block_hash_by_height(&self, height: u64) -> Option<H256> {
        let block_future = self
            .web3
            .eth()
            .block(BlockId::Number(BlockNumber::Number(height)));
        let block = block_future.wait();
        block.ok().and_then(|x| x).and_then(|b| b.hash)
    }

    /// Get `deposit_count` from deposit contract at given eth1 block number.
    fn get_deposit_count(&self, block_number: Option<BlockNumber>) -> Option<u64> {
        let contract =
            Contract::from_json(self.web3.eth(), self.contract.address, &self.contract.abi).ok()?;
        let data = contract.query(
            "get_deposit_count",
            (),
            None,
            Options::default(),
            block_number,
        );
        let deposit_count: Vec<u8> = data.wait().ok()?;
        vec_to_u64_le(&deposit_count)
    }

    /// Get `deposit_root` from deposit contract at given eth1 block number.
    fn get_deposit_root(&self, block_number: Option<BlockNumber>) -> Option<H256> {
        let contract =
            Contract::from_json(self.web3.eth(), self.contract.address, &self.contract.abi).ok()?;
        let data = contract.query(
            "get_hash_tree_root",
            (),
            None,
            Options::default(),
            block_number,
        );
        let deposit_root: Vec<u8> = data.wait().ok()?;
        Some(H256::from_slice(&deposit_root))
    }

    /// Get `DepositEvent` events in given range.
    fn get_deposit_logs_in_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
    ) -> Option<Vec<Log>> {
        /// Keccak256 hash of "DepositEvent" in bytes for passing to log filter.
        const DEPOSIT_CONTRACT_HASH: &str =
            "649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";
        let filter = FilterBuilder::default()
            .address(vec![self.contract.address])
            .topics(
                Some(vec![DEPOSIT_CONTRACT_HASH.parse().unwrap()]),
                None,
                None,
                None,
            )
            .from_block(start_block)
            .to_block(end_block)
            .build();
        self.web3.eth().logs(filter).wait().ok()
    }
}

// Converts a valid vector to a u64.
fn vec_to_u64_le(bytes: &[u8]) -> Option<u64> {
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
fn parse_logs(log: Log, types: &[ParamType]) -> Option<Vec<Token>> {
    decode(types, &log.data.0).ok()
}

/// Parse logs from deposit contract.
pub fn parse_deposit_logs(log: Log) -> Option<DepositData> {
    let deposit_event_params = &[
        ParamType::FixedBytes(48), // pubkey
        ParamType::FixedBytes(32), // withdrawal_credentials
        ParamType::FixedBytes(8),  // amount
        ParamType::FixedBytes(96), // signature
        ParamType::FixedBytes(8),  // index
    ];
    let parsed_logs = parse_logs(log, deposit_event_params).unwrap();
    // Convert from tokens to Vec<u8>.
    let params = parsed_logs
        .into_iter()
        .map(|x| match x {
            Token::FixedBytes(v) => Some(v),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;

    // Event should have exactly 5 parameters.
    if params.len() == 5 {
        Some(DepositData {
            pubkey: PublicKey::from_bytes(&params[0]).unwrap(),
            withdrawal_credentials: H256::from_slice(&params[1]),
            amount: vec_to_u64_le(&params[2])?,
            signature: Signature::from_bytes(&params[3]).ok()?,
            // How is index used?
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Running tests using ganache-cli instance with config
    // from https://github.com/ChainSafe/lodestar#starting-private-eth1-chain

    #[test]
    fn test_get_current_block_number() {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        let block_number = w3.get_current_block_number();
        assert!(block_number.is_some());
    }

    #[test]
    fn test_get_block() {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        let block_hash = w3.get_block_hash_by_height(1);
        assert!(block_hash.is_some());
    }

    #[test]
    fn test_deposit_count() {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        let deposit_count = w3.get_deposit_count(None);
        assert_eq!(deposit_count, Some(0));
    }

    #[test]
    fn test_deposit_root() {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        let expected: H256 = [
            215, 10, 35, 71, 49, 40, 92, 104, 4, 194, 164, 245, 103, 17, 221, 184, 200, 44, 153,
            116, 15, 32, 120, 84, 137, 16, 40, 175, 52, 226, 126, 94,
        ]
        .into();
        let deposit_root = w3.get_deposit_root(None);
        assert_eq!(deposit_root, Some(expected));
    }

    #[test]
    fn test_deposit_contract_logs() {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        let logs = w3
            .get_deposit_logs_in_range(BlockNumber::Earliest, BlockNumber::Latest)
            .unwrap();

        for log in logs {
            assert!(parse_deposit_logs(log).is_some());
        }
    }

}
