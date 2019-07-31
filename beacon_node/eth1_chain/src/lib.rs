use web3::contract::{Contract, Options};
use web3::futures::Future;
use web3::transports::WebSocket;
use web3::types::FilterBuilder;
use web3::types::*;
use web3::Web3;

// Keccak256 hash of "DepositEvent" in bytes.
const DEPOSIT_EVENT_HASH: &str =
    "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";

/// Deposit contract config.
#[derive(Debug, Clone)]
pub struct DepositContract {
    /// Address at which deployed in eth1 chain.
    pub address: Address,
    /// Path for contract abi.
    pub abi_path: String,
}

/// Wrapper around web3 api.
pub struct Web3Object {
    _event_loop: web3::transports::EventLoopHandle,
    web3: web3::api::Web3<web3::transports::ws::WebSocket>,
}

impl Web3Object {
    /// Create a new Web3 object.
    pub fn new(endpoint: &str, _deposit_contract_address: String) -> Web3Object {
        let (event_loop, transport) = WebSocket::new(endpoint).unwrap();
        let web3 = Web3::new(transport);
        Web3Object {
            _event_loop: event_loop,
            web3,
        }
    }

    /// Get block hash at given height.
    pub fn get_block_hash_by_height(&self, height: u64) -> Option<H256> {
        let block_future = self
            .web3
            .eth()
            .block(BlockId::Number(BlockNumber::Number(height)));
        let block = block_future.wait();
        block.ok().and_then(|x| x).and_then(|b| b.hash)
    }

    /// Queries deposit contract for `deposit_count`.
    pub fn query_deposit_count(&self, deposit_contract: DepositContract) -> Vec<u8> {
        let contract = Contract::from_json(
            self.web3.eth(),
            deposit_contract.address,
            include_bytes!("deposit_contract.json"), // Load from deposit_contract.abi
        )
        .unwrap();
        let data = contract.query("get_deposit_count", (), None, Options::default(), None);
        let deposit_count: Vec<u8> = data.wait().unwrap();
        deposit_count
    }

    /// Queries deposit contract for `deposit_root`.
    pub fn query_deposit_root(&self, deposit_contract: DepositContract) -> Vec<u8> {
        let contract = Contract::from_json(
            self.web3.eth(),
            deposit_contract.address,
            include_bytes!("deposit_contract.json"), // Load from deposit_contract.abi
        )
        .unwrap();
        let data = contract.query("get_hash_tree_root", (), None, Options::default(), None);
        let deposit_root: Vec<u8> = data.wait().unwrap();
        deposit_root
    }

    /// Subscribe to `DepositEvent`. Returns a `eth_subscription` future.
    /// TODO: write tests.
    pub fn get_contract_logs(&self, address: Address) -> impl Future {
        let filter = FilterBuilder::default()
            .address(vec![address])
            .topics(
                Some(vec![DEPOSIT_EVENT_HASH.parse().unwrap()]),
                None,
                None,
                None,
            )
            .from_block(BlockNumber::Earliest)
            .to_block(BlockNumber::Latest)
            .build();

        self.web3.eth_subscribe().subscribe_logs(filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_block() {
        let web3_obj = Web3Object::new("ws://localhost:8545", "Test".to_string());
        let block_hash = web3_obj.get_block_hash_by_height(1);
        assert!(block_hash.is_some());
    }

    #[test]
    fn deposit_count_test() {
        let web3_obj = Web3Object::new("ws://localhost:8545", "Test".to_string());
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = DepositContract {
            address: deposit_contract_address,
            abi_path: "deposit_contract.json".into(),
        };
        let deposit_count = web3_obj.query_deposit_count(deposit_contract);
        assert_eq!(deposit_count, vec![0; 8]);
    }

    #[test]
    fn deposit_root_test() {
        let web3_obj = Web3Object::new("ws://localhost:8545", "Test".to_string());
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = DepositContract {
            address: deposit_contract_address,
            abi_path: "deposit_contract.json".into(),
        };
        let expected = vec![
            215, 10, 35, 71, 49, 40, 92, 104, 4, 194, 164, 245, 103, 17, 221, 184, 200, 44, 153,
            116, 15, 32, 120, 84, 137, 16, 40, 175, 52, 226, 126, 94,
        ];
        let deposit_root = web3_obj.query_deposit_root(deposit_contract);
        assert_eq!(expected, deposit_root);
    }

}
