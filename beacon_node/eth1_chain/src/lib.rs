use web3::futures::Future;
use web3::transports::Http;
use web3::contract::{Contract, Options};
use web3::types::*;
use web3::Web3;

/// Wrapper around web3 api.
pub struct Web3Object {
    _event_loop: web3::transports::EventLoopHandle,
    web3: web3::api::Web3<web3::transports::http::Http>,
}

impl Web3Object {
    /// Create a new Web3 object.
    pub fn new(endpoint: &str, _deposit_contract_address: String) -> Web3Object {
        let (_event_loop, transport) = Http::new(endpoint).unwrap();
        let web3 = Web3::new(transport);
        Web3Object {
            _event_loop,
            web3,
        }
    }

    /// Get block hash at given height.
    /// TODO: convert to async code.
    pub fn get_block_hash_by_height(&self, height: u64) -> Option<H256> {
        let block_future = self
            .web3
            .eth()
            .block(BlockId::Number(BlockNumber::Number(height)));
        let block = block_future.wait();
        block.ok().and_then(|x| x).and_then(|b| b.hash)
    }

    /// Queries deposit contract.
    pub fn query_deposit_contract(&self, address: Address) {
        let contract = Contract::from_json(
            self.web3.eth(),
            address,
            include_bytes!("deposit_contract.json"),
        )
        .unwrap();
        let data = contract.query("get_deposit_count", (), None, Options::default(), None);
        let deposit_root: Vec<u8> = data.wait().unwrap();
        println!("{:?}", deposit_root);
    }

    // Get contract logs
    // pub fn get_contract_logs(&self, _deposit_contract_address: String)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_block() {
        let web3_obj = Web3Object::new("http://localhost:8545", "Test".to_string());
        let block_hash = web3_obj.get_block_hash_by_height(1);
        assert!(block_hash.is_some());
    }

    #[test]
    fn deposit_contract_test() {
        let web3_obj = Web3Object::new("http://localhost:8545", "Test".to_string());
        let deposit_contract_address: Address = "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        web3_obj.query_deposit_contract(deposit_contract_address);
    }
}
