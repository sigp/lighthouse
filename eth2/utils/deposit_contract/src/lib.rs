use ethabi::{Contract, Token};
use ssz::Encode;
use tree_hash::TreeHash;
use types::DepositData;

pub use ethabi::Error;

pub const CONTRACT_DEPLOY_GAS: usize = 4_000_000;
pub const DEPOSIT_GAS: usize = 4_000_000;
pub const ABI: &[u8] = include_bytes!("../contracts/v0.9.2_validator_registration.json");
pub const BYTECODE: &[u8] = include_bytes!("../contracts/v0.9.2_validator_registration.bytecode");

pub mod testnet {
    pub const ABI: &[u8] =
        include_bytes!("../contracts/v0.9.2_testnet_validator_registration.json");
    pub const BYTECODE: &[u8] =
        include_bytes!("../contracts/v0.9.2_testnet_validator_registration.bytecode");
}

pub fn eth1_tx_data(deposit_data: &DepositData) -> Result<Vec<u8>, Error> {
    let params = vec![
        Token::Bytes(deposit_data.pubkey.as_ssz_bytes()),
        Token::Bytes(deposit_data.withdrawal_credentials.as_ssz_bytes()),
        Token::Bytes(deposit_data.signature.as_ssz_bytes()),
        Token::FixedBytes(deposit_data.tree_hash_root().as_ssz_bytes()),
    ];

    // Here we make an assumption that the `crate::testnet::ABI` has a superset of the features of
    // the crate::ABI`.
    let abi = Contract::load(ABI)?;
    let function = abi.function("deposit")?;
    function.encode_input(&params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        test_utils::generate_deterministic_keypair, ChainSpec, EthSpec, Hash256, Keypair,
        MinimalEthSpec, Signature,
    };

    type E = MinimalEthSpec;

    fn get_deposit(keypair: Keypair, spec: &ChainSpec) -> DepositData {
        let mut deposit_data = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials: Hash256::from_slice(&[42; 32]),
            amount: u64::max_value(),
            signature: Signature::empty_signature().into(),
        };
        deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);
        deposit_data
    }

    #[test]
    fn basic() {
        let spec = &E::default_spec();

        let keypair = generate_deterministic_keypair(42);
        let deposit = get_deposit(keypair.clone(), spec);

        let data = eth1_tx_data(&deposit).expect("should produce tx data");

        assert_eq!(data.len(), 420, "bytes should be correct length");
    }
}
