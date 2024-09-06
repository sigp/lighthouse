use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use ssz::{Decode, DecodeError as SszDecodeError, Encode};
use tree_hash::TreeHash;
use types::{DepositData, Hash256};

#[derive(Debug)]
pub enum Error {
    SerdeJson(serde_json::Error),
    Alloy(alloy_dyn_abi::Error),
    SszDecodeError(SszDecodeError),
    MissingField,
    UnableToGetBytes,
    MissingDynSolValue,
    MissingDepositFunction,
    InadequateBytes,
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJson(e)
    }
}

impl From<alloy_dyn_abi::Error> for Error {
    fn from(e: alloy_dyn_abi::Error) -> Self {
        Self::Alloy(e)
    }
}

pub const CONTRACT_DEPLOY_GAS: usize = 4_000_000;
pub const DEPOSIT_GAS: usize = 400_000;
pub const ABI: &str = include_str!("../contracts/v0.12.1_validator_registration.json");
pub const BYTECODE: &str = include_str!("../contracts/v0.12.1_validator_registration.bytecode");
pub const DEPOSIT_DATA_LEN: usize = 420; // lol

pub mod testnet {
    pub const ABI: &str = include_str!("../contracts/v0.12.1_testnet_validator_registration.json");
    pub const BYTECODE: &str =
        include_str!("../contracts/v0.12.1_testnet_validator_registration.bytecode");
}

pub fn encode_eth1_tx_data(deposit_data: &DepositData) -> Result<Vec<u8>, Error> {
    let params = vec![
        DynSolValue::Bytes(deposit_data.pubkey.as_ssz_bytes()),
        DynSolValue::Bytes(deposit_data.withdrawal_credentials.as_ssz_bytes()),
        DynSolValue::Bytes(deposit_data.signature.as_ssz_bytes()),
        DynSolValue::FixedBytes(deposit_data.tree_hash_root(), 32),
    ];

    // Here we make an assumption that the `crate::testnet::ABI` has a superset of the features of
    // the crate::ABI`.
    let abi: JsonAbi = serde_json::from_str(ABI)?;
    let function = abi
        .function("deposit")
        .and_then(|funcs| funcs.first().clone())
        .ok_or(Error::MissingDepositFunction)?;
    function.abi_encode_input(&params).map_err(Into::into)
}

pub fn decode_eth1_tx_data(bytes: &[u8], amount: u64) -> Result<(DepositData, Hash256), Error> {
    let abi: JsonAbi = serde_json::from_str(ABI)?;
    let function = abi
        .function("deposit")
        .and_then(|funcs| funcs.first().clone())
        .ok_or(Error::MissingDepositFunction)?;
    let validate = true;
    let mut tokens =
        function.abi_decode_input(bytes.get(4..).ok_or(Error::InadequateBytes)?, validate)?;

    println!("{:?}", tokens);

    fn decode_token<T: Decode>(
        tokens: &mut Vec<DynSolValue>,
        token_decoder: impl FnOnce(&DynSolValue) -> Option<&[u8]>,
    ) -> Result<T, Error> {
        let token = tokens.pop().ok_or_else(|| Error::MissingDynSolValue)?;
        T::from_ssz_bytes(token_decoder(&token).ok_or_else(|| Error::UnableToGetBytes)?)
            .map_err(Error::SszDecodeError)
    }

    let root = decode_token(&mut tokens, |token| {
        token.as_fixed_bytes().map(|(bytes, _length)| bytes)
    })?;

    let deposit_data = DepositData {
        amount,
        signature: decode_token(&mut tokens, DynSolValue::as_bytes)?,
        withdrawal_credentials: decode_token(&mut tokens, DynSolValue::as_bytes)?,
        pubkey: decode_token(&mut tokens, DynSolValue::as_bytes)?,
    };

    Ok((deposit_data, root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        test_utils::generate_deterministic_keypair, ChainSpec, EthSpec, Keypair, MinimalEthSpec,
        Signature,
    };

    type E = MinimalEthSpec;

    fn get_deposit(keypair: Keypair, spec: &ChainSpec) -> DepositData {
        let mut deposit_data = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials: Hash256::from_slice(&[42; 32]),
            amount: u64::MAX,
            signature: Signature::empty().into(),
        };
        deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);
        deposit_data
    }

    #[test]
    fn round_trip() {
        let spec = &E::default_spec();

        let keypair = generate_deterministic_keypair(42);
        let original = get_deposit(keypair, spec);

        let data = encode_eth1_tx_data(&original).expect("should produce tx data");

        assert_eq!(
            data.len(),
            DEPOSIT_DATA_LEN,
            "bytes should be correct length"
        );

        let (decoded, root) = decode_eth1_tx_data(&data, original.amount).expect("should decode");

        assert_eq!(decoded, original, "decoded should match original");
        assert_eq!(
            root,
            original.tree_hash_root(),
            "decode root should match original root"
        );
    }
}
