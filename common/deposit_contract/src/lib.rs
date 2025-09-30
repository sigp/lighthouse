use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use alloy_primitives::FixedBytes;
use ssz::{Decode, DecodeError as SszDecodeError, Encode};
use tree_hash::TreeHash;
use types::{DepositData, Hash256, PublicKeyBytes, SignatureBytes};

pub use EncodeError as Error;

#[derive(Debug)]
pub enum EncodeError {
    AlloyCoreError(alloy_json_abi::Error),
    SerdeJsonError(serde_json::Error),
    DynAbiError(alloy_dyn_abi::Error),
    FunctionNotFound,
}

impl From<alloy_json_abi::Error> for EncodeError {
    fn from(e: alloy_json_abi::Error) -> EncodeError {
        EncodeError::AlloyCoreError(e)
    }
}

impl From<serde_json::Error> for EncodeError {
    fn from(e: serde_json::Error) -> EncodeError {
        EncodeError::SerdeJsonError(e)
    }
}

impl From<alloy_dyn_abi::Error> for EncodeError {
    fn from(e: alloy_dyn_abi::Error) -> EncodeError {
        EncodeError::DynAbiError(e)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    AlloyCoreError(alloy_json_abi::Error),
    SszDecodeError(SszDecodeError),
    SerdeJsonError(serde_json::Error),
    DynAbiError(alloy_dyn_abi::Error),
    FunctionNotFound,
    MissingField,
    UnableToGetBytes,
    MissingToken,
    InadequateBytes,
}

impl From<alloy_json_abi::Error> for DecodeError {
    fn from(e: alloy_json_abi::Error) -> DecodeError {
        DecodeError::AlloyCoreError(e)
    }
}

impl From<serde_json::Error> for DecodeError {
    fn from(e: serde_json::Error) -> DecodeError {
        DecodeError::SerdeJsonError(e)
    }
}

impl From<alloy_dyn_abi::Error> for DecodeError {
    fn from(e: alloy_dyn_abi::Error) -> DecodeError {
        DecodeError::DynAbiError(e)
    }
}

impl From<SszDecodeError> for DecodeError {
    fn from(e: SszDecodeError) -> DecodeError {
        DecodeError::SszDecodeError(e)
    }
}

pub const CONTRACT_DEPLOY_GAS: usize = 4_000_000;
pub const DEPOSIT_GAS: usize = 400_000;
pub const ABI: &[u8] = include_bytes!("../contracts/v0.12.1_validator_registration.json");
pub const BYTECODE: &[u8] = include_bytes!("../contracts/v0.12.1_validator_registration.bytecode");
pub const DEPOSIT_DATA_LEN: usize = 420; // lol

pub mod testnet {
    pub const ABI: &[u8] =
        include_bytes!("../contracts/v0.12.1_testnet_validator_registration.json");
    pub const BYTECODE: &[u8] =
        include_bytes!("../contracts/v0.12.1_testnet_validator_registration.bytecode");
}

pub fn encode_eth1_tx_data(deposit_data: &DepositData) -> Result<Vec<u8>, EncodeError> {
    let params = vec![
        DynSolValue::Bytes(deposit_data.pubkey.as_ssz_bytes()),
        DynSolValue::Bytes(deposit_data.withdrawal_credentials.as_ssz_bytes()),
        DynSolValue::Bytes(deposit_data.signature.as_ssz_bytes()),
        DynSolValue::FixedBytes(
            FixedBytes::<32>::from_slice(&deposit_data.tree_hash_root().as_ssz_bytes()),
            32,
        ),
    ];

    let abi: JsonAbi = serde_json::from_slice(ABI)?;
    let functions = abi
        .function("deposit")
        .ok_or(EncodeError::FunctionNotFound)?;
    let function = &functions.first().ok_or(EncodeError::FunctionNotFound)?; // Get the first (and likely only) deposit function

    Ok(function.abi_encode_input(&params)?)
}

pub fn decode_eth1_tx_data(
    bytes: &[u8],
    amount: u64,
) -> Result<(DepositData, Hash256), DecodeError> {
    let abi: JsonAbi = serde_json::from_slice(ABI)?;
    let functions = abi
        .function("deposit")
        .ok_or(DecodeError::FunctionNotFound)?;
    let function = &functions.first().ok_or(DecodeError::FunctionNotFound)?;

    let input_data = bytes.get(4..).ok_or(DecodeError::InadequateBytes)?;
    let mut tokens = function.abi_decode_input(input_data)?;

    macro_rules! decode_token {
        ($type: ty) => {{
            let token = tokens.pop().ok_or(DecodeError::MissingToken)?;
            let bytes_data = match token {
                DynSolValue::Bytes(b) => b,
                DynSolValue::FixedBytes(b, _) => b.to_vec(),
                _ => return Err(DecodeError::UnableToGetBytes),
            };
            <$type>::from_ssz_bytes(&bytes_data)?
        }};
    }

    let root = decode_token!(Hash256);

    let deposit_data = DepositData {
        amount,
        signature: decode_token!(SignatureBytes),
        withdrawal_credentials: decode_token!(Hash256),
        pubkey: decode_token!(PublicKeyBytes),
    };

    Ok((deposit_data, root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        ChainSpec, EthSpec, Keypair, MinimalEthSpec, Signature,
        test_utils::generate_deterministic_keypair,
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
