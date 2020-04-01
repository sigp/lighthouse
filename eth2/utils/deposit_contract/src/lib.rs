use ethabi::{Contract, Token};
use ssz::{Decode, DecodeError as SszDecodeError, Encode};
use tree_hash::TreeHash;
use types::{DepositData, Hash256, PublicKeyBytes, SignatureBytes};

pub use ethabi::Error;

#[derive(Debug)]
pub enum DecodeError {
    EthabiError(ethabi::Error),
    SszDecodeError(SszDecodeError),
    MissingField,
    UnableToGetBytes,
    MissingToken,
    InadequateBytes,
}

impl From<ethabi::Error> for DecodeError {
    fn from(e: ethabi::Error) -> DecodeError {
        DecodeError::EthabiError(e)
    }
}

pub const CONTRACT_DEPLOY_GAS: usize = 4_000_000;
pub const DEPOSIT_GAS: usize = 4_000_000;
pub const ABI: &[u8] = include_bytes!("../contracts/v0.11.1_validator_registration.json");
pub const BYTECODE: &[u8] = include_bytes!("../contracts/v0.11.1_validator_registration.bytecode");
pub const DEPOSIT_DATA_LEN: usize = 420; // lol

pub mod testnet {
    pub const ABI: &[u8] =
        include_bytes!("../contracts/v0.11.1_testnet_validator_registration.json");
    pub const BYTECODE: &[u8] =
        include_bytes!("../contracts/v0.11.1_testnet_validator_registration.bytecode");
}

pub fn encode_eth1_tx_data(deposit_data: &DepositData) -> Result<Vec<u8>, Error> {
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

pub fn decode_eth1_tx_data(
    bytes: &[u8],
    amount: u64,
) -> Result<(DepositData, Hash256), DecodeError> {
    let abi = Contract::load(ABI)?;
    let function = abi.function("deposit")?;
    let mut tokens =
        function.decode_input(bytes.get(4..).ok_or_else(|| DecodeError::InadequateBytes)?)?;

    macro_rules! decode_token {
        ($type: ty, $to_fn: ident) => {
            <$type>::from_ssz_bytes(
                &tokens
                    .pop()
                    .ok_or_else(|| DecodeError::MissingToken)?
                    .$to_fn()
                    .ok_or_else(|| DecodeError::UnableToGetBytes)?,
            )
            .map_err(DecodeError::SszDecodeError)?
        };
    };

    let root = decode_token!(Hash256, to_fixed_bytes);

    let deposit_data = DepositData {
        amount,
        signature: decode_token!(SignatureBytes, to_bytes),
        withdrawal_credentials: decode_token!(Hash256, to_bytes),
        pubkey: decode_token!(PublicKeyBytes, to_bytes),
    };

    Ok((deposit_data, root))
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
