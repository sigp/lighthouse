use bls::{PublicKeyBytes, SignatureBytes};
use ethabi::{decode, ParamType, Token};
use types::DepositData;
use web3::types::*;

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
pub fn parse_logs(log: Log, types: &[ParamType]) -> Option<Vec<Token>> {
    decode(types, &log.data.0).ok()
}

/// Parse logs from deposit contract.
pub fn parse_deposit_logs(log: Log) -> Option<(u64, DepositData)> {
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
        Some((
            vec_to_u64_le(&params[4])?,
            DepositData {
                pubkey: PublicKeyBytes::from_bytes(&params[0]).unwrap(),
                withdrawal_credentials: H256::from_slice(&params[1]),
                amount: vec_to_u64_le(&params[2])?,
                signature: SignatureBytes::from_bytes(&params[3]).ok()?,
            },
        ))
    } else {
        None
    }
}
