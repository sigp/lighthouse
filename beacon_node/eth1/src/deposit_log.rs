use super::http::Log;
use ssz::Decode;
use types::{DepositData, Hash256, PublicKeyBytes, SignatureBytes};

/// The following constants define the layout of bytes in the deposit contract `DepositEvent`. The
/// event bytes are formatted according to the  Ethereum ABI.
const PUBKEY_START: usize = 192;
const PUBKEY_LEN: usize = 48;
const CREDS_START: usize = PUBKEY_START + 64 + 32;
const CREDS_LEN: usize = 32;
const AMOUNT_START: usize = CREDS_START + 32 + 32;
const AMOUNT_LEN: usize = 8;
const SIG_START: usize = AMOUNT_START + 32 + 32;
const SIG_LEN: usize = 96;
const INDEX_START: usize = SIG_START + 96 + 32;
const INDEX_LEN: usize = 8;

/// A fully parsed eth1 deposit contract log.
#[derive(Debug, PartialEq, Clone)]
pub struct DepositLog {
    pub deposit_data: DepositData,
    /// The block number of the log that included this `DepositData`.
    pub block_number: u64,
    /// The index included with the deposit log.
    pub index: u64,
}

impl DepositLog {
    /// Attempts to parse a raw `Log` from the deposit contract into a `DepositLog`.
    pub fn from_log(log: &Log) -> Result<Self, String> {
        let bytes = &log.data;

        let pubkey = bytes
            .get(PUBKEY_START..PUBKEY_START + PUBKEY_LEN)
            .ok_or_else(|| "Insufficient bytes for pubkey".to_string())?;
        let withdrawal_credentials = bytes
            .get(CREDS_START..CREDS_START + CREDS_LEN)
            .ok_or_else(|| "Insufficient bytes for withdrawal credential".to_string())?;
        let amount = bytes
            .get(AMOUNT_START..AMOUNT_START + AMOUNT_LEN)
            .ok_or_else(|| "Insufficient bytes for amount".to_string())?;
        let signature = bytes
            .get(SIG_START..SIG_START + SIG_LEN)
            .ok_or_else(|| "Insufficient bytes for signature".to_string())?;
        let index = bytes
            .get(INDEX_START..INDEX_START + INDEX_LEN)
            .ok_or_else(|| "Insufficient bytes for index".to_string())?;

        let deposit_data = DepositData {
            pubkey: PublicKeyBytes::from_ssz_bytes(pubkey)
                .map_err(|e| format!("Invalid index ssz: {:?}", e))?,
            withdrawal_credentials: Hash256::from_ssz_bytes(withdrawal_credentials)
                .map_err(|e| format!("Invalid withdrawal_credentials ssz: {:?}", e))?,
            amount: u64::from_ssz_bytes(amount)
                .map_err(|e| format!("Invalid amount ssz: {:?}", e))?,
            signature: SignatureBytes::from_ssz_bytes(signature)
                .map_err(|e| format!("Invalid signature ssz: {:?}", e))?,
        };

        Ok(DepositLog {
            deposit_data,
            block_number: log.block_number,
            index: u64::from_ssz_bytes(index).map_err(|e| format!("Invalid index ssz: {:?}", e))?,
        })
    }
}
