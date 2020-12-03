use super::http::Log;
use ssz::Decode;
use state_processing::per_block_processing::signature_sets::deposit_pubkey_signature_message;
use types::{ChainSpec, DepositData, Hash256, PublicKeyBytes, SignatureBytes};

pub use eth2::lighthouse::DepositLog;

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

impl Log {
    /// Attempts to parse a raw `Log` from the deposit contract into a `DepositLog`.
    pub fn to_deposit_log(&self, spec: &ChainSpec) -> Result<DepositLog, String> {
        let bytes = &self.data;

        let pubkey = bytes
            .get(PUBKEY_START..PUBKEY_START + PUBKEY_LEN)
            .ok_or("Insufficient bytes for pubkey")?;
        let withdrawal_credentials = bytes
            .get(CREDS_START..CREDS_START + CREDS_LEN)
            .ok_or("Insufficient bytes for withdrawal credential")?;
        let amount = bytes
            .get(AMOUNT_START..AMOUNT_START + AMOUNT_LEN)
            .ok_or("Insufficient bytes for amount")?;
        let signature = bytes
            .get(SIG_START..SIG_START + SIG_LEN)
            .ok_or("Insufficient bytes for signature")?;
        let index = bytes
            .get(INDEX_START..INDEX_START + INDEX_LEN)
            .ok_or("Insufficient bytes for index")?;

        let deposit_data = DepositData {
            pubkey: PublicKeyBytes::from_ssz_bytes(pubkey)
                .map_err(|e| format!("Invalid pubkey ssz: {:?}", e))?,
            withdrawal_credentials: Hash256::from_ssz_bytes(withdrawal_credentials)
                .map_err(|e| format!("Invalid withdrawal_credentials ssz: {:?}", e))?,
            amount: u64::from_ssz_bytes(amount)
                .map_err(|e| format!("Invalid amount ssz: {:?}", e))?,
            signature: SignatureBytes::from_ssz_bytes(signature)
                .map_err(|e| format!("Invalid signature ssz: {:?}", e))?,
        };

        let signature_is_valid = deposit_pubkey_signature_message(&deposit_data, spec)
            .map_or(false, |(public_key, signature, msg)| {
                signature.verify(&public_key, msg)
            });

        Ok(DepositLog {
            deposit_data,
            block_number: self.block_number,
            index: u64::from_ssz_bytes(index).map_err(|e| format!("Invalid index ssz: {:?}", e))?,
            signature_is_valid,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::http::Log;
    use types::{EthSpec, MainnetEthSpec};

    /// The data from a deposit event, using the v0.8.3 version of the deposit contract.
    pub const EXAMPLE_LOG: &[u8] = &[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 167, 108, 6, 69, 88, 17, 3, 51, 6, 4, 158, 232, 82,
        248, 218, 2, 71, 219, 55, 102, 86, 125, 136, 203, 36, 77, 64, 213, 43, 52, 175, 154, 239,
        50, 142, 52, 201, 77, 54, 239, 0, 229, 22, 46, 139, 120, 62, 240, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 64, 89, 115, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 140, 74, 175, 158, 209, 20, 206,
        30, 63, 215, 238, 113, 60, 132, 216, 211, 100, 186, 202, 71, 34, 200, 160, 225, 212, 213,
        119, 88, 51, 80, 101, 74, 2, 45, 78, 153, 12, 192, 44, 51, 77, 40, 10, 72, 246, 34, 193,
        187, 22, 95, 4, 211, 245, 224, 13, 162, 21, 163, 54, 225, 22, 124, 3, 56, 14, 81, 122, 189,
        149, 250, 251, 159, 22, 77, 94, 157, 197, 196, 253, 110, 201, 88, 193, 246, 136, 226, 221,
        18, 113, 232, 105, 100, 114, 103, 237, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn can_parse_example_log() {
        let log = Log {
            block_number: 42,
            data: EXAMPLE_LOG.to_vec(),
        };
        log.to_deposit_log(&MainnetEthSpec::default_spec())
            .expect("should decode log");
    }
}
