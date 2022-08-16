use account_utils::ZeroizeString;
use eth2::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::*;

#[derive(Serialize, Deserialize)]
pub struct CreateValidatorSpec {
    pub derivation_index: u32,
    pub voting_keystore_password: Option<ZeroizeString>,
    pub deposit_gwei: u64,
    pub eth1_withdrawal_address: Option<Address>,
    pub fee_recipient: Option<Address>,
    pub gas_limit: Option<u64>,
    pub builder_proposals: Option<bool>,
    pub enabled: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateSpec {
    pub mnemonic: String,
    pub validator_client_url: Option<SensitiveUrl>,
    pub validator_client_token_path: Option<PathBuf>,
    pub json_deposit_data_path: Option<PathBuf>,
    pub ignore_duplicates: bool,
    pub validators: Vec<CreateValidatorSpec>,
}
