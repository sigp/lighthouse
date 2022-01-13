use clap::ArgMatches;
use clap_utils::lcli_flags::{DEPOSIT_AMOUNT_FLAG, DEPOSIT_DATA_FLAG};
use clap_utils::{parse_required, parse_ssz_required};
use deposit_contract::{decode_eth1_tx_data, DEPOSIT_DATA_LEN};
use tree_hash::TreeHash;
use types::EthSpec;

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let rlp_bytes = parse_ssz_required::<Vec<u8>>(matches, DEPOSIT_DATA_FLAG)?;
    let amount = parse_required(matches, DEPOSIT_AMOUNT_FLAG)?;

    if rlp_bytes.len() != DEPOSIT_DATA_LEN {
        return Err(format!(
            "The given deposit-data is {} bytes, expected {}",
            rlp_bytes.len(),
            DEPOSIT_DATA_LEN
        ));
    }

    let (deposit_data, root) = decode_eth1_tx_data(&rlp_bytes, amount)
        .map_err(|e| format!("Invalid deposit data bytes: {:?}", e))?;

    let expected_root = deposit_data.tree_hash_root();
    if root != expected_root {
        return Err(format!(
            "Deposit data root is invalid. Expected {:?}, but got {:?}. Perhaps the amount is incorrect?",
            expected_root, root
        ));
    }

    Ok(())
}
