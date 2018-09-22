/*
 * Collection of helper functions used in the state transition modules
 */
use super::active_state::ActiveState;
use super::block::Block;
use super::chain_config::ChainConfig;
use super::utils::errors::ParameterError;
use super::utils::types::Hash256;

/*
   pub fn get_signed_parent_hashes(
   active_state: &ActiveState,
   block: &Block,
   attestation: &AttestationRecord,
   chain_config: &ChainConfig)
   -> Vec<Hash256> {
   }
   */

pub fn get_block_hash(
    active_state_recent_block_hashes: &Vec<Hash256>,
    current_block_slot: &u64,
    slot: &u64,
    cycle_length: &u64, // convert from standard u8
) -> Result<Hash256, ParameterError> {
    // active_state must have at 2*cycle_length hashes
    assert_error!(
        active_state_recent_block_hashes.len() as u64 == cycle_length * 2,
        ParameterError::InvalidInput(String::from(
            "active state has incorrect number of block hashes"
        ))
    );

    let state_start_slot = (*current_block_slot)
        .checked_sub(cycle_length * 2)
        .unwrap_or(0);

    assert_error!(
        (state_start_slot <= *slot) && (*slot < *current_block_slot),
        ParameterError::InvalidInput(String::from("incorrect slot number"))
    );

    let index = 2 * cycle_length + (*slot) - *current_block_slot; // should always be positive
    Ok(active_state_recent_block_hashes[index as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_block_hash() {
        let block_slot: u64 = 10;
        let slot: u64 = 3;
        let cycle_length: u64 = 8;

        let mut block_hashes: Vec<Hash256> = Vec::new();
        for _i in 0..2 * cycle_length {
            block_hashes.push(Hash256::random());
        }

        let result = get_block_hash(&block_hashes, &block_slot, &slot, &cycle_length).unwrap();

        assert_eq!(
            result,
            block_hashes[(2 * cycle_length + slot - block_slot) as usize]
        );

        println!("{:?}", result);
    }
}
