extern crate types;

use types::{BeaconBlock, ChainConfig};

pub enum BlockProductionErorr {
    Cats,
}

pub fn produce_block_at_slot(
    slot: u64,
    parent_block: &BeaconBlock,
    randao_reveal: Hash256,
    pow_chain_reference: Hash256,
    config: &ChainConfig,
) -> Result<BeaconBlock, BlockProductionErorr> {
    Ok(BeaconBlock {
        slot,
        randao_reveal,
        pow_chain_reference,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
