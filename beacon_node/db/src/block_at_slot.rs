use super::*;
use ssz::{Decode, DecodeError};

fn get_block_bytes<T: Store>(store: &T, root: Hash256) -> Result<Option<Vec<u8>>, Error> {
    store.get_bytes(BeaconBlock::db_column().into(), &root[..])
}

fn read_slot_from_block_bytes(bytes: &[u8]) -> Result<Slot, DecodeError> {
    let end = std::cmp::min(Slot::ssz_fixed_len(), bytes.len());

    Slot::from_ssz_bytes(&bytes[0..end])
}

fn read_previous_block_root_from_block_bytes(bytes: &[u8]) -> Result<Hash256, DecodeError> {
    let previous_bytes = Slot::ssz_fixed_len();
    let slice = bytes
        .get(previous_bytes..previous_bytes + Hash256::ssz_fixed_len())
        .ok_or_else(|| DecodeError::BytesInvalid("Not enough bytes.".to_string()))?;

    Hash256::from_ssz_bytes(slice)
}

pub fn get_block_at_preceeding_slot<T: Store>(
    store: &T,
    slot: Slot,
    start_root: Hash256,
) -> Result<Option<(Hash256, BeaconBlock)>, Error> {
    let mut root = start_root;

    loop {
        if let Some(bytes) = get_block_bytes(store, root)? {
            let this_slot = read_slot_from_block_bytes(&bytes)?;

            if this_slot == slot {
                let block = BeaconBlock::from_ssz_bytes(&bytes)?;
                break Ok(Some((root, block)));
            } else if this_slot < slot {
                break Ok(None);
            } else {
                root = read_previous_block_root_from_block_bytes(&bytes)?;
            }
        } else {
            break Ok(None);
        }
    }
}
