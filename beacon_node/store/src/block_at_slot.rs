use super::*;
use ssz::{Decode, DecodeError};

fn get_block_bytes<T: Store, E: EthSpec>(
    store: &T,
    root: Hash256,
) -> Result<Option<Vec<u8>>, Error> {
    store.get_bytes(BeaconBlock::<E>::db_column().into(), &root[..])
}

fn read_slot_from_block_bytes(bytes: &[u8]) -> Result<Slot, DecodeError> {
    let end = std::cmp::min(Slot::ssz_fixed_len(), bytes.len());

    Slot::from_ssz_bytes(&bytes[0..end])
}

fn read_parent_root_from_block_bytes(bytes: &[u8]) -> Result<Hash256, DecodeError> {
    let previous_bytes = Slot::ssz_fixed_len();
    let slice = bytes
        .get(previous_bytes..previous_bytes + Hash256::ssz_fixed_len())
        .ok_or_else(|| DecodeError::BytesInvalid("Not enough bytes.".to_string()))?;

    Hash256::from_ssz_bytes(slice)
}

pub fn get_block_at_preceeding_slot<T: Store, E: EthSpec>(
    store: &T,
    slot: Slot,
    start_root: Hash256,
) -> Result<Option<(Hash256, BeaconBlock<E>)>, Error> {
    Ok(
        match get_at_preceeding_slot::<_, E>(store, slot, start_root)? {
            Some((hash, bytes)) => Some((hash, BeaconBlock::<E>::from_ssz_bytes(&bytes)?)),
            None => None,
        },
    )
}

fn get_at_preceeding_slot<T: Store, E: EthSpec>(
    store: &T,
    slot: Slot,
    mut root: Hash256,
) -> Result<Option<(Hash256, Vec<u8>)>, Error> {
    loop {
        if let Some(bytes) = get_block_bytes::<_, E>(store, root)? {
            let this_slot = read_slot_from_block_bytes(&bytes)?;

            if this_slot == slot {
                break Ok(Some((root, bytes)));
            } else if this_slot < slot {
                break Ok(None);
            } else {
                root = read_parent_root_from_block_bytes(&bytes)?;
            }
        } else {
            break Ok(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode;
    use tree_hash::TreeHash;

    type BeaconBlock = types::BeaconBlock<MinimalEthSpec>;

    #[test]
    fn read_slot() {
        let spec = MinimalEthSpec::default_spec();

        let test_slot = |slot: Slot| {
            let mut block = BeaconBlock::empty(&spec);
            block.slot = slot;
            let bytes = block.as_ssz_bytes();
            assert_eq!(read_slot_from_block_bytes(&bytes).unwrap(), slot);
        };

        test_slot(Slot::new(0));
        test_slot(Slot::new(1));
        test_slot(Slot::new(42));
        test_slot(Slot::new(u64::max_value()));
    }

    #[test]
    fn bad_slot() {
        for i in 0..8 {
            assert!(read_slot_from_block_bytes(&vec![0; i]).is_err());
        }
    }

    #[test]
    fn read_parent_root() {
        let spec = MinimalEthSpec::default_spec();

        let test_root = |root: Hash256| {
            let mut block = BeaconBlock::empty(&spec);
            block.parent_root = root;
            let bytes = block.as_ssz_bytes();
            assert_eq!(read_parent_root_from_block_bytes(&bytes).unwrap(), root);
        };

        test_root(Hash256::random());
        test_root(Hash256::random());
        test_root(Hash256::random());
    }

    fn build_chain(
        store: &impl Store,
        slots: &[usize],
        spec: &ChainSpec,
    ) -> Vec<(Hash256, BeaconBlock)> {
        let mut blocks_and_roots: Vec<(Hash256, BeaconBlock)> = vec![];

        for (i, slot) in slots.iter().enumerate() {
            let mut block = BeaconBlock::empty(spec);
            block.slot = Slot::from(*slot);

            if i > 0 {
                block.parent_root = blocks_and_roots[i - 1].0;
            }

            let root = Hash256::from_slice(&block.tree_hash_root());

            store.put(&root, &block).unwrap();
            blocks_and_roots.push((root, block));
        }

        blocks_and_roots
    }

    #[test]
    fn chain_without_skips() {
        let n: usize = 10;
        let store = MemoryStore::open();
        let spec = MinimalEthSpec::default_spec();

        let slots: Vec<usize> = (0..n).collect();
        let blocks_and_roots = build_chain(&store, &slots, &spec);

        for source in 1..n {
            for target in 0..=source {
                let (source_root, _source_block) = &blocks_and_roots[source];
                let (target_root, target_block) = &blocks_and_roots[target];

                let (found_root, found_block) = store
                    .get_block_at_preceeding_slot(*source_root, target_block.slot)
                    .unwrap()
                    .unwrap();

                assert_eq!(found_root, *target_root);
                assert_eq!(found_block, *target_block);
            }
        }
    }

    #[test]
    fn chain_with_skips() {
        let store = MemoryStore::open();
        let spec = MinimalEthSpec::default_spec();

        let slots = vec![0, 1, 2, 5];

        let blocks_and_roots = build_chain(&store, &slots, &spec);

        // Valid slots
        for target in 0..3 {
            let (source_root, _source_block) = &blocks_and_roots[3];
            let (target_root, target_block) = &blocks_and_roots[target];

            let (found_root, found_block) = store
                .get_block_at_preceeding_slot(*source_root, target_block.slot)
                .unwrap()
                .unwrap();

            assert_eq!(found_root, *target_root);
            assert_eq!(found_block, *target_block);
        }

        // Slot that doesn't exist
        let (source_root, _source_block) = &blocks_and_roots[3];
        assert!(store
            .get_block_at_preceeding_slot::<MinimalEthSpec>(*source_root, Slot::new(3))
            .unwrap()
            .is_none());

        // Slot too high
        let (source_root, _source_block) = &blocks_and_roots[3];
        assert!(store
            .get_block_at_preceeding_slot::<MinimalEthSpec>(*source_root, Slot::new(3))
            .unwrap()
            .is_none());
    }
}
