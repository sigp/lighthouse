use parking_lot::RwLock;
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::iter::FromIterator;
use types::{BeaconBlock, EthSpec, Hash256, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    MismatchingLengths { roots_len: usize, slots_len: usize },
}

#[derive(Encode, Decode)]
pub struct SszHeadTracker {
    roots: Vec<Hash256>,
    slots: Vec<Slot>,
}

#[derive(Default, Debug)]
pub struct HeadTracker(RwLock<HashMap<Hash256, Slot>>);

impl HeadTracker {
    pub fn register_block<E: EthSpec>(&self, block_root: Hash256, block: &BeaconBlock<E>) {
        let mut map = self.0.write();

        map.remove(&block.parent_root);
        map.insert(block_root, block.slot);
    }

    pub fn heads(&self) -> Vec<(Hash256, Slot)> {
        self.0
            .read()
            .iter()
            .map(|(root, slot)| (*root, *slot))
            .collect()
    }

    pub fn to_ssz_container(&self) -> SszHeadTracker {
        let (roots, slots) = self
            .0
            .read()
            .iter()
            .map(|(hash, slot)| (*hash, *slot))
            .unzip();

        SszHeadTracker { roots, slots }
    }

    pub fn from_ssz_container(ssz_container: &SszHeadTracker) -> Result<Self, Error> {
        let roots_len = ssz_container.roots.len();
        let slots_len = ssz_container.slots.len();

        if roots_len != slots_len {
            return Err(Error::MismatchingLengths {
                roots_len,
                slots_len,
            });
        } else {
            let map = HashMap::from_iter(
                ssz_container
                    .roots
                    .iter()
                    .zip(ssz_container.slots.iter())
                    .map(|(root, slot)| (*root, *slot)),
            );

            Ok(Self(RwLock::new(map)))
        }
    }
}

impl PartialEq<HeadTracker> for HeadTracker {
    fn eq(&self, other: &HeadTracker) -> bool {
        *self.0.read() == *other.0.read()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ssz::{Decode, Encode};
    use types::MainnetEthSpec;

    type E = MainnetEthSpec;

    #[test]
    fn block_add() {
        let spec = &E::default_spec();

        let head_tracker = HeadTracker::default();

        for i in 0..16 {
            let mut block = BeaconBlock::empty(spec);
            let block_root = Hash256::from_low_u64_be(i);

            block.slot = Slot::new(i);
            block.parent_root = if i == 0 {
                Hash256::random()
            } else {
                Hash256::from_low_u64_be(i - 1)
            };

            head_tracker.register_block::<E>(block_root, &block);
        }

        assert_eq!(
            head_tracker.heads(),
            vec![(Hash256::from_low_u64_be(15), Slot::new(15))],
            "should only have one head"
        );

        let mut block = BeaconBlock::empty(spec);
        let block_root = Hash256::from_low_u64_be(42);
        block.slot = Slot::new(15);
        block.parent_root = Hash256::from_low_u64_be(14);
        head_tracker.register_block::<E>(block_root, &block);

        let heads = head_tracker.heads();

        assert_eq!(heads.len(), 2, "should only have two heads");
        assert!(
            heads
                .iter()
                .any(|(root, slot)| *root == Hash256::from_low_u64_be(15) && *slot == Slot::new(15)),
            "should contain first head"
        );
        assert!(
            heads
                .iter()
                .any(|(root, slot)| *root == Hash256::from_low_u64_be(42) && *slot == Slot::new(15)),
            "should contain second head"
        );
    }

    #[test]
    fn empty_round_trip() {
        let non_empty = HeadTracker::default();
        for i in 0..16 {
            non_empty.0.write().insert(Hash256::random(), Slot::new(i));
        }
        let bytes = non_empty.to_ssz_container().as_ssz_bytes();

        assert_eq!(
            HeadTracker::from_ssz_container(
                &SszHeadTracker::from_ssz_bytes(&bytes).expect("should decode")
            ),
            Ok(non_empty),
            "non_empty should pass round trip"
        );
    }

    #[test]
    fn non_empty_round_trip() {
        let non_empty = HeadTracker::default();
        for i in 0..16 {
            non_empty.0.write().insert(Hash256::random(), Slot::new(i));
        }
        let bytes = non_empty.to_ssz_container().as_ssz_bytes();

        assert_eq!(
            HeadTracker::from_ssz_container(
                &SszHeadTracker::from_ssz_bytes(&bytes).expect("should decode")
            ),
            Ok(non_empty),
            "non_empty should pass round trip"
        );
    }

    #[test]
    fn bad_length() {
        let container = SszHeadTracker {
            roots: vec![Hash256::random()],
            slots: vec![],
        };
        let bytes = container.as_ssz_bytes();

        assert_eq!(
            HeadTracker::from_ssz_container(
                &SszHeadTracker::from_ssz_bytes(&bytes).expect("should decode")
            ),
            Err(Error::MismatchingLengths {
                roots_len: 1,
                slots_len: 0
            }),
            "should fail decoding with bad lengths"
        );
    }
}
