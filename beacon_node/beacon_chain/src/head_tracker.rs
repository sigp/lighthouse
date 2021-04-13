use parking_lot::RwLock;
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use types::{Hash256, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    MismatchingLengths { roots_len: usize, slots_len: usize },
}

/// Maintains a list of `BeaconChain` head block roots and slots.
///
/// Each time a new block is imported, it should be applied to the `Self::register_block` function.
/// In order for this struct to be effective, every single block that is imported must be
/// registered here.
#[derive(Default, Debug)]
pub struct HeadTracker(pub RwLock<HashMap<Hash256, Slot>>);

impl HeadTracker {
    /// Register a block with `Self`, so it may or may not be included in a `Self::heads` call.
    ///
    /// This function assumes that no block is imported without its parent having already been
    /// imported. It cannot detect an error if this is not the case, it is the responsibility of
    /// the upstream user.
    pub fn register_block(&self, block_root: Hash256, parent_root: Hash256, slot: Slot) {
        let mut map = self.0.write();
        map.remove(&parent_root);
        map.insert(block_root, slot);
    }

    /// Returns true iff `block_root` is a recognized head.
    pub fn contains_head(&self, block_root: Hash256) -> bool {
        self.0.read().contains_key(&block_root)
    }

    /// Returns the list of heads in the chain.
    pub fn heads(&self) -> Vec<(Hash256, Slot)> {
        self.0
            .read()
            .iter()
            .map(|(root, slot)| (*root, *slot))
            .collect()
    }

    /// Returns a `SszHeadTracker`, which contains all necessary information to restore the state
    /// of `Self` at some later point.
    pub fn to_ssz_container(&self) -> SszHeadTracker {
        SszHeadTracker::from_map(&*self.0.read())
    }

    /// Creates a new `Self` from the given `SszHeadTracker`, restoring `Self` to the same state of
    /// the `Self` that created the `SszHeadTracker`.
    pub fn from_ssz_container(ssz_container: &SszHeadTracker) -> Result<Self, Error> {
        let roots_len = ssz_container.roots.len();
        let slots_len = ssz_container.slots.len();

        if roots_len != slots_len {
            Err(Error::MismatchingLengths {
                roots_len,
                slots_len,
            })
        } else {
            let map = ssz_container
                .roots
                .iter()
                .zip(ssz_container.slots.iter())
                .map(|(root, slot)| (*root, *slot))
                .collect::<HashMap<_, _>>();

            Ok(Self(RwLock::new(map)))
        }
    }
}

impl PartialEq<HeadTracker> for HeadTracker {
    fn eq(&self, other: &HeadTracker) -> bool {
        *self.0.read() == *other.0.read()
    }
}

/// Helper struct that is used to encode/decode the state of the `HeadTracker` as SSZ bytes.
///
/// This is used when persisting the state of the `BeaconChain` to disk.
#[derive(Encode, Decode, Clone)]
pub struct SszHeadTracker {
    roots: Vec<Hash256>,
    slots: Vec<Slot>,
}

impl SszHeadTracker {
    pub fn from_map(map: &HashMap<Hash256, Slot>) -> Self {
        let (roots, slots) = map.iter().map(|(hash, slot)| (*hash, *slot)).unzip();
        SszHeadTracker { roots, slots }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ssz::{Decode, Encode};
    use types::{BeaconBlock, EthSpec, MainnetEthSpec};

    type E = MainnetEthSpec;

    #[test]
    fn block_add() {
        let spec = &E::default_spec();

        let head_tracker = HeadTracker::default();

        for i in 0..16 {
            let mut block: BeaconBlock<E> = BeaconBlock::empty(spec);
            let block_root = Hash256::from_low_u64_be(i);

            *block.slot_mut() = Slot::new(i);
            *block.parent_root_mut() = if i == 0 {
                Hash256::random()
            } else {
                Hash256::from_low_u64_be(i - 1)
            };

            head_tracker.register_block(block_root, block.parent_root(), block.slot());
        }

        assert_eq!(
            head_tracker.heads(),
            vec![(Hash256::from_low_u64_be(15), Slot::new(15))],
            "should only have one head"
        );

        let mut block: BeaconBlock<E> = BeaconBlock::empty(spec);
        let block_root = Hash256::from_low_u64_be(42);
        *block.slot_mut() = Slot::new(15);
        *block.parent_root_mut() = Hash256::from_low_u64_be(14);
        head_tracker.register_block(block_root, block.parent_root(), block.slot());

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
