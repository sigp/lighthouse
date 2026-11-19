use crate::XmssPublicKey;
use rpds::HashTrieMapSync as HashTrieMap;

type ValidatorIndex = usize;

#[allow(clippy::len_without_is_empty)]
#[derive(Debug, PartialEq, Clone, Default)]
pub struct PubkeyCache {
    /// Maintain the number of keys added to the map. It is not sufficient to just use the
    /// HashTrieMap len, as it does not increase when duplicate keys are added. Duplicate keys are
    /// used during testing.
    len: usize,
    map: HashTrieMap<XmssPublicKey, ValidatorIndex>,
}

impl PubkeyCache {
    /// Returns the number of validator indices added to the map so far.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> ValidatorIndex {
        self.len
    }

    /// Inserts a validator index into the map.
    ///
    /// The added index must equal the number of validators already added to the map. This ensures
    /// that an index is never skipped.
    pub fn insert(&mut self, pubkey: XmssPublicKey, index: ValidatorIndex) -> bool {
        let Some(next_len) = self.len.checked_add(1) else {
            return false;
        };
        if index != self.len {
            return false;
        }
        self.map.insert_mut(pubkey, index);
        self.len = next_len;
        true
    }

    /// Looks up a validator index by their public key.
    pub fn get(&self, pubkey: &XmssPublicKey) -> Option<ValidatorIndex> {
        self.map.get(pubkey).copied()
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PubkeyCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}
