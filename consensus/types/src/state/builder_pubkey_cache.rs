use crate::BuilderIndex;
use bls::PublicKeyBytes;
use rpds::HashTrieMapSync as HashTrieMap;

/// Bidirectional pubkey <-> index cache for the Gloas builder registry.
#[allow(clippy::len_without_is_empty)]
#[derive(Debug, PartialEq, Clone, Default)]
pub struct BuilderPubkeyCache {
    len: usize,
    pubkey_to_index: HashTrieMap<PublicKeyBytes, BuilderIndex>,
    index_to_pubkey: HashTrieMap<BuilderIndex, PublicKeyBytes>,
}

impl BuilderPubkeyCache {
    pub fn len(&self) -> usize {
        self.len
    }

    /// Append a new builder slot. Returns `false` if `index != self.len`.
    pub fn append(&mut self, pubkey: PublicKeyBytes, index: BuilderIndex) -> bool {
        if index as usize != self.len {
            return false;
        }
        self.pubkey_to_index.insert_mut(pubkey, index);
        self.index_to_pubkey.insert_mut(index, pubkey);
        self.len = self
            .len
            .checked_add(1)
            .expect("map length cannot exceed usize");
        true
    }

    /// Replace the pubkey at an existing index. Returns `false` if `index >= self.len`.
    pub fn replace(&mut self, index: BuilderIndex, new_pubkey: PublicKeyBytes) -> bool {
        if index as usize >= self.len {
            return false;
        }
        if let Some(old_pubkey) = self.index_to_pubkey.get(&index).copied() {
            if old_pubkey == new_pubkey {
                return true;
            }
            if self.pubkey_to_index.get(&old_pubkey).copied() == Some(index) {
                self.pubkey_to_index.remove_mut(&old_pubkey);
            }
        }
        self.pubkey_to_index.insert_mut(new_pubkey, index);
        self.index_to_pubkey.insert_mut(index, new_pubkey);
        true
    }

    /// Append (`index == self.len`) or replace (`index < self.len`). Returns `false` if
    /// `index > self.len`.
    pub fn set(&mut self, index: BuilderIndex, pubkey: PublicKeyBytes) -> bool {
        match (index as usize).cmp(&self.len) {
            std::cmp::Ordering::Equal => self.append(pubkey, index),
            std::cmp::Ordering::Less => self.replace(index, pubkey),
            std::cmp::Ordering::Greater => false,
        }
    }

    pub fn get_index(&self, pubkey: &PublicKeyBytes) -> Option<BuilderIndex> {
        self.pubkey_to_index.get(pubkey).copied()
    }

    pub fn get_pubkey(&self, index: BuilderIndex) -> Option<PublicKeyBytes> {
        self.index_to_pubkey.get(&index).copied()
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for BuilderPubkeyCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> PublicKeyBytes {
        let mut bytes = [0u8; 48];
        bytes[0] = byte;
        PublicKeyBytes::deserialize(&bytes).unwrap()
    }

    #[test]
    fn append_in_order() {
        let mut cache = BuilderPubkeyCache::default();
        assert!(cache.append(pk(1), 0));
        assert!(cache.append(pk(2), 1));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get_index(&pk(1)), Some(0));
        assert_eq!(cache.get_index(&pk(2)), Some(1));
        assert_eq!(cache.get_pubkey(0), Some(pk(1)));
        assert_eq!(cache.get_pubkey(1), Some(pk(2)));
    }

    #[test]
    fn append_out_of_order_rejected() {
        let mut cache = BuilderPubkeyCache::default();
        assert!(!cache.append(pk(1), 1));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn replace_reuses_slot() {
        let mut cache = BuilderPubkeyCache::default();
        cache.append(pk(1), 0);
        cache.append(pk(2), 1);
        assert!(cache.replace(0, pk(3)));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get_index(&pk(1)), None);
        assert_eq!(cache.get_index(&pk(3)), Some(0));
        assert_eq!(cache.get_pubkey(0), Some(pk(3)));
        assert_eq!(cache.get_index(&pk(2)), Some(1));
    }

    #[test]
    fn replace_unknown_slot_rejected() {
        let mut cache = BuilderPubkeyCache::default();
        cache.append(pk(1), 0);
        assert!(!cache.replace(5, pk(2)));
    }

    #[test]
    fn persistent_clone_is_independent() {
        let mut cache = BuilderPubkeyCache::default();
        cache.append(pk(1), 0);
        let snapshot = cache.clone();
        cache.append(pk(2), 1);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.get_index(&pk(2)), None);
        assert_eq!(cache.len(), 2);
    }
}
