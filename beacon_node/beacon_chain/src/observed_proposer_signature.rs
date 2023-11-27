//! Blocks and each of `MAX_BLOBS_PER_BLOCK` blobs should contain the same
//! proposal signature.
//!
//! This cache avoids verifying the same signature multiple times.

use std::collections::{hash_map::Entry, HashMap};
use std::marker::PhantomData;

use types::{BlobSidecar, EthSpec, Hash256, Signature, SignedBeaconBlock, Slot};

#[derive(Debug)]
pub enum Error {}

#[derive(Debug, PartialEq, Hash, Eq)]
struct Key {
    block_root: Hash256,
    slot: Slot,
}

pub enum SeenSignature {
    Duplicate,
    New,
    Slashable,
}

pub struct ProposerSignatureCache<E: EthSpec> {
    items: HashMap<Key, Signature>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ProposerSignatureCache<E> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ProposerSignatureCache<E> {
    pub fn observe_valid_proposer_signature(
        &mut self,
        block_root: Hash256,
        slot: Slot,
        signature: Signature,
    ) -> SeenSignature {
        let key = Key { block_root, slot };
        let entry = self.items.entry(key);
        match entry {
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(signature);
                SeenSignature::New
            }
            Entry::Occupied(occupied_entry) => {
                let existing_signature = occupied_entry.get();
                if *existing_signature == signature {
                    SeenSignature::Duplicate
                } else {
                    SeenSignature::Slashable
                }
            }
        }
    }

    pub fn proposer_signature_has_been_observed(
        &self,
        block_root: Hash256,
        slot: Slot,
        signature: Signature,
    ) -> SeenSignature {
        let key = Key { block_root, slot };
        match self.items.get(&key) {
            None => SeenSignature::New,
            Some(existing_signature) => {
                if *existing_signature == signature {
                    SeenSignature::Duplicate
                } else {
                    SeenSignature::Slashable
                }
            }
        }
    }
}
