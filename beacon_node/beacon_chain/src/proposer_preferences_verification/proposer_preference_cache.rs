use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use crate::proposer_preferences_verification::gossip_verified_proposer_preferences::GossipVerifiedProposerPreferences;
use parking_lot::RwLock;
use types::{Hash256, SignedProposerPreferences, Slot};

pub struct GossipVerifiedProposerPreferenceCache {
    preferences: RwLock<BTreeMap<Slot, GossipVerifiedProposerPreferences>>,
    seen: RwLock<BTreeMap<Slot, HashSet<(Hash256, u64)>>>,
}

impl Default for GossipVerifiedProposerPreferenceCache {
    fn default() -> Self {
        Self {
            preferences: RwLock::new(BTreeMap::new()),
            seen: RwLock::new(BTreeMap::new()),
        }
    }
}

impl GossipVerifiedProposerPreferenceCache {
    pub fn get_preferences(&self, slot: &Slot) -> Option<Arc<SignedProposerPreferences>> {
        self.preferences
            .read()
            .get(slot)
            .map(|p| p.signed_preferences.clone())
    }

    pub fn insert_preferences(&self, preferences: GossipVerifiedProposerPreferences) {
        let slot = preferences.signed_preferences.message.proposal_slot;
        self.preferences.write().insert(slot, preferences);
    }

    pub fn get_seen_validator(
        &self,
        slot: &Slot,
        checkpoint_root: Hash256,
        validator_index: u64,
    ) -> bool {
        self.seen
            .read()
            .get(slot)
            .is_some_and(|seen| seen.contains(&(checkpoint_root, validator_index)))
    }

    pub fn insert_seen_validator(&self, preferences: &GossipVerifiedProposerPreferences) {
        let slot = preferences.signed_preferences.message.proposal_slot;
        let checkpoint_root = preferences.signed_preferences.message.checkpoint_root;
        let validator_index = preferences.signed_preferences.message.validator_index;
        self.seen
            .write()
            .entry(slot)
            .or_default()
            .insert((checkpoint_root, validator_index));
    }

    pub fn prune(&self, current_slot: Slot) {
        self.preferences
            .write()
            .retain(|&slot, _| slot >= current_slot);
        self.seen.write().retain(|&slot, _| slot >= current_slot);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bls::Signature;
    use types::{Address, ProposerPreferences, SignedProposerPreferences, Slot};

    use super::GossipVerifiedProposerPreferenceCache;
    use crate::proposer_preferences_verification::gossip_verified_proposer_preferences::GossipVerifiedProposerPreferences;

    fn make_gossip_verified(slot: Slot, validator_index: u64) -> GossipVerifiedProposerPreferences {
        GossipVerifiedProposerPreferences {
            signed_preferences: Arc::new(SignedProposerPreferences {
                message: ProposerPreferences {
                    proposal_slot: slot,
                    validator_index,
                    fee_recipient: Address::ZERO,
                    gas_limit: 30_000_000,
                    ..ProposerPreferences::default()
                },
                signature: Signature::empty(),
            }),
        }
    }

    #[test]
    fn prune_removes_old_retains_current() {
        let cache = GossipVerifiedProposerPreferenceCache::default();

        for slot in [1, 2, 3, 7, 8, 9, 10] {
            let verified = make_gossip_verified(Slot::new(slot), slot);
            cache.insert_seen_validator(&verified);
            cache.insert_preferences(verified);
        }

        cache.prune(Slot::new(8));

        for slot in [1, 2, 3, 7] {
            assert!(cache.get_preferences(&Slot::new(slot)).is_none());
            assert!(!cache.get_seen_validator(&Slot::new(slot), types::Hash256::ZERO, slot));
        }
        for slot in [8, 9, 10] {
            assert!(cache.get_preferences(&Slot::new(slot)).is_some());
            assert!(cache.get_seen_validator(&Slot::new(slot), types::Hash256::ZERO, slot));
        }
    }
}
