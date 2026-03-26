use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use crate::proposer_preferences_verification::gossip_verified_proposer_preferences::{
    GossipVerifiedProposerPreferences, SignatureVerifiedProposerPreferences,
};
use parking_lot::RwLock;
use types::{SignedProposerPreferences, Slot};

pub struct GossipVerifiedProposerPreferenceCache {
    preferences: RwLock<BTreeMap<Slot, GossipVerifiedProposerPreferences>>,
    seen: RwLock<BTreeMap<Slot, HashSet<u64>>>,
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

    pub fn get_seen_validator(&self, slot: &Slot, validator_index: u64) -> bool {
        self.seen
            .read()
            .get(slot)
            .is_some_and(|seen| seen.contains(&validator_index))
    }

    pub fn insert_seen_validator(&self, preferences: SignatureVerifiedProposerPreferences) {
        let slot = preferences.signed_preferences.message.proposal_slot;
        let validator_index = preferences.signed_preferences.message.validator_index;
        self.seen
            .write()
            .entry(slot)
            .or_default()
            .insert(validator_index);
    }

    pub fn prune(&self, current_slot: Slot) {
        self.preferences
            .write()
            .retain(|&slot, _| slot >= current_slot);
        self.seen.write().retain(|&slot, _| slot >= current_slot);
    }
}
