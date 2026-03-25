use std::{collections::BTreeMap, sync::Arc};

use crate::{
    BeaconChainTypes,
    proposer_preferences_verification::gossip_verified_proposer_preferences::GossipVerifiedProposerPreferences,
};
use parking_lot::RwLock;
use types::{SignedExecutionPayloadBid, SignedProposerPreferences, Slot};

pub struct GossipVerifiedProposerPreferenceCache {
    inner: RwLock<BTreeMap<Slot, GossipVerifiedProposerPreferences>>,
}

impl GossipVerifiedProposerPreferenceCache {
    pub fn get(&self, slot: &Slot) -> Option<Arc<SignedProposerPreferences>> {
        self.inner
            .read()
            .get(slot)
            .and_then(|p| Some(p.signed_proposer_preference.clone()))
    }
}
