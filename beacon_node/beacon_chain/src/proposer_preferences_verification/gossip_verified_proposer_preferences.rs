use std::sync::Arc;

// use educe::Educe;
use types::SignedProposerPreferences;

// use crate::BeaconChainTypes;

/// A wrapper around a `SignedProposerPreferences` that indicates it has been approved for re-gossiping on
/// the p2p network.
// #[derive(Educe)]
// #[educe(Debug(bound = "T: BeaconChainTypes"))]
pub struct GossipVerifiedProposerPreferences {
    pub signed_proposer_preference: Arc<SignedProposerPreferences>,
}
