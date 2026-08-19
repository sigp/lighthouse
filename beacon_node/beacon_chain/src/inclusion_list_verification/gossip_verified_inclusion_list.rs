use crate::inclusion_list_verification::InclusionListVerificationError;
use crate::{BeaconChain, BeaconChainTypes};
use std::sync::Arc;
use tracing::debug;
use types::{ChainSpec, SignedInclusionList};

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    // TODO(heze): complete while implementing the gossip verification of inclusion lists
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
}

pub struct GossipVerifiedInclusionList {
    pub signed_inclusion_list: Arc<SignedInclusionList>,
}

impl GossipVerifiedInclusionList {
    pub fn new<T: BeaconChainTypes>(
        signed_inclusion_list: Arc<SignedInclusionList>,
        _ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, InclusionListVerificationError> {
        // TODO(heze): implement gossip verification for inclusion lists
        Ok(Self {
            signed_inclusion_list,
        })
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn inclusion_list_gossip_verification_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            slot_clock: &self.slot_clock,
            spec: &self.spec,
        }
    }

    pub fn verify_inclusion_list_for_gossip(
        &self,
        signed_inclusion_list: Arc<SignedInclusionList>,
    ) -> Result<GossipVerifiedInclusionList, InclusionListVerificationError> {
        let slot = signed_inclusion_list.message.slot;
        let validator_index = signed_inclusion_list.message.validator_index;

        let ctx = self.inclusion_list_gossip_verification_context();
        match GossipVerifiedInclusionList::new(signed_inclusion_list, &ctx) {
            Ok(verified) => {
                debug!(
                    %slot,
                    %validator_index,
                    "Successfully verified gossip inclusion list"
                );

                // TODO(heze): emit the inclusion_list SSE event

                Ok(verified)
            }
            Err(e) => {
                debug!(
                    error = ?e,
                    %slot,
                    %validator_index,
                    "Rejected gossip inclusion list"
                );
                Err(e)
            }
        }
    }
}
