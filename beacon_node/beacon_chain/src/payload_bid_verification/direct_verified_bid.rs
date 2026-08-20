use crate::payload_bid_verification::{
    PayloadBidError,
    gossip_verified_bid::{is_gas_limit_target_compatible, verify_bid_consistency},
};
use eth2::types::BuilderPubkeys;
use state_processing::signature_sets::{
    execution_payload_bid_signature_set, get_builder_pubkey_from_state,
};
use types::{
    BeaconState, ChainSpec, EthSpec, ExecutionBlockHash, Hash256, SignedExecutionPayloadBid,
    SignedProposerPreferences, Slot,
};

/// Fully validate a bid fetched directly from a builder, for inclusion in a block being produced.
///
/// This performs all validation a direct builder bid must pass before it can be selected:
/// - the consensus-consistency checks shared with the gossip verifier via [`verify_bid_consistency`]
///   (fee recipient, blob count, builder eligibility/version, and that the builder's collateral
///   covers the bid value),
/// - that the bid matches the block being produced — the exact `proposal_slot`, the selected
///   FULL/EMPTY parent (`parent_block_hash` / `parent_block_root`), the state's RANDAO mix, and a
///   gas limit compatible with the parent's under the proposer's target, and
/// - a valid builder signature.
///
/// Unlike gossip bids, direct bids may carry an execution payment; the `execution_payment == 0`
/// rule is a gossip-only check applied in the gossip verifier, not here.
///
/// `state` must be the beacon state the block is being produced against — the parent block's
/// post-state advanced to `proposal_slot` — and `parent_block_hash` / `parent_block_root` the
/// FULL/EMPTY parent the producer selected.
#[allow(clippy::too_many_arguments)]
pub fn verify_direct_bid<E: EthSpec>(
    signed_bid: &SignedExecutionPayloadBid<E>,
    proposal_slot: Slot,
    parent_block_hash: ExecutionBlockHash,
    parent_block_root: Hash256,
    expected_builder_pubkeys: &BuilderPubkeys,
    proposer_preferences: &SignedProposerPreferences,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), PayloadBidError> {
    let bid = &signed_bid.message;

    // The bid must be for exactly the slot being produced.
    if bid.slot != proposal_slot {
        return Err(PayloadBidError::InvalidBidSlot { bid_slot: bid.slot });
    }

    // The bid must build on the same parent the producer selected (FULL or EMPTY).
    if bid.parent_block_hash != parent_block_hash {
        return Err(PayloadBidError::InvalidParentBlockHash {
            bid: bid.parent_block_hash,
            expected: parent_block_hash,
        });
    }
    if bid.parent_block_root != parent_block_root {
        return Err(PayloadBidError::InvalidParentBlockRoot {
            bid: bid.parent_block_root,
            expected: parent_block_root,
        });
    }

    // `prev_randao` must be the RANDAO mix from the production state.
    let expected_prev_randao = *state.get_randao_mix(proposal_slot.epoch(E::slots_per_epoch()))?;
    if bid.prev_randao != expected_prev_randao {
        return Err(PayloadBidError::InvalidPrevRandao { slot: bid.slot });
    }

    // The gas limit must be compatible with the parent's, given the proposer's target.
    if let Ok(parent_bid) = state.latest_execution_payload_bid()
        && !is_gas_limit_target_compatible(
            parent_bid.gas_limit,
            bid.gas_limit,
            proposer_preferences.message.target_gas_limit,
        )?
    {
        return Err(PayloadBidError::InvalidGasLimit);
    }

    // Consensus-consistency checks shared with the gossip verifier.
    verify_bid_consistency(bid, proposal_slot, proposer_preferences, state, spec)?;

    // If the requesting `BuilderEntry` named builder pubkeys, the bid must come from one of them:
    // the builder at `bid.builder_index` must have one of those pubkeys (the `builder_pubkeys`
    // response filter from beacon-APIs #630; an empty list accepts any builder).
    if !expected_builder_pubkeys.is_empty() {
        let actual = state
            .get_builder(bid.builder_index)
            .map_err(|_| PayloadBidError::InvalidBuilder {
                builder_index: bid.builder_index,
            })?
            .pubkey;
        if !expected_builder_pubkeys.contains(&actual) {
            return Err(PayloadBidError::UnexpectedBuilder {
                builder_index: bid.builder_index,
            });
        }
    }

    // Verify the builder's signature.
    execution_payload_bid_signature_set(
        state,
        |i| get_builder_pubkey_from_state(state, i),
        signed_bid,
        spec,
    )
    .map_err(|_| PayloadBidError::BadSignature)?
    .ok_or(PayloadBidError::BadSignature)?
    .verify()
    .then_some(())
    .ok_or(PayloadBidError::BadSignature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Signature;
    use types::{Address, ExecutionPayloadBid, MinimalEthSpec, ProposerPreferences};

    type E = MinimalEthSpec;

    fn state_and_spec() -> (BeaconState<E>, ChainSpec) {
        let spec = E::default_spec();
        let state = BeaconState::new(0, <_>::default(), &spec);
        (state, spec)
    }

    fn preferences() -> SignedProposerPreferences {
        SignedProposerPreferences {
            message: ProposerPreferences {
                fee_recipient: Address::ZERO,
                target_gas_limit: 30_000_000,
                ..ProposerPreferences::default()
            },
            signature: Signature::empty(),
        }
    }

    fn signed_bid(
        slot: Slot,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
        prev_randao: Hash256,
    ) -> SignedExecutionPayloadBid<E> {
        SignedExecutionPayloadBid {
            message: ExecutionPayloadBid {
                slot,
                parent_block_hash,
                parent_block_root,
                prev_randao,
                ..ExecutionPayloadBid::default()
            },
            signature: Signature::empty(),
        }
    }

    #[test]
    fn rejects_wrong_slot() {
        let (state, spec) = state_and_spec();
        let bid = signed_bid(
            Slot::new(2),
            ExecutionBlockHash::zero(),
            Hash256::ZERO,
            Hash256::ZERO,
        );
        let result = verify_direct_bid(
            &bid,
            Slot::new(1),
            ExecutionBlockHash::zero(),
            Hash256::ZERO,
            &BuilderPubkeys::default(),
            &preferences(),
            &state,
            &spec,
        );
        assert!(matches!(
            result,
            Err(PayloadBidError::InvalidBidSlot { .. })
        ));
    }

    #[test]
    fn rejects_wrong_parent_hash() {
        let (state, spec) = state_and_spec();
        let bid = signed_bid(
            Slot::new(1),
            ExecutionBlockHash::repeat_byte(9),
            Hash256::ZERO,
            Hash256::ZERO,
        );
        let result = verify_direct_bid(
            &bid,
            Slot::new(1),
            ExecutionBlockHash::zero(),
            Hash256::ZERO,
            &BuilderPubkeys::default(),
            &preferences(),
            &state,
            &spec,
        );
        assert!(matches!(
            result,
            Err(PayloadBidError::InvalidParentBlockHash { .. })
        ));
    }

    #[test]
    fn rejects_wrong_parent_root() {
        let (state, spec) = state_and_spec();
        let bid = signed_bid(
            Slot::new(1),
            ExecutionBlockHash::zero(),
            Hash256::repeat_byte(9),
            Hash256::ZERO,
        );
        let result = verify_direct_bid(
            &bid,
            Slot::new(1),
            ExecutionBlockHash::zero(),
            Hash256::ZERO,
            &BuilderPubkeys::default(),
            &preferences(),
            &state,
            &spec,
        );
        assert!(matches!(
            result,
            Err(PayloadBidError::InvalidParentBlockRoot { .. })
        ));
    }

    #[test]
    fn rejects_wrong_prev_randao() {
        let (state, spec) = state_and_spec();
        // The fresh state's RANDAO mix is zero, so a non-zero `prev_randao` is rejected.
        let bid = signed_bid(
            Slot::new(1),
            ExecutionBlockHash::zero(),
            Hash256::ZERO,
            Hash256::repeat_byte(9),
        );
        let result = verify_direct_bid(
            &bid,
            Slot::new(1),
            ExecutionBlockHash::zero(),
            Hash256::ZERO,
            &BuilderPubkeys::default(),
            &preferences(),
            &state,
            &spec,
        );
        assert!(matches!(
            result,
            Err(PayloadBidError::InvalidPrevRandao { .. })
        ));
    }
}
