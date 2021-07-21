use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::{
    lighthouse::{GlobalValidatorInclusionData, ValidatorInclusionData},
    types::ValidatorId,
};
use serde::Serialize;
use state_processing::{common::get_indexed_attestation, per_epoch_processing::ValidatorStatuses};
use std::collections::HashMap;
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// Returns information about *all validators* (i.e., global) and how they performed during a given
/// epoch.
pub fn global_validator_inclusion_data<T: BeaconChainTypes>(
    epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<GlobalValidatorInclusionData, warp::Rejection> {
    let target_slot = epoch.end_slot(T::EthSpec::slots_per_epoch());

    let state = StateId::slot(target_slot).state(chain)?;

    let mut validator_statuses = ValidatorStatuses::new(&state, &chain.spec)
        .map_err(warp_utils::reject::beacon_state_error)?;
    validator_statuses
        .process_attestations(&state)
        .map_err(warp_utils::reject::beacon_state_error)?;

    let totals = validator_statuses.total_balances;

    Ok(GlobalValidatorInclusionData {
        current_epoch_active_gwei: totals.current_epoch(),
        previous_epoch_active_gwei: totals.previous_epoch(),
        current_epoch_attesting_gwei: totals.current_epoch_attesters(),
        current_epoch_target_attesting_gwei: totals.current_epoch_target_attesters(),
        previous_epoch_attesting_gwei: totals.previous_epoch_attesters(),
        previous_epoch_target_attesting_gwei: totals.previous_epoch_target_attesters(),
        previous_epoch_head_attesting_gwei: totals.previous_epoch_head_attesters(),
    })
}

struct BlockAndParent<T: EthSpec> {
    block: SignedBeaconBlock<T>,
    block_root: Hash256,
    parent: SignedBeaconBlock<T>,
    parent_root: Hash256,
}

type BlocksByRoot<T> = HashMap<Hash256, BlockAndParent<T>>;

fn blocks_between_slots<T: BeaconChainTypes>(
    lowest_slot: Slot,
    highest_slot: Slot,
    state: &BeaconState<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<BlocksByRoot<T::EthSpec>, warp::reject::Rejection> {
    let mut blocks_by_root = HashMap::new();
    let mut block_root = *state
        .get_block_root(highest_slot)
        .map_err(warp_utils::reject::beacon_state_error)?;

    loop {
        let block = chain
            .get_block(&block_root)
            .map_err(warp_utils::reject::beacon_chain_error)?
            .ok_or_else(|| {
                warp_utils::reject::custom_server_error(format!(
                    "missing block with root {:?}",
                    block_root
                ))
            })?;

        let parent_root = block.parent_root();
        let parent_block = chain
            .get_block(&parent_root)
            .map_err(warp_utils::reject::beacon_chain_error)?
            .ok_or_else(|| {
                warp_utils::reject::custom_server_error(format!(
                    "missing parent block with root {:?}",
                    parent_root
                ))
            })?;
        let parent_slot = parent_block.slot();

        blocks_by_root.insert(
            block_root,
            BlockAndParent {
                block,
                block_root,
                parent: parent_block,
                parent_root,
            },
        );

        if parent_slot < lowest_slot {
            break;
        }

        block_root = parent_root;
    }

    Ok(blocks_by_root)
}

#[derive(Serialize)]
enum BlockVote {
    Matched {
        vote_root: Hash256,
    },
    UnknownBlock {
        canonical_root: Hash256,
        vote_root: Hash256,
    },
    Late {
        canonical_root: Hash256,
        vote_root: Hash256,
        distance: usize,
    },
}

impl BlockVote {
    pub fn new<T: EthSpec>(
        vote_slot: Slot,
        vote_root: Hash256,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, warp::reject::Rejection> {
        let canonical_root = *state
            .get_block_root(vote_slot)
            .map_err(warp_utils::reject::beacon_state_error)?;

        let mut prev_root = None;
        let mut num_intermediate_blocks = None;
        for result in state.rev_iter_block_roots(spec) {
            let (slot, root) = result.map_err(warp_utils::reject::beacon_state_error)?;

            if slot > vote_slot {
                continue;
            } else if root == vote_root {
                if let Some(distance) = num_intermediate_blocks {
                    return Ok(BlockVote::Late {
                        canonical_root,
                        vote_root,
                        distance,
                    });
                } else {
                    return Ok(BlockVote::Matched { vote_root });
                }
            } else if prev_root.map_or(true, |prev_root| prev_root != root) {
                num_intermediate_blocks = Some(num_intermediate_blocks.unwrap_or(0) + 1);
                prev_root = Some(root);
            }
        }

        Ok(BlockVote::UnknownBlock {
            canonical_root,
            vote_root,
        })
    }
}

#[derive(Serialize)]
struct AttestationInclusion {
    attestation_index: u64,
    attestation_slot: Slot,
    attestation_epoch: Epoch,
    attestation_inclusion_slot: Slot,
    head_vote: BlockVote,
    target_vote: BlockVote,
}

pub type InclusionsByValidator = HashMap<u64, Vec<AttestationInclusion>>;

#[derive(Serialize)]
pub struct AttestationPerformanceReport {
    validator_index: u64,
    attestation_inclusions: Vec<AttestationInclusion>,
}

/// Returns information about a single validator and how it performed during a given epoch.
pub fn validator_performance_report<T: BeaconChainTypes>(
    request_epoch: Epoch,
    validator_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<Vec<AttestationPerformanceReport>, warp::Rejection> {
    let slots_per_epoch = T::EthSpec::slots_per_epoch();
    let next_epoch = request_epoch + 1;
    let target_slot = next_epoch.end_slot(slots_per_epoch);

    let mut state = StateId::slot(target_slot).state(chain)?;

    let mut inclusions_by_validator: InclusionsByValidator = <_>::default();
    for val_index in validator_indices {
        inclusions_by_validator.entry(*val_index).or_default();
    }

    let blocks_by_root = {
        let lowest_slot = request_epoch.start_slot(slots_per_epoch);
        let highest_slot =
            next_epoch.start_slot(slots_per_epoch) + chain.spec.min_attestation_inclusion_delay;
        blocks_between_slots(lowest_slot, highest_slot, &state, chain)?
    };

    for (block_root, block_and_parent) in &blocks_by_root {
        let block = block_and_parent.block.message();
        for attestation in block.body().attestations() {
            if attestation.data.target.epoch != request_epoch {
                continue;
            }

            let committee = state
                .get_beacon_committee(attestation.data.slot, attestation.data.index)
                .map_err(warp_utils::reject::beacon_state_error)?;
            let indexed_attestation = get_indexed_attestation(committee.committee, attestation)
                .map_err(|e| {
                    warp_utils::reject::custom_server_error(format!(
                        "error converting to indexed attestation: {:?}",
                        e
                    ))
                })?;
            let data = &indexed_attestation.data;

            for val_index in &indexed_attestation.attesting_indices {
                if let Some(inclusions) = inclusions_by_validator.get_mut(val_index) {
                    let head_vote =
                        BlockVote::new(data.slot, data.beacon_block_root, &state, &chain.spec)?;
                    let target_slot = data.target.epoch.start_slot(slots_per_epoch);
                    let target_vote =
                        BlockVote::new(target_slot, data.target.root, &state, &chain.spec)?;

                    inclusions.push(AttestationInclusion {
                        attestation_index: data.index,
                        attestation_slot: data.slot,
                        attestation_epoch: data.slot.epoch(slots_per_epoch),
                        attestation_inclusion_slot: block.slot(),
                        head_vote,
                        target_vote,
                    })
                }
            }
        }
    }

    let reports = inclusions_by_validator
        .into_iter()
        .map(
            |(validator_index, attestation_inclusions)| AttestationPerformanceReport {
                validator_index,
                attestation_inclusions,
            },
        )
        .collect();

    Ok(reports)
}
