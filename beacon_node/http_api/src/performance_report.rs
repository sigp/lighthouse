use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use serde::Serialize;
use state_processing::common::get_indexed_attestation;
use std::collections::{HashMap, HashSet};
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

type VotesPerRoot = HashMap<Slot, HashMap<Hash256, HashSet<u64>>>;

#[derive(Serialize)]
enum VoteCategory {
    Matched,
    UnknownBlock,
    Late {
        #[serde(with = "serde_utils::quoted_u64")]
        distance: u64,
    },
}

#[derive(Serialize)]
struct BlockVote {
    canonical_root: Hash256,
    vote_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    total_votes_agreeing: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    total_votes_disagreeing: u64,
    category: VoteCategory,
}

impl BlockVote {
    pub fn new<T: EthSpec>(
        vote_slot: Slot,
        vote_root: Hash256,
        votes_per_root: &VotesPerRoot,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, warp::reject::Rejection> {
        let canonical_root = *state
            .get_block_root(vote_slot)
            .map_err(warp_utils::reject::beacon_state_error)?;

        let total_votes_agreeing = votes_per_root
            .get(&vote_slot)
            .and_then(|votes_per_slot| votes_per_slot.get(&vote_root))
            .map(|validator_set: &HashSet<_>| validator_set.len() as u64)
            .unwrap_or(0);
        let total_votes_disagreeing = votes_per_root
            .get(&vote_slot)
            .map(|votes_per_slot| {
                votes_per_slot
                    .iter()
                    .filter(|(root, _)| **root != vote_root)
                    .map(|(_, votes)| votes.len() as u64)
                    .sum()
            })
            .unwrap_or(0);

        let mut prev_root = None;
        let mut num_intermediate_blocks = None;
        for result in state.rev_iter_block_roots(spec) {
            let (slot, root) = result.map_err(warp_utils::reject::beacon_state_error)?;

            if slot > vote_slot {
                continue;
            } else if root == vote_root {
                if let Some(distance) = num_intermediate_blocks {
                    return Ok(BlockVote {
                        canonical_root,
                        vote_root,
                        total_votes_agreeing,
                        total_votes_disagreeing,
                        category: VoteCategory::Late { distance },
                    });
                } else {
                    return Ok(BlockVote {
                        canonical_root,
                        vote_root,
                        total_votes_agreeing,
                        total_votes_disagreeing,
                        category: VoteCategory::Matched,
                    });
                }
            } else if prev_root.map_or(true, |prev_root| prev_root != root) {
                num_intermediate_blocks = Some(num_intermediate_blocks.unwrap_or(0) + 1);
                prev_root = Some(root);
            }
        }

        Ok(BlockVote {
            canonical_root,
            vote_root,
            total_votes_agreeing,
            total_votes_disagreeing,
            category: VoteCategory::UnknownBlock,
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

#[derive(Serialize)]
pub struct AttestationPerformanceReport {
    validator_index: u64,
    best_inclusion: Option<AttestationInclusion>,
    total_inclusions: u64,
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

    let state = StateId::slot(target_slot).state(chain)?;

    let blocks = {
        let lowest_slot = request_epoch.start_slot(slots_per_epoch);
        let highest_slot =
            next_epoch.start_slot(slots_per_epoch) + chain.spec.min_attestation_inclusion_delay;
        blocks_between_slots(lowest_slot, highest_slot, &state, chain)?
    };

    let mut reports = validator_indices
        .iter()
        .map(|i| AttestationPerformanceReport {
            validator_index: *i,
            best_inclusion: None,
            total_inclusions: 0,
        })
        .map(|report| (report.validator_index, report))
        .collect::<HashMap<_, _>>();

    let mut head_votes: VotesPerRoot = <_>::default();
    let mut target_votes: VotesPerRoot = <_>::default();

    let mut indexed_attestations = vec![];
    for signed_block in &blocks {
        let block = signed_block.message();
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
                head_votes
                    .entry(data.slot)
                    .or_default()
                    .entry(data.beacon_block_root)
                    .or_default()
                    .insert(*val_index);
                target_votes
                    .entry(data.target.epoch.start_slot(slots_per_epoch))
                    .or_default()
                    .entry(data.target.root)
                    .or_default()
                    .insert(*val_index);
            }

            indexed_attestations.push((block.slot(), indexed_attestation))
        }
    }

    for signed_block in &blocks {
        let block = signed_block.message();
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
                if let Some(report) = reports.get_mut(val_index) {
                    report.total_inclusions += 1;

                    if report
                        .best_inclusion
                        .as_ref()
                        .map_or(true, |best| best.attestation_inclusion_slot >= block.slot())
                    {
                        let head_vote = BlockVote::new(
                            data.slot,
                            data.beacon_block_root,
                            &head_votes,
                            &state,
                            &chain.spec,
                        )?;
                        let target_slot = data.target.epoch.start_slot(slots_per_epoch);
                        let target_vote = BlockVote::new(
                            target_slot,
                            data.target.root,
                            &target_votes,
                            &state,
                            &chain.spec,
                        )?;

                        report.best_inclusion = Some(AttestationInclusion {
                            attestation_index: data.index,
                            attestation_slot: data.slot,
                            attestation_epoch: data.slot.epoch(slots_per_epoch),
                            attestation_inclusion_slot: block.slot(),
                            head_vote,
                            target_vote,
                        });
                    }
                }
            }
        }
    }

    Ok(reports.into_iter().map(|(_, report)| report).collect())
}

fn blocks_between_slots<T: BeaconChainTypes>(
    lowest_slot: Slot,
    highest_slot: Slot,
    state: &BeaconState<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<Vec<SignedBeaconBlock<T::EthSpec>>, warp::reject::Rejection> {
    let mut roots: Vec<(Slot, Hash256)> =
        itertools::process_results(state.rev_iter_block_roots(&chain.spec), |iter| {
            iter.skip_while(|(slot, _)| *slot > highest_slot)
                .take_while(|(slot, _)| *slot >= lowest_slot)
                .collect()
        })
        .map_err(warp_utils::reject::beacon_state_error)?;

    roots.dedup();

    roots
        .into_iter()
        .map(|(_, root)| {
            chain
                .get_block(&root)
                .map_err(warp_utils::reject::beacon_chain_error)?
                .ok_or_else(|| {
                    warp_utils::reject::custom_server_error(format!(
                        "missing block with root {:?}",
                        root
                    ))
                })
        })
        .collect()
}
