use crate::{BeaconState, ChainSpec, Hash256, PendingAttestation};
use std::collections::HashMap;

pub enum Error {
    UnableToDetermineProducer,
    NoBlockRoots,
    UnableToGetCrosslinkCommittees,
    BaseRewardQuotientIsZero,
}

#[derive(Clone)]
pub struct WinningRoot {
    pub shard_block_root: Hash256,
    pub attesting_validator_indices: Vec<usize>,
    pub total_balance: u64,
    pub total_attesting_balance: u64,
}

impl BeaconState {
    pub(crate) fn winning_root(
        &self,
        shard: u64,
        current_epoch_attestations: &[&PendingAttestation],
        previous_epoch_attestations: &[&PendingAttestation],
        spec: &ChainSpec,
    ) -> Option<WinningRoot> {
        let mut attestations = current_epoch_attestations.to_vec();
        attestations.append(&mut previous_epoch_attestations.to_vec());

        let mut candidates: HashMap<Hash256, WinningRoot> = HashMap::new();

        let mut highest_seen_balance = 0;

        for a in &attestations {
            if a.data.shard != shard {
                continue;
            }

            let shard_block_root = &a.data.shard_block_root;

            if candidates.contains_key(shard_block_root) {
                continue;
            }

            let attesting_validator_indices = attestations.iter().fold(vec![], |mut acc, a| {
                if (a.data.shard == shard) && (a.data.shard_block_root == *shard_block_root) {
                    acc.append(
                        &mut self.get_attestation_participants(&a.data, &a.aggregation_bitfield),
                    );
                }
                acc
            });

            let total_balance: u64 = attesting_validator_indices
                .iter()
                .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

            let total_attesting_balance: u64 = attesting_validator_indices
                .iter()
                .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

            if total_attesting_balance > highest_seen_balance {
                highest_seen_balance = total_attesting_balance;
            }

            let candidate_root = WinningRoot {
                shard_block_root: shard_block_root.clone(),
                attesting_validator_indices,
                total_attesting_balance,
                total_balance,
            };

            candidates.insert(*shard_block_root, candidate_root);
        }

        let winner = candidates
            .iter()
            .filter_map(|(_hash, candidate)| {
                if candidate.total_attesting_balance == highest_seen_balance {
                    Some(candidate)
                } else {
                    None
                }
            })
            .min_by_key(|candidate| candidate.shard_block_root);

        match winner {
            Some(winner) => Some(winner.clone()),
            None => None,
        }
    }
}
