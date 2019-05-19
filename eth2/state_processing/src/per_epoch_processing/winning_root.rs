use super::get_attesting_indices::get_attesting_indices_unsorted;
use std::collections::{HashMap, HashSet};
use tree_hash::TreeHash;
use types::*;

#[derive(Clone)]
pub struct WinningRoot {
    pub crosslink: Crosslink,
    pub attesting_validator_indices: Vec<usize>,
    pub total_attesting_balance: u64,
}

impl WinningRoot {
    /// Returns `true` if `self` is a "better" candidate than `other`.
    ///
    /// A winning root is "better" than another if it has a higher `total_attesting_balance`. Ties
    /// are broken by favouring the higher `crosslink_data_root` value.
    ///
    /// Spec v0.6.1
    pub fn is_better_than(&self, other: &Self) -> bool {
        (
            self.total_attesting_balance,
            self.crosslink.crosslink_data_root,
        ) > (
            other.total_attesting_balance,
            other.crosslink.crosslink_data_root,
        )
    }
}

/// Returns the `crosslink_data_root` with the highest total attesting balance for the given shard.
/// Breaks ties by favouring the smaller `crosslink_data_root` hash.
///
/// The `WinningRoot` object also contains additional fields that are useful in later stages of
/// per-epoch processing.
///
/// Spec v0.6.1
pub fn winning_root<T: EthSpec>(
    state: &BeaconState<T>,
    shard: u64,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<Option<WinningRoot>, BeaconStateError> {
    let shard_attestations: Vec<&PendingAttestation> = state
        .get_matching_source_attestations(epoch)?
        .iter()
        .filter(|a| a.data.shard == shard)
        .collect();

    let shard_crosslinks = shard_attestations.iter().map(|att| {
        (
            att,
            state.get_crosslink_from_attestation_data(&att.data, spec),
        )
    });

    let current_shard_crosslink_root = state.current_crosslinks[shard as usize].tree_hash_root();
    let candidate_crosslinks = shard_crosslinks.filter(|(_, c)| {
        c.previous_crosslink_root.as_bytes() == &current_shard_crosslink_root[..]
            || c.tree_hash_root() == current_shard_crosslink_root
    });

    // Build a map from candidate crosslink to attestations that support that crosslink.
    let mut candidate_crosslink_map: HashMap<Crosslink, Vec<&PendingAttestation>> = HashMap::new();

    for (&attestation, crosslink) in candidate_crosslinks {
        let supporting_attestations = candidate_crosslink_map
            .entry(crosslink)
            .or_insert_with(Vec::new);
        supporting_attestations.push(attestation);
    }

    if candidate_crosslink_map.is_empty() {
        return Ok(None);
    }

    let mut winning_root = None;
    for (crosslink, attestations) in candidate_crosslink_map {
        let attesting_validator_indices =
            get_unslashed_attesting_indices_unsorted(state, &attestations, spec)?;
        let total_attesting_balance =
            state.get_total_balance(&attesting_validator_indices, spec)?;

        let candidate = WinningRoot {
            crosslink,
            attesting_validator_indices,
            total_attesting_balance,
        };

        if let Some(ref winner) = winning_root {
            if candidate.is_better_than(&winner) {
                winning_root = Some(candidate);
            }
        } else {
            winning_root = Some(candidate);
        }
    }

    Ok(winning_root)
}

pub fn get_unslashed_attesting_indices_unsorted<T: EthSpec>(
    state: &BeaconState<T>,
    attestations: &[&PendingAttestation],
    spec: &ChainSpec,
) -> Result<Vec<usize>, BeaconStateError> {
    let mut output = HashSet::new();
    for a in attestations {
        output.extend(get_attesting_indices_unsorted(
            state,
            &a.data,
            &a.aggregation_bitfield,
            spec,
        )?);
    }
    Ok(output
        .into_iter()
        .filter(|index| {
            state
                .validator_registry
                .get(*index)
                .map_or(false, |v| !v.slashed)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_better_than() {
        let worse = WinningRoot {
            crosslink: Crosslink {
                epoch: Epoch::new(0),
                previous_crosslink_root: Hash256::from_slice(&[0; 32]),
                crosslink_data_root: Hash256::from_slice(&[1; 32]),
            },
            attesting_validator_indices: vec![],
            total_attesting_balance: 42,
        };

        let mut better = worse.clone();
        better.crosslink.crosslink_data_root = Hash256::from_slice(&[2; 32]);

        assert!(better.is_better_than(&worse));

        let better = WinningRoot {
            total_attesting_balance: worse.total_attesting_balance + 1,
            ..worse.clone()
        };

        assert!(better.is_better_than(&worse));
    }
}
