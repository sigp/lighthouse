use super::get_attestation_participants::get_attestation_participants;
use std::collections::HashSet;
use std::iter::FromIterator;
use types::*;

#[derive(Clone)]
pub struct WinningRoot {
    pub crosslink_data_root: Hash256,
    pub attesting_validator_indices: Vec<usize>,
    pub total_attesting_balance: u64,
}

impl WinningRoot {
    /// Returns `true` if `self` is a "better" candidate than `other`.
    ///
    /// A winning root is "better" than another if it has a higher `total_attesting_balance`. Ties
    /// are broken by favouring the higher `crosslink_data_root` value.
    ///
    /// Spec v0.5.1
    pub fn is_better_than(&self, other: &Self) -> bool {
        if self.total_attesting_balance > other.total_attesting_balance {
            true
        } else if self.total_attesting_balance == other.total_attesting_balance {
            self.crosslink_data_root > other.crosslink_data_root
        } else {
            false
        }
    }
}

/// Returns the `crosslink_data_root` with the highest total attesting balance for the given shard.
/// Breaks ties by favouring the smaller `crosslink_data_root` hash.
///
/// The `WinningRoot` object also contains additional fields that are useful in later stages of
/// per-epoch processing.
///
/// Spec v0.5.1
pub fn winning_root<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    shard: u64,
    spec: &ChainSpec,
) -> Result<Option<WinningRoot>, BeaconStateError> {
    let mut winning_root: Option<WinningRoot> = None;

    let crosslink_data_roots: HashSet<Hash256> = HashSet::from_iter(
        state
            .previous_epoch_attestations
            .iter()
            .chain(state.current_epoch_attestations.iter())
            .filter_map(|a| {
                if is_eligible_for_winning_root(state, a, shard) {
                    Some(a.data.crosslink_data_root)
                } else {
                    None
                }
            }),
    );

    for crosslink_data_root in crosslink_data_roots {
        let attesting_validator_indices =
            get_attesting_validator_indices(state, shard, &crosslink_data_root, spec)?;

        let total_attesting_balance: u64 =
            attesting_validator_indices
                .iter()
                .try_fold(0_u64, |acc, i| {
                    state
                        .get_effective_balance(*i, spec)
                        .and_then(|bal| Ok(acc + bal))
                })?;

        let candidate = WinningRoot {
            crosslink_data_root,
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

/// Returns `true` if pending attestation `a` is eligible to become a winning root.
///
/// Spec v0.5.1
fn is_eligible_for_winning_root<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    a: &PendingAttestation,
    shard: Shard,
) -> bool {
    if shard >= state.latest_crosslinks.len() as u64 {
        return false;
    }

    a.data.previous_crosslink == state.latest_crosslinks[shard as usize]
}

/// Returns all indices which voted for a given crosslink. Does not contain duplicates.
///
/// Spec v0.5.1
fn get_attesting_validator_indices<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    shard: u64,
    crosslink_data_root: &Hash256,
    spec: &ChainSpec,
) -> Result<Vec<usize>, BeaconStateError> {
    let mut indices = vec![];

    for a in state
        .current_epoch_attestations
        .iter()
        .chain(state.previous_epoch_attestations.iter())
    {
        if (a.data.shard == shard) && (a.data.crosslink_data_root == *crosslink_data_root) {
            indices.append(&mut get_attestation_participants(
                state,
                &a.data,
                &a.aggregation_bitfield,
                spec,
            )?);
        }
    }

    // Sort the list (required for dedup). "Unstable" means the sort may re-order equal elements,
    // this causes no issue here.
    //
    // These sort + dedup ops are potentially good CPU time optimisation targets.
    indices.sort_unstable();
    // Remove all duplicate indices (requires a sorted list).
    indices.dedup();

    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_better_than() {
        let worse = WinningRoot {
            crosslink_data_root: Hash256::from_slice(&[1; 32]),
            attesting_validator_indices: vec![],
            total_attesting_balance: 42,
        };

        let better = WinningRoot {
            crosslink_data_root: Hash256::from_slice(&[2; 32]),
            ..worse.clone()
        };

        assert!(better.is_better_than(&worse));

        let better = WinningRoot {
            total_attesting_balance: worse.total_attesting_balance + 1,
            ..worse.clone()
        };

        assert!(better.is_better_than(&worse));
    }
}
