use super::WinningRootError;
use types::*;

#[derive(Clone)]
pub struct WinningRoot {
    pub shard_block_root: Hash256,
    pub attesting_validator_indices: Vec<usize>,
    pub total_balance: u64,
    pub total_attesting_balance: u64,
}

fn winning_root(
    state: &BeaconState,
    shard: u64,
    current_epoch_attestations: &[&PendingAttestation],
    previous_epoch_attestations: &[&PendingAttestation],
    spec: &ChainSpec,
) -> Result<WinningRoot, WinningRootError> {
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

        let attesting_validator_indices = attestations
            .iter()
            .try_fold::<_, _, Result<_, BeaconStateError>>(vec![], |mut acc, a| {
                if (a.data.shard == shard) && (a.data.shard_block_root == *shard_block_root) {
                    acc.append(&mut state.get_attestation_participants(
                        &a.data,
                        &a.aggregation_bitfield,
                        spec,
                    )?);
                }
                Ok(acc)
            })?;

        let total_balance: u64 = attesting_validator_indices
            .iter()
            .fold(0, |acc, i| acc + state.get_effective_balance(*i, spec));

        let total_attesting_balance: u64 = attesting_validator_indices
            .iter()
            .fold(0, |acc, i| acc + state.get_effective_balance(*i, spec));

        if total_attesting_balance > highest_seen_balance {
            highest_seen_balance = total_attesting_balance;
        }

        let candidate_root = WinningRoot {
            shard_block_root: *shard_block_root,
            attesting_validator_indices,
            total_attesting_balance,
            total_balance,
        };

        candidates.insert(*shard_block_root, candidate_root);
    }

    Ok(candidates
        .iter()
        .filter_map(|(_hash, candidate)| {
            if candidate.total_attesting_balance == highest_seen_balance {
                Some(candidate)
            } else {
                None
            }
        })
        .min_by_key(|candidate| candidate.shard_block_root)
        .ok_or_else(|| WinningRootError::NoWinningRoot)?
        // TODO: avoid clone.
        .clone())
}
