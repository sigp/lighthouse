use super::validator_historical_attestation::ValidatorHistoricalAttestation;
use types::*;
use tree_hash::TreeHash;

#[derive(PartialEq, Debug)]
pub enum PruningError {
    TargetEpochTooSmall(Epoch),
    SourceEpochTooSmall(Epoch),
}

#[derive(PartialEq, Debug)]
pub enum AttestationError {
    DoubleVote,
    InvalidAttestationData {
        source: Checkpoint,
        target: Checkpoint,
    },
    PruningError(PruningError),
    Surrounded,
    Surrounding,
}

#[derive(PartialEq, Debug)]
pub enum ValidAttestation {
    EmptyHistory,
    SameVote,
    ValidAttestation,
}

fn check_attestation_validity(attestation_data: &AttestationData) -> Result<(), AttestationError> {
    if attestation_data.target.epoch <= attestation_data.source.epoch {
        Err(AttestationError::InvalidAttestationData {
            source: attestation_data.source.clone(),
            target: attestation_data.target.clone(),
        })
    } else {
        Ok(())
    }
}

fn check_surrounded(
    attestation_data: &AttestationData,
    attestation_history: &[ValidatorHistoricalAttestation],
) -> Result<(), AttestationError> {
    let surrounded = attestation_history.iter().any(|historical_attestation| {
        historical_attestation.source_epoch < attestation_data.source.epoch
    });
    if surrounded {
        Err(AttestationError::Surrounded)
    } else {
        Ok(())
    }
}

fn check_surrounding(
    attestation_data: &AttestationData,
    attestation_history: &[ValidatorHistoricalAttestation],
) -> Result<(), AttestationError> {
    let surrounding = attestation_history.iter().any(|historical_attestation| {
        historical_attestation.source_epoch > attestation_data.source.epoch
    });
    if surrounding {
        Err(AttestationError::Surrounding)
    } else {
        Ok(())
    }
}

pub fn should_sign_attestation(
    attestation_data: &AttestationData,
    attestation_history: &[ValidatorHistoricalAttestation],
) -> Result<(ValidAttestation), AttestationError> {
    check_attestation_validity(attestation_data)?;
    if attestation_history.is_empty() {
        return Ok(ValidAttestation::EmptyHistory);
    }

    let target_index = match attestation_history
        .iter()
        .rev()
        .position(|historical_attestation| {
            historical_attestation.target_epoch <= attestation_data.target.epoch
        }) {
        None => {
            return Err(AttestationError::PruningError(
                PruningError::TargetEpochTooSmall(attestation_data.target.epoch),
            ))
        }
        Some(index) => attestation_history.len() - index - 1,
    };

    check_surrounded(attestation_data, &attestation_history[target_index + 1..])?;
    if attestation_history[target_index].target_epoch == attestation_data.target.epoch {
        if attestation_history[target_index].signing_root == Hash256::from_slice(&attestation_data.tree_hash_root()) {
            return Ok(ValidAttestation::SameVote);
        } else {
            return Err(AttestationError::DoubleVote);
        }
    }

    let source_index =
        match attestation_history[..=target_index]
            .iter()
            .rev()
            .position(|historical_attestation| {
                historical_attestation.target_epoch <= attestation_data.source.epoch
            }) {
            None => {
                if attestation_data.source.epoch == 0 {
                    // Special case for genesis
                    0
                } else {
                    return Err(AttestationError::PruningError(
                        PruningError::SourceEpochTooSmall(attestation_data.source.epoch),
                    ));
                }
            }
            Some(index) => target_index - index + 1,
        };

    check_surrounding(
        attestation_data,
        &attestation_history[source_index..=target_index],
    )?;

    Ok(ValidAttestation::ValidAttestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_checkpoint(epoch_num: u64) -> Checkpoint {
	    Checkpoint {
	    	epoch: Epoch::from(epoch_num),
		    root: Hash256::zero(),
	    }
    }

    fn attestation_builder(source: u64, target: u64) -> AttestationData {
    	let source = build_checkpoint(source);
    	let target = build_checkpoint(target);
    	let crosslink = Crosslink::default();

    	AttestationData {
    		beacon_block_root: Hash256::zero(),
    		source,
    		target,
    		crosslink,
    	}
    }

    #[test]
    fn valid_simple_test() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_builder(2, 3);

        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Ok(ValidAttestation::ValidAttestation)
        );
    }

    #[test]
    fn valid_empty_history() {
        let history = vec![];

        let attestation_data = attestation_builder(2, 3);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Ok(ValidAttestation::EmptyHistory)
        );
    }

    #[test]
    fn valid_cast_same_vote() {
        let mut history = vec![];

        let attestation_data = attestation_builder(0, 1);

        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::from_slice(&attestation_data.tree_hash_root())));
        history.push(ValidatorHistoricalAttestation::new(1, 2, Hash256::random()));

        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Ok(ValidAttestation::SameVote)
        );
    }

    #[test]
    fn invalid_double_vote() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_builder(0, 1);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::DoubleVote)
        );
    }

    #[test]
    fn invalid_surround_one_vote() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(1, 2, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(2, 3, Hash256::random()));

        let attestation_data = attestation_builder(1, 4);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounding)
        );
    }

    #[test]
    fn invalid_surround_one_vote_from_genesis() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_builder(0, 3);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounding)
        );
    }

    #[test]
    fn invalid_surround_multiple_votes() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(1, 2, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(2, 3, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(3, 4, Hash256::random()));

        let attestation_data = attestation_builder(1, 5);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounding)
        );
    }

    #[test]
    fn invalid_surrounded_by_one_vote() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(1, 6, Hash256::random()));

        let attestation_data = attestation_builder(2, 3);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounded)
        );
    }

    #[test]
    fn invalid_surrounded_by_multiple_votes() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(1, 6, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(2, 5, Hash256::random()));

        let attestation_data = attestation_builder(3, 4);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounded)
        );
    }

    #[test]
    fn invalid_surrounded_by_one_vote_from_genesis() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(0, 3, Hash256::random()));

        let attestation_data = attestation_builder(1, 2);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounded)
        );
    }

    #[test]
    fn invalid_surrounding_last_vote() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(0, 2, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(2, 3, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(4, 9, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(5, 10, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(6, 11, Hash256::random()));

        let attestation_data = attestation_builder(1, 8);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounding)
        );
    }

    #[test]
    fn invalid_prunning_error_target_too_small() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_builder(4, 5);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::PruningError(
                PruningError::TargetEpochTooSmall(Epoch::from(5u64))
            ))
        );
    }

    #[test]
    fn invalid_prunning_error_source_too_small() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_builder(4, 227);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::PruningError(
                PruningError::SourceEpochTooSmall(Epoch::from(4u64))
            ))
        );
    }

    #[test]
    fn invalid_surrounding_first_vote() {
        let mut history = vec![];
        history.push(ValidatorHistoricalAttestation::new(0, 1, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(0, 2, Hash256::random()));
        history.push(ValidatorHistoricalAttestation::new(2, 3, Hash256::random()));

        let attestation_data = attestation_builder(1, 4);
        assert_eq!(
            should_sign_attestation(&attestation_data, &history[..]),
            Err(AttestationError::Surrounding)
        );
    }
}
