use crate::{
    beacon_state::CommitteesError, PendingAttestation, AttestationData, BeaconState, Bitfield, ChainSpec,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    NoCommitteeForShard,
    NoCommittees,
    BadBitfieldLength,
    CommitteesError(CommitteesError),
}

impl BeaconState {
    pub fn get_attestation_participants_union(
        &self,
        attestations: &[&PendingAttestation],
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, Error> {
        attestations.iter().try_fold(vec![], |mut acc, a| {
            acc.append(&mut self.get_attestation_participants(
                &a.data,
                &a.aggregation_bitfield,
                spec,
            )?);
            Ok(acc)
        })
    }

    // TODO: analyse for efficiency improvments. This implementation is naive.
    pub fn get_attestation_participants(
        &self,
        attestation_data: &AttestationData,
        aggregation_bitfield: &Bitfield,
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, Error> {
        let crosslink_committees =
            self.get_crosslink_committees_at_slot(attestation_data.slot, spec)?;

        /*
        let mut shard_present = false;
        for (_committee, shard) in &crosslink_committees {
            println!("want shard: {}, got shard: {}", shard, attestation_data.shard);
            if *shard == attestation_data.shard {
                shard_present = true;
            }
        }
        if !shard_present {
            return Err(Error::NoCommitteeForShard);
        }
        */

        let crosslink_committee: Vec<usize> = crosslink_committees
            .iter()
            .filter_map(|(committee, shard)| {
                if *shard == attestation_data.shard {
                    Some(committee.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<Vec<usize>>>()
            .first()
            .ok_or_else(|| Error::NoCommitteeForShard)?
            .clone();

        /*
         * TODO: check for this condition.
         *
        if aggregation_bitfield.len() != (crosslink_committee.len() + 7) / 8 {
            return Err(Error::BadBitfieldLength);
        }
        */

        let mut participants = vec![];
        for (i, validator_index) in crosslink_committee.iter().enumerate() {
            if aggregation_bitfield.get(i).unwrap() {
                participants.push(*validator_index);
            }
        }
        Ok(participants)
    }
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}
