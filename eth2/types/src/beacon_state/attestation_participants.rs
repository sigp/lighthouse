use crate::{
    beacon_state::CommitteesError, AttestationData, BeaconState, Bitfield, ChainSpec,
    PendingAttestation,
};
use log::debug;

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
        let mut all_participants = attestations
            .iter()
            .try_fold::<_, _, Result<Vec<usize>, Error>>(vec![], |mut acc, a| {
                acc.append(&mut self.get_attestation_participants(
                    &a.data,
                    &a.aggregation_bitfield,
                    spec,
                )?);
                Ok(acc)
            })?;
        all_participants.sort_unstable();
        all_participants.dedup();
        Ok(all_participants)
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

        let committee_index: usize = crosslink_committees
            .iter()
            .position(|(_committee, shard)| *shard == attestation_data.shard)
            .ok_or_else(|| Error::NoCommitteeForShard)?;
        let (crosslink_committee, _shard) = &crosslink_committees[committee_index];

        /*
         * TODO: that bitfield length is valid.
         *
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
