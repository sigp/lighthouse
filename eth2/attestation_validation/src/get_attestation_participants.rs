//! This implements [`get_attestation_participants`]
//! (https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#get_attestation_participants)

use failure::{Error, Fail};
use types::{AttestationData, BeaconState, Bitfield, ShardCommittee};

#[derive(Debug, Fail)]
/// An error type for `get_attestation_participants()` problems
pub enum AttestationParticipantError {
    #[fail(
        display = "Invalid aggregation_bitfield size: {}, expected {}",
        got, expected
    )]
    /// The participation bitfield was the wrong size
    InvalidBitfieldSize { expected: usize, got: usize },
    #[fail(
        display = "No crosslink committee found in attestation data shart {}",
        _0
    )]
    /// The attestation data shard doesn't match any committee's shard
    NoMatchingShard(u64),
}

use self::AttestationParticipantError::*;

fn dummy_get_crosslink_committees_at_slot(
    state: &BeaconState,
    slot: u64,
) -> Result<Vec<ShardCommittee>, Error> {
    Ok(vec![])
}

/// Get validator indices partaking in the attestation described by `attestation_data` and
/// `aggregation_bitfield`.
pub fn get_attestation_participants(
    state: &BeaconState,
    attestation_data: &AttestationData,
    aggregation_bitfield: &Bitfield,
) -> Result<Vec<usize>, Error> {
    // Find the committee in the list with the desired shard
    let crosslink_committees =
        dummy_get_crosslink_committees_at_slot(state, attestation_data.slot)?;
    let crosslink_committee = match crosslink_committees
        .iter()
        .filter(|committee| committee.shard == attestation_data.shard)
        .nth(0)
    {
        Some(committee) => committee,
        None => return Err(NoMatchingShard(attestation_data.shard).into()),
    };

    let desired_bitfield_len = (crosslink_committee.len() + 7) / 8;
    // The Bitfield type is bit-indexed while the spec assumes the byte-indexed Python bytes()
    if aggregation_bitfield.num_bytes() != desired_bitfield_len {
        return Err(InvalidBitfieldSize {
            expected: aggregation_bitfield.num_bytes(),
            got: desired_bitfield_len,
        }
        .into());
    }

    // Find the participating attesters in the committee
    let mut participants = vec![];
    for (i, validator_index) in crosslink_committee.committee.iter().enumerate() {
        // Again, we need `to_bytes()` because the spec assumes a byte-indexed vec
        let aggregation_bit = (aggregation_bitfield.to_bytes()[i / 8] >> (7 - (i % 8))) % 2;

        if aggregation_bit == 1 {
            participants.push(*validator_index);
        }
    }

    Ok(participants)
}
