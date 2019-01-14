extern crate honey_badger_split;
extern crate spec;
extern crate types;
extern crate vec_shuffle;

use byteorder::{BigEndian, ByteOrder};

use spec::ChainSpec;
use types::{validator_registry::get_active_validator_indices, Hash256, ValidatorRecord};
use vec_shuffle::{shuffle, ShuffleErr};

#[derive(Debug, PartialEq)]
pub enum ValidatorAssignmentError {
    TooManyValidators,
    TooFewShards,
}

/// Spec: https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#get_committee_count_per_slot
pub fn get_committee_count_per_slot(active_validator_count: usize) -> usize {
    let spec = ChainSpec::foundation();
    *[
        1usize,
        *[
            (spec.shard_count / spec.epoch_length) as usize,
            active_validator_count
                / spec.epoch_length as usize
                / spec.target_committee_size as usize,
        ]
        .iter()
        .min()
        .unwrap(),
    ]
    .iter()
    .max()
    .unwrap()
}

/// Spec: https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#split
pub fn split<T: Clone>(values: Vec<T>, split_count: usize) -> Vec<Vec<T>> {
    let list_length = values.len();

    let mut ret = Vec::new();

    for i in 0..split_count {
        let start_idx = list_length * i / split_count;
        let end_idx = list_length * (i + 1) / split_count;
        ret.push(values[start_idx..end_idx].into());
    }

    return ret;
}

/// Implements [`get_shuffling`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#get_shuffling).
/// Delegates active validators into slots for a given cycle, given a random seed.
/// Returns a vector of validator index vectors representing the committees each slot.
pub fn get_shuffling(
    seed: Hash256,
    validators: &[ValidatorRecord],
    mut slot: u64,
) -> Result<Vec<Vec<usize>>, ValidatorAssignmentError> {
    let spec = ChainSpec::foundation();

    // Normalizes slot to start of epoch boundary
    slot -= slot % spec.epoch_length;

    let active_validator_indices = get_active_validator_indices(validators, slot);
    let committees_per_slot = get_committee_count_per_slot(active_validator_indices.len());

    // Shuffle
    let xored_seed: Vec<u8> = {
        let mut slot_bytes = vec![0u8; 8];
        BigEndian::write_u64(&mut slot_bytes, slot);

        let mut slot_bytes32 = vec![0u8; 24];
        slot_bytes32.append(&mut slot_bytes.to_vec());

        (*seed) // Deref turns Hash256 into a u8 slice
            .iter()
            .zip(slot_bytes32)
            .map(|(seed_byte, slot_byte)| seed_byte ^ slot_byte) // xor(seed, bytes32(slot))
            .collect()
    };

    let shuffled_validator_indices = shuffle(&xored_seed, active_validator_indices)?;

    return Ok(split(
        shuffled_validator_indices,
        committees_per_slot * spec.epoch_length as usize,
    ));
}

impl From<ShuffleErr> for ValidatorAssignmentError {
    fn from(e: ShuffleErr) -> ValidatorAssignmentError {
        match e {
            ShuffleErr::ExceedsListLength => ValidatorAssignmentError::TooManyValidators,
        }
    }
}
