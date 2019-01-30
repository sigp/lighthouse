use super::crosslink::Crosslink;
use super::eth1_data::Eth1Data;
use super::eth1_data_vote::Eth1DataVote;
use super::fork::Fork;
use super::pending_attestation::PendingAttestation;
use super::ssz::{hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use super::validator::Validator;
use super::validator_registry::get_active_validator_indices;
use super::Hash256;
use crate::test_utils::TestRandom;
use hashing::canonical_hash;
use honey_badger_split::SplitExt;
use rand::RngCore;
use std::cmp;

// TODO this function is not implemented
// NOTE: just splits the current active set, does not shuffle!
fn get_shuffling(
    _seed: Hash256,
    validators: &[Validator],
    epoch: u64,
    committees_per_epoch: u64,
) -> Vec<Vec<usize>> {
    get_active_validator_indices(validators, epoch)
        .honey_badger_split(committees_per_epoch as usize)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>()
}

fn slot_to_epoch(slot: u64, epoch_length: u64) -> u64 {
    slot / epoch_length
}

/// this function computes how many committees should exist for every slot (within an epoch), given some number of validators active within that epoch.
fn get_epoch_committee_count(
    active_validator_count: usize,
    shard_count: u64,
    epoch_length: u64,
    target_committee_size: u64,
) -> u64 {
    cmp::max(
        1,
        cmp::min(
            shard_count / epoch_length,
            active_validator_count as u64 / epoch_length / target_committee_size,
        ),
    ) * epoch_length
}

// Custody will not be added to the specs until Phase 1 (Sharding Phase) so dummy class used.
type CustodyChallenge = usize;

// CrosslinkCommittee represents a pair of validator indices along with the shard they are expected to crosslink this epoch.
// A convenient type alias for later...
type CrosslinkCommittee = (Vec<usize>, u64);

#[derive(Debug, PartialEq, Clone, Default)]
pub struct BeaconState {
    // Misc
    pub slot: u64,
    pub genesis_time: u64,
    pub fork_data: Fork,

    // Validator registry
    pub validator_registry: Vec<Validator>,
    pub validator_balances: Vec<u64>,
    pub validator_registry_update_slot: u64,
    pub validator_registry_exit_count: u64,
    pub validator_registry_delta_chain_tip: Hash256,

    // Randomness and committees
    pub latest_randao_mixes: Vec<Hash256>,
    pub latest_vdf_outputs: Vec<Hash256>,
    pub previous_epoch_start_shard: u64,
    pub current_epoch_start_shard: u64,
    pub previous_calculation_epoch: u64,
    pub current_calculation_epoch: u64,
    pub previous_epoch_seed: Hash256,
    pub current_epoch_seed: Hash256,

    // Custody challenges
    pub custody_challenges: Vec<CustodyChallenge>,

    // Finality
    pub previous_justified_slot: u64,
    pub justified_slot: u64,
    pub justification_bitfield: u64,
    pub finalized_slot: u64,

    // Recent state
    pub latest_crosslinks: Vec<Crosslink>,
    pub latest_block_roots: Vec<Hash256>,
    pub latest_penalized_exit_balances: Vec<u64>,
    pub latest_attestations: Vec<PendingAttestation>,
    pub batched_block_roots: Vec<Hash256>,

    // Ethereum 1.0 chain data
    pub latest_eth1_data: Eth1Data,
    pub eth1_data_votes: Vec<Eth1DataVote>,
}

#[derive(PartialEq, Debug)]
pub enum Error {
    InvalidSlot,
    InsufficientNumberOfValidators,
}

type Result<T> = std::result::Result<T, Error>;

impl BeaconState {
    pub fn canonical_root(&self) -> Hash256 {
        // TODO: implement tree hashing.
        // https://github.com/sigp/lighthouse/issues/70
        Hash256::from(&canonical_hash(&ssz_encode(self))[..])
    }

    fn get_current_epoch(&self, epoch_length: u64) -> u64 {
        slot_to_epoch(self.slot, epoch_length)
    }

    fn get_previous_epoch_committee_count(
        &self,
        shard_count: u64,
        epoch_length: u64,
        target_committee_size: u64,
    ) -> u64 {
        let previous_active_validators =
            get_active_validator_indices(&self.validator_registry, self.previous_calculation_epoch);
        get_epoch_committee_count(
            previous_active_validators.len(),
            shard_count,
            epoch_length,
            target_committee_size,
        )
    }

    fn get_current_epoch_committee_count(
        &self,
        shard_count: u64,
        epoch_length: u64,
        target_committee_size: u64,
    ) -> u64 {
        let current_active_validators =
            get_active_validator_indices(&self.validator_registry, self.current_calculation_epoch);
        get_epoch_committee_count(
            current_active_validators.len(),
            shard_count,
            epoch_length,
            target_committee_size,
        )
    }

    /// Returns the collection of `(committee, shard)` tuples for the requested `slot`.
    /// NOTE: a `committee` here is a finite sequence of validator indices and the `shard` is the shard number.
    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: u64,
        epoch_length: u64,
        shard_count: u64,
        target_committee_size: u64,
        genesis_epoch: u64,
    ) -> Result<Vec<CrosslinkCommittee>> {
        let epoch = slot_to_epoch(slot, epoch_length);
        let current_epoch = self.get_current_epoch(epoch_length);
        let previous_epoch = if current_epoch > genesis_epoch {
            current_epoch - 1
        } else {
            current_epoch
        };
        let next_epoch = current_epoch + 1;

        if epoch < previous_epoch || epoch >= next_epoch {
            return Err(Error::InvalidSlot);
        }

        let (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard) =
            if epoch < current_epoch {
                let committees_per_epoch = self.get_previous_epoch_committee_count(
                    shard_count,
                    epoch_length,
                    target_committee_size,
                );
                let seed = self.previous_epoch_seed;
                let shuffling_epoch = self.previous_calculation_epoch;
                let shuffling_start_shard = self.previous_epoch_start_shard;
                (
                    committees_per_epoch,
                    seed,
                    shuffling_epoch,
                    shuffling_start_shard,
                )
            } else {
                let committees_per_epoch = self.get_current_epoch_committee_count(
                    shard_count,
                    epoch_length,
                    target_committee_size,
                );
                let seed = self.current_epoch_seed;
                let shuffling_epoch = self.current_calculation_epoch;
                let shuffling_start_shard = self.current_epoch_start_shard;
                (
                    committees_per_epoch,
                    seed,
                    shuffling_epoch,
                    shuffling_start_shard,
                )
            };

        // TODO: following callsite will need to be adjusted with correct `get_shuffling`
        let shuffling = get_shuffling(
            seed,
            &self.validator_registry,
            shuffling_epoch,
            committees_per_epoch,
        );
        let offset = slot % epoch_length;
        let committees_per_slot = committees_per_epoch / epoch_length;
        let slot_start_shard = (shuffling_start_shard + committees_per_slot * offset) % shard_count;

        let shard_range = slot_start_shard..;
        Ok(shuffling
            .into_iter()
            .skip((committees_per_slot * offset) as usize)
            .zip(shard_range.into_iter())
            .take(committees_per_slot as usize)
            .map(|(committees, shard_number)| (committees, shard_number % shard_count))
            .collect::<Vec<_>>())
    }

    /// Returns the beacon proposer index for the `slot`.
    /// If the slot is outside the bounds of what can currently be calculated from the state, an `Err` is returned.
    /// If the requested slot does not have a proposer, `None` is returned.
    pub fn get_beacon_proposer_index(
        &self,
        slot: u64,
        epoch_length: u64,
        shard_count: u64,
        target_committee_size: u64,
        genesis_epoch: u64,
    ) -> Result<Option<usize>> {
        let committees = self.get_crosslink_committees_at_slot(
            slot,
            epoch_length,
            shard_count,
            target_committee_size,
            genesis_epoch,
        )?;

        // NOTE: invariant that `get_crosslink_committees_at_slot` will always return at least one element.
        let first_committee = &committees.first().unwrap().0;

        let result = if let Some(index) = (slot as usize).checked_rem(first_committee.len()) {
            Some(first_committee[index])
        } else {
            None
        };
        Ok(result)
    }
}

impl Encodable for BeaconState {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.genesis_time);
        s.append(&self.fork_data);
        s.append(&self.validator_registry);
        s.append(&self.validator_balances);
        s.append(&self.validator_registry_update_slot);
        s.append(&self.validator_registry_exit_count);
        s.append(&self.validator_registry_delta_chain_tip);
        s.append(&self.latest_randao_mixes);
        s.append(&self.latest_vdf_outputs);
        s.append(&self.previous_epoch_start_shard);
        s.append(&self.current_epoch_start_shard);
        s.append(&self.previous_calculation_epoch);
        s.append(&self.current_calculation_epoch);
        s.append(&self.previous_epoch_seed);
        s.append(&self.current_epoch_seed);
        s.append(&self.custody_challenges);
        s.append(&self.previous_justified_slot);
        s.append(&self.justified_slot);
        s.append(&self.justification_bitfield);
        s.append(&self.finalized_slot);
        s.append(&self.latest_crosslinks);
        s.append(&self.latest_block_roots);
        s.append(&self.latest_penalized_exit_balances);
        s.append(&self.latest_attestations);
        s.append(&self.batched_block_roots);
        s.append(&self.latest_eth1_data);
        s.append(&self.eth1_data_votes);
    }
}

impl Decodable for BeaconState {
    fn ssz_decode(bytes: &[u8], i: usize) -> std::result::Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (genesis_time, i) = <_>::ssz_decode(bytes, i)?;
        let (fork_data, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_update_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_exit_count, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_delta_chain_tip, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_randao_mixes, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_vdf_outputs, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_calculation_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (current_calculation_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_challenges, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_justified_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (justified_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (justification_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (finalized_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_crosslinks, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_penalized_exit_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_attestations, i) = <_>::ssz_decode(bytes, i)?;
        let (batched_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_eth1_data, i) = <_>::ssz_decode(bytes, i)?;
        let (eth1_data_votes, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                genesis_time,
                fork_data,
                validator_registry,
                validator_balances,
                validator_registry_update_slot,
                validator_registry_exit_count,
                validator_registry_delta_chain_tip,
                latest_randao_mixes,
                latest_vdf_outputs,
                previous_epoch_start_shard,
                current_epoch_start_shard,
                previous_calculation_epoch,
                current_calculation_epoch,
                previous_epoch_seed,
                current_epoch_seed,
                custody_challenges,
                previous_justified_slot,
                justified_slot,
                justification_bitfield,
                finalized_slot,
                latest_crosslinks,
                latest_block_roots,
                latest_penalized_exit_balances,
                latest_attestations,
                batched_block_roots,
                latest_eth1_data,
                eth1_data_votes,
            },
            i,
        ))
    }
}

impl TreeHash for BeaconState {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.slot.hash_tree_root());
        result.append(&mut self.genesis_time.hash_tree_root());
        result.append(&mut self.fork_data.hash_tree_root());
        result.append(&mut self.validator_registry.hash_tree_root());
        result.append(&mut self.validator_balances.hash_tree_root());
        result.append(&mut self.validator_registry_update_slot.hash_tree_root());
        result.append(&mut self.validator_registry_exit_count.hash_tree_root());
        result.append(&mut self.validator_registry_delta_chain_tip.hash_tree_root());
        result.append(&mut self.latest_randao_mixes.hash_tree_root());
        result.append(&mut self.latest_vdf_outputs.hash_tree_root());
        result.append(&mut self.previous_epoch_start_shard.hash_tree_root());
        result.append(&mut self.current_epoch_start_shard.hash_tree_root());
        result.append(&mut self.previous_calculation_epoch.hash_tree_root());
        result.append(&mut self.current_calculation_epoch.hash_tree_root());
        result.append(&mut self.previous_epoch_seed.hash_tree_root());
        result.append(&mut self.current_epoch_seed.hash_tree_root());
        result.append(&mut self.custody_challenges.hash_tree_root());
        result.append(&mut self.previous_justified_slot.hash_tree_root());
        result.append(&mut self.justified_slot.hash_tree_root());
        result.append(&mut self.justification_bitfield.hash_tree_root());
        result.append(&mut self.finalized_slot.hash_tree_root());
        result.append(&mut self.latest_crosslinks.hash_tree_root());
        result.append(&mut self.latest_block_roots.hash_tree_root());
        result.append(&mut self.latest_penalized_exit_balances.hash_tree_root());
        result.append(&mut self.latest_attestations.hash_tree_root());
        result.append(&mut self.batched_block_roots.hash_tree_root());
        result.append(&mut self.latest_eth1_data.hash_tree_root());
        result.append(&mut self.eth1_data_votes.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for BeaconState {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            genesis_time: <_>::random_for_test(rng),
            fork_data: <_>::random_for_test(rng),
            validator_registry: <_>::random_for_test(rng),
            validator_balances: <_>::random_for_test(rng),
            validator_registry_update_slot: <_>::random_for_test(rng),
            validator_registry_exit_count: <_>::random_for_test(rng),
            validator_registry_delta_chain_tip: <_>::random_for_test(rng),
            latest_randao_mixes: <_>::random_for_test(rng),
            latest_vdf_outputs: <_>::random_for_test(rng),
            previous_epoch_start_shard: <_>::random_for_test(rng),
            current_epoch_start_shard: <_>::random_for_test(rng),
            previous_calculation_epoch: <_>::random_for_test(rng),
            current_calculation_epoch: <_>::random_for_test(rng),
            previous_epoch_seed: <_>::random_for_test(rng),
            current_epoch_seed: <_>::random_for_test(rng),
            custody_challenges: <_>::random_for_test(rng),
            previous_justified_slot: <_>::random_for_test(rng),
            justified_slot: <_>::random_for_test(rng),
            justification_bitfield: <_>::random_for_test(rng),
            finalized_slot: <_>::random_for_test(rng),
            latest_crosslinks: <_>::random_for_test(rng),
            latest_block_roots: <_>::random_for_test(rng),
            latest_penalized_exit_balances: <_>::random_for_test(rng),
            latest_attestations: <_>::random_for_test(rng),
            batched_block_roots: <_>::random_for_test(rng),
            latest_eth1_data: <_>::random_for_test(rng),
            eth1_data_votes: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconState::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconState::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }

    #[test]
    fn test_get_crosslink_committees_at_slot() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut state = BeaconState::random_for_test(&mut rng);

        // TODO test at {1, high} validator count

        let epoch_length = 64;
        let shard_count = 1024;
        let target_committee_size = 128;
        let genesis_epoch = 0;

        let current_epoch = state.get_current_epoch(epoch_length);
        let current_epoch_start_slot = current_epoch * epoch_length;
        let current_epoch_end_slot = current_epoch_start_slot + epoch_length;

        // TODO test at the first, second epoch...
        let previous_epoch = current_epoch.checked_sub(1).unwrap_or(0);
        let previous_epoch_start_slot = previous_epoch * epoch_length;

        let slot_before_previous_epoch = previous_epoch_start_slot.checked_sub(10).unwrap_or(0);
        let slot_after_current_epoch = current_epoch_start_slot
            .checked_add(epoch_length + 10)
            .unwrap_or(std::u64::MAX);

        let activation_epoch = current_epoch.checked_sub(100).unwrap_or(0);
        for validator in &mut state.validator_registry {
            validator.activation_epoch = activation_epoch;
        }

        for slot in slot_before_previous_epoch..previous_epoch_start_slot {
            let result = state.get_crosslink_committees_at_slot(
                slot,
                epoch_length,
                shard_count,
                target_committee_size,
                genesis_epoch,
            );
            match result {
                Ok(_) => panic!("should not return crosslink committee for early slot"),
                Err(e) => assert_eq!(
                    e,
                    Error::InvalidSlot,
                    "returned wrong error for early slot to crosslink committee helper"
                ),
            }
        }

        for slot in current_epoch_end_slot..slot_after_current_epoch {
            let result = state.get_crosslink_committees_at_slot(
                slot,
                epoch_length,
                shard_count,
                target_committee_size,
                genesis_epoch,
            );
            match result {
                Ok(_) => panic!("should not return crosslink committee for future slot"),
                Err(e) => assert_eq!(
                    e,
                    Error::InvalidSlot,
                    "returned wrong error for future slot to crosslink committee helper"
                ),
            }
        }

        for slot in previous_epoch_start_slot..current_epoch_start_slot {
            let result = state.get_crosslink_committees_at_slot(
                slot,
                epoch_length,
                shard_count,
                target_committee_size,
                genesis_epoch,
            );
            match result {
                Ok(committees) => {
                    let committees_per_epoch = state.get_previous_epoch_committee_count(
                        shard_count,
                        epoch_length,
                        target_committee_size,
                    );
                    let seed = state.previous_epoch_seed;
                    let shuffling_epoch = state.previous_calculation_epoch;
                    let shuffling_start_shard = state.previous_epoch_start_shard;

                    let shuffling = get_shuffling(
                        seed,
                        &state.validator_registry,
                        shuffling_epoch,
                        committees_per_epoch,
                    );
                    let offset = slot % epoch_length;
                    let committees_per_slot = committees_per_epoch / epoch_length;
                    let slot_start_shard =
                        (shuffling_start_shard + committees_per_slot * offset) % shard_count;

                    let mut expected_committees = vec![];
                    for i in 0..committees_per_slot {
                        let indices = &shuffling[(committees_per_slot * offset + i) as usize];
                        let shard = (slot_start_shard + i) % shard_count;
                        let committee = (indices.to_vec(), shard);
                        expected_committees.push(committee);
                    }
                    assert_eq!(expected_committees, committees);
                }
                Err(_) => panic!("should return crosslink committee for previous epoch"),
            }
        }

        for slot in current_epoch_start_slot..current_epoch_end_slot {
            let result = state.get_crosslink_committees_at_slot(
                slot,
                epoch_length,
                shard_count,
                target_committee_size,
                genesis_epoch,
            );
            match result {
                Ok(committees) => {
                    let committees_per_epoch = state.get_current_epoch_committee_count(
                        shard_count,
                        epoch_length,
                        target_committee_size,
                    );
                    let seed = state.current_epoch_seed;
                    let shuffling_epoch = state.current_calculation_epoch;
                    let shuffling_start_shard = state.current_epoch_start_shard;

                    let shuffling = get_shuffling(
                        seed,
                        &state.validator_registry,
                        shuffling_epoch,
                        committees_per_epoch,
                    );
                    let offset = slot % epoch_length;
                    let committees_per_slot = committees_per_epoch / epoch_length;
                    let slot_start_shard =
                        (shuffling_start_shard + committees_per_slot * offset) % shard_count;

                    let mut expected_committees = vec![];
                    for i in 0..committees_per_slot {
                        let indices = &shuffling[(committees_per_slot * offset + i) as usize];
                        let shard = (slot_start_shard + i) % shard_count;
                        let committee = (indices.to_vec(), shard);
                        expected_committees.push(committee);
                    }
                    assert_eq!(expected_committees, committees);
                }
                Err(_) => panic!("should return crosslink committee for current epoch"),
            }
        }
    }

    #[test]
    fn test_get_beacon_proposer_index() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut state = BeaconState::random_for_test(&mut rng);

        let epoch_length = 64;
        let shard_count = 1024;
        let target_committee_size = 128;
        let genesis_epoch = 0;

        // TODO test near epochs 0, 1, ...
        state.slot = cmp::min(
            cmp::max(state.slot, state.slot + 10 * epoch_length),
            std::u64::MAX - 10 * epoch_length,
        );

        // TODO test large and small (0, 1, ...) numbers of validators

        let current_epoch = state.get_current_epoch(epoch_length);
        let current_epoch_start_slot = current_epoch * epoch_length;
        let current_epoch_end_slot = current_epoch_start_slot + epoch_length;
        let previous_epoch = current_epoch.checked_sub(1).unwrap_or(0);
        let previous_epoch_start_slot = previous_epoch * epoch_length;

        let activation_epoch = current_epoch.checked_sub(100).unwrap_or(0);
        for validator in &mut state.validator_registry {
            validator.activation_epoch = activation_epoch;
        }

        let some_slot_before_previous_epoch =
            previous_epoch_start_slot.checked_sub(10).unwrap_or(0);
        let some_slot_after_current_epoch = current_epoch_end_slot
            .checked_add(10)
            .unwrap_or(std::u64::MAX);

        for slot in some_slot_before_previous_epoch..previous_epoch_start_slot {
            match state.get_beacon_proposer_index(
                slot,
                epoch_length,
                shard_count,
                target_committee_size,
                genesis_epoch,
            ) {
                Ok(_) => {
                    panic!("should not return beacon proposer index for slot before previous epoch")
                }
                Err(e) => assert_eq!(
                    e,
                    Error::InvalidSlot,
                    "should return invalid slot for slot before previous epoch"
                ),
            }
        }

        for slot in current_epoch_end_slot..some_slot_after_current_epoch {
            match state.get_beacon_proposer_index(
                some_slot_after_current_epoch,
                epoch_length,
                shard_count,
                target_committee_size,
                genesis_epoch,
            ) {
                Ok(_) => {
                    panic!("should not return beacon proposer index for slot before previous epoch")
                }
                Err(e) => assert_eq!(
                    e,
                    Error::InvalidSlot,
                    "should return invalid slot for slot after current epoch"
                ),
            }
        }

        for slot in previous_epoch_start_slot..current_epoch_end_slot {
            match state.get_beacon_proposer_index(
                slot,
                epoch_length,
                shard_count,
                target_committee_size,
                genesis_epoch,
            ) {
                Ok(some_index) => {
                    let committees = state
                        .get_crosslink_committees_at_slot(
                            slot,
                            epoch_length,
                            shard_count,
                            target_committee_size,
                            genesis_epoch,
                        )
                        .unwrap_or_else(|_| panic!("error getting crosslink committees"));
                    let first_committee = &committees.first().unwrap().0;
                    match first_committee.len() {
                        0 => assert_eq!(some_index, None),
                        length => {
                            let committee_index = slot as usize % length;
                            let expected_index = &first_committee[committee_index];
                            match some_index {
                                None => panic!("beacon proposer index should not be `None` if the first committee is non-empty"),
                                Some(index) => assert_eq!(*expected_index, index),
                            }
                        }
                    }
                }
                Err(_) => panic!("should not return error for valid slot"),
            }
        }
    }
}
