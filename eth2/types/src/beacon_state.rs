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
use std::ops::Range;

// utility function pending this functionality being stabilized on the `Range` type.
fn range_contains<T: PartialOrd>(range: &Range<T>, target: T) -> bool {
    range.start <= target && target < range.end
}

// TODO this function is not implemented
// NOTE: just splits the current active set, does not shuffle!
fn get_shuffling(
    _seed: Hash256,
    validators: &[Validator],
    epoch: u64,
    committees_per_slot: u64,
    epoch_length: u64,
) -> Vec<Vec<usize>> {
    get_active_validator_indices(validators, epoch)
        .honey_badger_split((committees_per_slot * epoch_length) as usize)
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
    ) -> Result<Vec<(Vec<usize>, u64)>> {
        let current_epoch_range = self.get_current_epoch_boundaries(epoch_length);
        if !range_contains(&current_epoch_range, slot) {
            return Err(Error::InvalidSlot);
        }

        let state_epoch_slot = current_epoch_range.start;
        let offset = slot % epoch_length;

        let (committees_per_slot, shuffling, slot_start_shard) = if slot < state_epoch_slot {
            let committees_per_slot = self.get_previous_epoch_committee_count_per_slot(
                shard_count,
                epoch_length,
                target_committee_size,
            );
            let shuffling = get_shuffling(
                self.previous_epoch_seed,
                &self.validator_registry,
                self.previous_epoch_calculation_slot,
                committees_per_slot,
                epoch_length,
            );
            let slot_start_shard =
                (self.previous_epoch_start_shard + committees_per_slot * offset) % shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        } else {
            let committees_per_slot = self.get_current_epoch_committee_count_per_slot(
                shard_count,
                epoch_length,
                target_committee_size,
            );
            let shuffling = get_shuffling(
                self.current_epoch_seed,
                &self.validator_registry,
                self.current_epoch_calculation_slot,
                committees_per_slot,
                epoch_length,
            );
            let slot_start_shard =
                (self.current_epoch_start_shard + committees_per_slot * offset) % shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        };

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
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    pub fn get_beacon_proposer_index(
        &self,
        slot: u64,
        epoch_length: u64,
        shard_count: u64,
        target_committee_size: u64,
    ) -> Result<usize> {
        let committees = self.get_crosslink_committees_at_slot(
            slot,
            epoch_length,
            shard_count,
            target_committee_size,
        )?;
        committees
            .first()
            .ok_or(Error::InsufficientNumberOfValidators)
            .and_then(|(first_committee, _)| {
                let index = (slot as usize)
                    .checked_rem(first_committee.len())
                    .ok_or(Error::InsufficientNumberOfValidators)?;
                // NOTE: next index will not panic as we have already returned if this is the case
                Ok(first_committee[index])
            })
    }

    /// Returns the start slot and end slot of the current epoch containing `self.slot`.
    fn get_current_epoch_boundaries(&self, epoch_length: u64) -> Range<u64> {
        let slot_in_epoch = self.slot % epoch_length;
        let start = self.slot - slot_in_epoch;
        let end = self.slot + (epoch_length - slot_in_epoch);
        start..end
    }

    /// Returns the start slot and end slot of the previous epoch with respect to `self.slot`.
    fn get_previous_epoch_boundaries(&self, epoch_length: u64) -> Range<u64> {
        let current_epoch = self.get_current_epoch_boundaries(epoch_length);
        current_epoch.start - epoch_length..current_epoch.end - epoch_length
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
    fn test_get_epoch_boundaries() {
        let epoch_length = 64;
        // focus on the third epoch, for example...
        let slot = 3 + 2 * epoch_length;
        let expected_current_range = 2 * epoch_length..3 * epoch_length;
        let expected_previous_range = epoch_length..2 * epoch_length;

        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut state = BeaconState::random_for_test(&mut rng);
        state.slot = slot;
        let current_result = state.get_current_epoch_boundaries(epoch_length);
        let previous_result = state.get_previous_epoch_boundaries(epoch_length);
        // test we get the expected range
        assert_eq!(expected_current_range, current_result);
        assert_eq!(expected_previous_range, previous_result);

        // test slots around the range behave as expected
        for i in 0..4 * epoch_length {
            if i >= epoch_length && i < 2 * epoch_length {
                assert!(range_contains(&previous_result, i));
                assert!(!range_contains(&current_result, i));
            } else if i >= 2 * epoch_length && i < 3 * epoch_length {
                assert!(!range_contains(&previous_result, i));
                assert!(range_contains(&current_result, i));
            } else {
                assert!(
                    !range_contains(&previous_result, i) && !range_contains(&current_result, i)
                );
            }
        }
    }

    #[test]
    fn test_get_shard_committees_at_slot() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut state = BeaconState::random_for_test(&mut rng);

        let epoch_length = 64;

        let mut committees_at_slots = vec![];
        for _ in 0..epoch_length * 2 {
            committees_at_slots.push(vec![ShardCommittee::random_for_test(&mut rng)]);
        }

        state.shard_committees_at_slots = committees_at_slots.clone();

        let current_epoch_slots = state.get_current_epoch_boundaries(epoch_length);
        let previous_epoch_slots = state.get_previous_epoch_boundaries(epoch_length);

        let span = previous_epoch_slots.start - 10..current_epoch_slots.end + 10;
        let earliest_slot_in_array = state.slot - (state.slot % epoch_length) - epoch_length;

        for i in span {
            if !range_contains(&previous_epoch_slots, i) && !range_contains(&current_epoch_slots, i)
            {
                assert!(state
                    .get_shard_committees_at_slot(i, epoch_length)
                    .is_none())
            } else {
                let index = (i - earliest_slot_in_array) as usize;
                let expected_committee = committees_at_slots.get(index);
                assert_eq!(
                    expected_committee,
                    state.get_shard_committees_at_slot(i, epoch_length)
                )
            }
        }
    }

    #[test]
    fn test_get_beacon_proposer_index() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut state = BeaconState::random_for_test(&mut rng);

        let epoch_length = 64;

        let mut committees_at_slots = vec![];
        for i in 0..epoch_length * 2 {
            let mut shard_committee = ShardCommittee::random_for_test(&mut rng);
            // ensure distinct indices, rather than just taking random values which may collide
            // a collision here could *give* a false indication when testing below...
            let indices = 3 * i..3 * i + 3;
            shard_committee.committee = indices.into_iter().map(|i| i as usize).collect::<Vec<_>>();
            committees_at_slots.push(vec![shard_committee]);
        }

        state.shard_committees_at_slots = committees_at_slots.clone();

        let current_epoch_slots = state.get_current_epoch_boundaries(epoch_length);
        let previous_epoch_slots = state.get_previous_epoch_boundaries(epoch_length);

        let span = previous_epoch_slots.start - 10..current_epoch_slots.end + 10;
        let earliest_slot_in_array = state.slot - (state.slot % epoch_length) - epoch_length;

        for i in span {
            if !range_contains(&previous_epoch_slots, i) && !range_contains(&current_epoch_slots, i)
            {
                assert!(state.get_beacon_proposer_index(i, epoch_length).is_none())
            } else {
                let index = (i - earliest_slot_in_array) as usize;
                let expected_committees = committees_at_slots.get(index).unwrap();
                let expected_committee = &expected_committees.get(0).unwrap().committee;
                let expected_proposer = expected_committee
                    .get(i as usize % expected_committee.len())
                    .unwrap();
                assert_eq!(
                    *expected_proposer,
                    state.get_beacon_proposer_index(i, epoch_length).unwrap()
                )
            }
        }
    }
}
