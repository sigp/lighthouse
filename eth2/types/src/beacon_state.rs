use super::crosslink::Crosslink;
use super::eth1_data::Eth1Data;
use super::eth1_data_vote::Eth1DataVote;
use super::fork::Fork;
use super::pending_attestation::PendingAttestation;
use super::ssz::{hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use super::validator::Validator;
use super::Hash256;
use crate::test_utils::TestRandom;
use hashing::canonical_hash;
use rand::RngCore;
use std::cmp;

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
    pub previous_epoch_calculation_slot: u64,
    pub current_epoch_calculation_slot: u64,
    pub previous_epoch_randao_mix: Hash256,
    pub current_epoch_randao_mix: Hash256,

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

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
enum Error {
    InvalidSlot,
}

impl BeaconState {
    pub fn canonical_root(&self) -> Hash256 {
        // TODO: implement tree hashing.
        // https://github.com/sigp/lighthouse/issues/70
        Hash256::from(&canonical_hash(&ssz_encode(self))[..])
    }

    /// Returns the block root at a recent `slot`.
    /// If the `slot` is in the future or far enough in the past that the state has dropped it, then we return an `Err`.
    fn get_block_root(&self, slot: u64, latest_block_roots_length: usize) -> Result<Hash256> {
        if self.slot as usize > slot as usize + latest_block_roots_length || slot >= self.slot {
            return Err(Error::InvalidSlot);
        }

        Ok(self.latest_block_roots[slot as usize % latest_block_roots_length])
    }

    /// Returns the effective balance ("balance at stake") for a validator with the given `index`.
    fn get_effective_balance(&self, index: usize, max_deposit_amount: u64) -> u64 {
        cmp::min(self.validator_balances[index], max_deposit_amount)
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
        s.append(&self.previous_epoch_calculation_slot);
        s.append(&self.current_epoch_calculation_slot);
        s.append(&self.previous_epoch_randao_mix);
        s.append(&self.current_epoch_randao_mix);
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
        let (previous_epoch_calculation_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_calculation_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_randao_mix, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_randao_mix, i) = <_>::ssz_decode(bytes, i)?;
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
                previous_epoch_calculation_slot,
                current_epoch_calculation_slot,
                previous_epoch_randao_mix,
                current_epoch_randao_mix,
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
        result.append(&mut self.previous_epoch_calculation_slot.hash_tree_root());
        result.append(&mut self.current_epoch_calculation_slot.hash_tree_root());
        result.append(&mut self.previous_epoch_randao_mix.hash_tree_root());
        result.append(&mut self.current_epoch_randao_mix.hash_tree_root());
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
            previous_epoch_calculation_slot: <_>::random_for_test(rng),
            current_epoch_calculation_slot: <_>::random_for_test(rng),
            previous_epoch_randao_mix: <_>::random_for_test(rng),
            current_epoch_randao_mix: <_>::random_for_test(rng),
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
    use ethereum_types::U256;

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
    fn test_get_block_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut state = BeaconState::random_for_test(&mut rng);

        let latest_block_roots_length: usize = 128;
        let block_roots = (0..latest_block_roots_length)
            .into_iter()
            .map(|i| {
                let as_u256: U256 = i.into();
                let as_h256: Hash256 = as_u256.into();
                as_h256
            })
            .collect::<Vec<_>>();
        state.latest_block_roots = block_roots.clone();

        let start = state.slot - latest_block_roots_length as u64 - 10;
        let end = state.slot + 10;

        for slot in start..end {
            let diff = state.slot.checked_sub(slot).unwrap_or(0);
            if diff as usize <= latest_block_roots_length && diff > 0 {
                match state.get_block_root(slot, latest_block_roots_length) {
                    Ok(root) => {
                        let expected_root_index = slot as usize % latest_block_roots_length;
                        let expected_root = block_roots[expected_root_index];
                        assert_eq!(expected_root, root);
                    }
                    Err(_) => panic!("should not return error for valid slot"),
                }
            } else {
                match state.get_block_root(slot, latest_block_roots_length) {
                    Ok(_) => panic!("should not return block root for past or future slot"),
                    Err(e) => assert_eq!(e, Error::InvalidSlot),
                }
            }
        }
    }

    #[test]
    fn test_get_effective_balance() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut state = BeaconState::random_for_test(&mut rng);

        let max_deposit_amount = 32;

        assert!(state.validator_registry.len() >= 2);

        state.validator_balances[0] = 32;
        state.validator_balances[1] = 128;

        assert_eq!(
            max_deposit_amount,
            state.get_effective_balance(0, max_deposit_amount)
        );
        assert_eq!(
            max_deposit_amount,
            state.get_effective_balance(1, max_deposit_amount)
        );
    }
}
