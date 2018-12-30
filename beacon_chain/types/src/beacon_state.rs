use super::candidate_pow_receipt_root_record::CandidatePoWReceiptRootRecord;
use super::crosslink_record::CrosslinkRecord;
use super::fork_data::ForkData;
use super::pending_attestation_record::PendingAttestationRecord;
use super::shard_committee::ShardCommittee;
use super::shard_reassignment_record::ShardReassignmentRecord;
use super::validator_record::ValidatorRecord;
use super::Hash256;
use crate::test_utils::TestRandom;
use hashing::canonical_hash;
use rand::RngCore;
use ssz::{ssz_encode, Decodable, DecodeError, Encodable, SszStream};

#[derive(Debug, PartialEq, Clone)]
pub struct BeaconState {
    // Misc
    pub slot: u64,
    pub genesis_time: u64,
    pub fork_data: ForkData,

    // Validator registry
    pub validator_registry: Vec<ValidatorRecord>,
    pub validator_registry_latest_change_slot: u64,
    pub validator_registry_exit_count: u64,
    pub validator_registry_delta_chain_tip: Hash256,

    // Randomness and committees
    pub randao_mix: Hash256,
    pub next_seed: Hash256,
    pub shard_committees_at_slots: Vec<Vec<ShardCommittee>>,
    pub persistent_committees: Vec<Vec<u32>>,
    pub persistent_committee_reassignments: Vec<ShardReassignmentRecord>,

    // Finality
    pub previous_justified_slot: u64,
    pub justified_slot: u64,
    pub justification_bitfield: u64,
    pub finalized_slot: u64,

    // Recent state
    pub latest_crosslinks: Vec<CrosslinkRecord>,
    pub latest_block_roots: Vec<Hash256>,
    pub latest_penalized_exit_balances: Vec<u64>,
    pub latest_attestations: Vec<PendingAttestationRecord>,

    // PoW receipt root
    pub processed_pow_receipt_root: Hash256,
    pub candidate_pow_receipt_roots: Vec<CandidatePoWReceiptRootRecord>,
}

impl BeaconState {
    pub fn canonical_root(&self) -> Hash256 {
        // TODO: implement tree hashing.
        // https://github.com/sigp/lighthouse/issues/70
        Hash256::from(&canonical_hash(&ssz_encode(self))[..])
    }
}

impl Encodable for BeaconState {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.genesis_time);
        s.append(&self.fork_data);
        s.append(&self.validator_registry);
        s.append(&self.validator_registry_latest_change_slot);
        s.append(&self.validator_registry_exit_count);
        s.append(&self.validator_registry_delta_chain_tip);
        s.append(&self.randao_mix);
        s.append(&self.next_seed);
        s.append(&self.shard_committees_at_slots);
        s.append(&self.persistent_committees);
        s.append(&self.persistent_committee_reassignments);
        s.append(&self.previous_justified_slot);
        s.append(&self.justified_slot);
        s.append(&self.justification_bitfield);
        s.append(&self.finalized_slot);
        s.append(&self.latest_crosslinks);
        s.append(&self.latest_block_roots);
        s.append(&self.latest_penalized_exit_balances);
        s.append(&self.latest_attestations);
        s.append(&self.processed_pow_receipt_root);
        s.append(&self.candidate_pow_receipt_roots);
    }
}

impl Decodable for BeaconState {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (genesis_time, i) = <_>::ssz_decode(bytes, i)?;
        let (fork_data, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_latest_change_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_exit_count, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_delta_chain_tip, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_mix, i) = <_>::ssz_decode(bytes, i)?;
        let (next_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (shard_committees_at_slots, i) = <_>::ssz_decode(bytes, i)?;
        let (persistent_committees, i) = <_>::ssz_decode(bytes, i)?;
        let (persistent_committee_reassignments, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_justified_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (justified_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (justification_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (finalized_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_crosslinks, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_penalized_exit_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_attestations, i) = <_>::ssz_decode(bytes, i)?;
        let (processed_pow_receipt_root, i) = <_>::ssz_decode(bytes, i)?;
        let (candidate_pow_receipt_roots, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                genesis_time,
                fork_data,
                validator_registry,
                validator_registry_latest_change_slot,
                validator_registry_exit_count,
                validator_registry_delta_chain_tip,
                randao_mix,
                next_seed,
                shard_committees_at_slots,
                persistent_committees,
                persistent_committee_reassignments,
                previous_justified_slot,
                justified_slot,
                justification_bitfield,
                finalized_slot,
                latest_crosslinks,
                latest_block_roots,
                latest_penalized_exit_balances,
                latest_attestations,
                processed_pow_receipt_root,
                candidate_pow_receipt_roots,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for BeaconState {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            genesis_time: <_>::random_for_test(rng),
            fork_data: <_>::random_for_test(rng),
            validator_registry: <_>::random_for_test(rng),
            validator_registry_latest_change_slot: <_>::random_for_test(rng),
            validator_registry_exit_count: <_>::random_for_test(rng),
            validator_registry_delta_chain_tip: <_>::random_for_test(rng),
            randao_mix: <_>::random_for_test(rng),
            next_seed: <_>::random_for_test(rng),
            shard_committees_at_slots: <_>::random_for_test(rng),
            persistent_committees: <_>::random_for_test(rng),
            persistent_committee_reassignments: <_>::random_for_test(rng),
            previous_justified_slot: <_>::random_for_test(rng),
            justified_slot: <_>::random_for_test(rng),
            justification_bitfield: <_>::random_for_test(rng),
            finalized_slot: <_>::random_for_test(rng),
            latest_crosslinks: <_>::random_for_test(rng),
            latest_block_roots: <_>::random_for_test(rng),
            latest_penalized_exit_balances: <_>::random_for_test(rng),
            latest_attestations: <_>::random_for_test(rng),
            processed_pow_receipt_root: <_>::random_for_test(rng),
            candidate_pow_receipt_roots: <_>::random_for_test(rng),
        }
    }
}
