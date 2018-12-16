use super::candidate_pow_receipt_root_record::CandidatePoWReceiptRootRecord;
use super::crosslink_record::CrosslinkRecord;
use super::fork_data::ForkData;
use super::pending_attestation_record::PendingAttestationRecord;
use super::shard_and_committee::ShardAndCommittee;
use super::shard_reassignment_record::ShardReassignmentRecord;
use super::validator_record::ValidatorRecord;
use super::Hash256;

#[derive(Debug, PartialEq, Default)]
pub struct BeaconState {
    pub validator_registry: Vec<ValidatorRecord>,
    pub validator_registry_latest_change_slot: u64,
    pub validator_registry_exit_count: u64,
    pub validator_registry_delta_chain_tip: Hash256,
    pub randao_mix: Hash256,
    pub next_seed: Hash256,
    pub shard_and_committee_for_slots: Vec<Vec<ShardAndCommittee>>,
    pub persistent_committees: Vec<Vec<u32>>,
    pub persistent_committee_reassignments: Vec<ShardReassignmentRecord>,
    pub previous_justified_slot: u64,
    pub justified_slot: u64,
    pub justified_slot_bitfield: u64,
    pub finalized_slot: u64,
    pub latest_crosslinks: Vec<CrosslinkRecord>,
    pub latest_state_recalculation_slot: u64,
    pub latest_block_hashes: Vec<Hash256>,
    pub latest_penalized_exit_balances: Vec<u64>,
    pub latest_attestations: Vec<PendingAttestationRecord>,
    pub processed_pow_receipt_root: Hash256,
    pub candidate_pow_receipt_roots: Vec<CandidatePoWReceiptRootRecord>,
    pub genesis_time: u64,
    pub fork_data: ForkData,
}
