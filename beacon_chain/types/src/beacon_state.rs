use super::candidate_pow_receipt_root_record::CandidatePoWReceiptRootRecord;
use super::crosslink_record::CrosslinkRecord;
use super::fork_data::ForkData;
use super::pending_attestation_record::PendingAttestationRecord;
use super::shard_and_committee::ShardAndCommittee;
use super::shard_reassignment_record::ShardReassignmentRecord;
use super::validator_record::ValidatorRecord;
use super::Hash256;

#[derive(Debug, PartialEq)]
pub struct BeaconState {
    validator_registry: Vec<ValidatorRecord>,
    validator_registry_latest_change_slot: u64,
    validator_registry_exit_count: u64,
    validator_registry_delta_chain_tip: Hash256,
    randao_mix: Hash256,
    next_seed: Hash256,
    shard_and_committee_for_slots: Vec<Vec<ShardAndCommittee>>,
    persistent_committees: Vec<Vec<u32>>,
    persistent_committee_reassignments: Vec<ShardReassignmentRecord>,
    previous_justified_slot: u64,
    justified_slot: u64,
    justified_slot_bitfield: u64,
    finalized_slot: u64,
    latest_crosslinks: Vec<CrosslinkRecord>,
    latest_state_recalculation_slot: u64,
    latest_block_hashes: Vec<Hash256>,
    latest_penalized_exit_balances: Vec<u64>,
    latest_attestations: Vec<PendingAttestationRecord>,
    processed_pow_receipt_root: Hash256,
    candidate_pow_receipt_roots: Vec<CandidatePoWReceiptRootRecord>,
    genesis_time: u64,
    fork_data: ForkData,
}
