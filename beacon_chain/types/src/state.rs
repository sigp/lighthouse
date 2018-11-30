use super::attestation_record::AttestationRecord;
use super::candidate_pow_receipt_root_record::CandidatePoWReceiptRootRecord;
use super::crosslink_record::CrosslinkRecord;
use super::shard_and_committee::ShardAndCommittee;
use super::shard_reassignment_record::ShardReassignmentRecord;
use super::validator_record::ValidatorRecord;
use super::Hash256;

#[derive(Debug, PartialEq)]
pub struct BeaconState {
    // Slot of last validator set change
    validator_set_change_slot: u64,
    // List of validators
    validators: Vec<ValidatorRecord>,
    // Most recent crosslink for each shard
    crosslinks: Vec<CrosslinkRecord>,
    // Last cycle-boundary state recalculation
    last_state_recalculation_slot: u64,
    // Last finalized slot
    last_finalized_slot: u64,
    // Last justified slot
    last_justified_slot: u64,
    // Number of consecutive justified slots
    justified_streak: u64,
    // Committee members and their assigned shard, per slot
    shard_and_committee_for_slots: Vec<Vec<ShardAndCommittee>>,
    // Persistent shard committees
    persistent_committees: Vec<Vec<u32>>,
    persistent_committee_reassignments: Vec<ShardReassignmentRecord>,
    // Randao seed used for next shuffling
    next_shuffling_seed: Hash256,
    // Total deposits penalized in the given withdrawal period
    deposits_penalized_in_period: Vec<u64>,
    // Hash chain of validator set changes (for light clients to easily track deltas)
    validator_set_delta_hash_chain: Hash256,
    // Current sequence number for withdrawals
    current_exit_seq: u64,
    // Genesis time
    genesis_time: u64,
    // PoW receipt root
    processed_pow_receipt_root: Hash256,
    candidate_pow_receipt_roots: Vec<CandidatePoWReceiptRootRecord>,
    // Parameters relevant to hard forks / versioning.
    // Should be updated only by hard forks.
    pre_fork_version: u64,
    post_fork_version: u64,
    fork_slot_number: u64,
    // Attestations not yet processed
    pending_attestations: Vec<AttestationRecord>,
    // recent beacon block hashes needed to process attestations, older to newer
    recent_block_hashes: Vec<Hash256>,
    // RANDAO state
    randao_mix: Hash256,
}
