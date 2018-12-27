use super::candidate_pow_receipt_root_record::CandidatePoWReceiptRootRecord;
use super::crosslink_record::CrosslinkRecord;
use super::fork_data::ForkData;
use super::pending_attestation_record::PendingAttestationRecord;
use super::shard_committee::ShardCommittee;
use super::shard_reassignment_record::ShardReassignmentRecord;
use super::validator_record::ValidatorRecord;
use super::Hash256;

#[derive(Debug, PartialEq, Clone)]
pub struct BeaconState {
    // Misc
    pub slot: u64,
    pub genesis_time: u64,
    pub fork_data: ForkData,

    // Validator registry
    pub validator_registry: Vec<ValidatorRecord>,
    pub validator_balances: Vec<u64>,
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
        Hash256::zero()
    }
}
