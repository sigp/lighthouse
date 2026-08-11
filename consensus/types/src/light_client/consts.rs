pub const FINALIZED_ROOT_PROOF_LEN: usize = 6;
pub const CURRENT_SYNC_COMMITTEE_PROOF_LEN: usize = 5;
pub const NEXT_SYNC_COMMITTEE_PROOF_LEN: usize = 5;
pub const EXECUTION_PAYLOAD_PROOF_LEN: usize = 4;

pub const FINALIZED_ROOT_PROOF_LEN_ELECTRA: usize = 7;
pub const NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA: usize = 6;
pub const CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA: usize = 6;

pub const FINALIZED_ROOT_INDEX: usize = 105;
pub const CURRENT_SYNC_COMMITTEE_INDEX: usize = 54;
pub const NEXT_SYNC_COMMITTEE_INDEX: usize = 55;
pub const EXECUTION_PAYLOAD_INDEX: usize = 25;

pub const FINALIZED_ROOT_INDEX_ELECTRA: usize = 169;
pub const CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA: usize = 86;
pub const NEXT_SYNC_COMMITTEE_INDEX_ELECTRA: usize = 87;

// [New in Gloas:EIP7688] the `BeaconState` is a progressive container, so the generalized indices
// differ from the balanced tree layout used by prior forks, and the proof lengths vary per field.
pub const FINALIZED_ROOT_INDEX_GLOAS: usize = 735;
pub const CURRENT_SYNC_COMMITTEE_INDEX_GLOAS: usize = 2945;
pub const NEXT_SYNC_COMMITTEE_INDEX_GLOAS: usize = 2946;

pub const FINALIZED_ROOT_PROOF_LEN_GLOAS: usize = 9;
pub const CURRENT_SYNC_COMMITTEE_PROOF_LEN_GLOAS: usize = 11;
pub const NEXT_SYNC_COMMITTEE_PROOF_LEN_GLOAS: usize = 11;

// Field offsets within the `BeaconState`. These are stable across forks, so the progressive
// proofs use them directly rather than deriving them from a generalized index.
pub const FINALIZED_CHECKPOINT_FIELD_INDEX: usize = 20;
pub const CURRENT_SYNC_COMMITTEE_FIELD_INDEX: usize = 22;
pub const NEXT_SYNC_COMMITTEE_FIELD_INDEX: usize = 23;

// [New in Gloas:EIP7732] the block no longer contains the execution payload, so the light client
// proves the execution block hash via the payload bid instead.
pub const EXECUTION_BLOCK_HASH_INDEX_GLOAS: usize = 2856;
pub const EXECUTION_BLOCK_HASH_PROOF_LEN_GLOAS: usize = 11;

// Field offsets within the `BeaconBlockBody` and `ExecutionPayloadBid` for Gloas.
pub const SIGNED_EXECUTION_PAYLOAD_BID_FIELD_INDEX: usize = 10;
pub const PARENT_BLOCK_HASH_FIELD_INDEX: usize = 0;

// Max light client updates by range request limits
// spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;
