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

// Max light client updates by range request limits
// spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;
