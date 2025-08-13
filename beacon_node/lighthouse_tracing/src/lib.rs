/// DA checker spans
pub const SPAN_PENDING_COMPONENTS: &str = "pending_components";
/// Gossip methods root spans
pub const SPAN_PROCESS_GOSSIP_DATA_COLUMN: &str = "process_gossip_data_column";
pub const SPAN_PROCESS_GOSSIP_BLOB: &str = "process_gossip_blob";
pub const SPAN_PROCESS_GOSSIP_BLOCK: &str = "process_gossip_block";
/// Sync methods root spans
pub const SPAN_OUTGOING_RANGE_REQUEST: &str = "outgoing_range_request";
pub const SPAN_OUTGOING_CUSTODY_REQUEST: &str = "outgoing_custody_request";
pub const SPAN_PROCESS_RPC_BLOCK: &str = "process_rpc_block";
pub const SPAN_PROCESS_RPC_BLOBS: &str = "process_rpc_blobs";
pub const SPAN_PROCESS_RPC_CUSTODY_COLUMNS: &str = "process_rpc_custody_columns";
pub const SPAN_PROCESS_CHAIN_SEGMENT: &str = "process_chain_segment";
/// RPC methods root spans
pub const SPAN_HANDLE_BLOCKS_BY_RANGE_REQUEST: &str = "handle_blocks_by_range_request";
pub const SPAN_HANDLE_BLOBS_BY_RANGE_REQUEST: &str = "handle_blobs_by_range_request";
pub const SPAN_HANDLE_DATA_COLUMNS_BY_RANGE_REQUEST: &str = "handle_data_columns_by_range_request";
pub const SPAN_HANDLE_BLOCKS_BY_ROOT_REQUEST: &str = "handle_blocks_by_root_request";
pub const SPAN_HANDLE_BLOBS_BY_ROOT_REQUEST: &str = "handle_blobs_by_root_request";
pub const SPAN_HANDLE_DATA_COLUMNS_BY_ROOT_REQUEST: &str = "handle_data_columns_by_root_request";
pub const SPAN_HANDLE_LIGHT_CLIENT_UPDATES_BY_RANGE: &str = "handle_light_client_updates_by_range";
pub const SPAN_HANDLE_LIGHT_CLIENT_BOOTSTRAP: &str = "handle_light_client_bootstrap";
pub const SPAN_HANDLE_LIGHT_CLIENT_OPTIMISTIC_UPDATE: &str =
    "handle_light_client_optimistic_update";
pub const SPAN_HANDLE_LIGHT_CLIENT_FINALITY_UPDATE: &str = "handle_light_client_finality_update";

// TODO: Only export allowed root spans and its descendants to the tracing backend, so that
// we don't get a lot of noise from code paths that are not instrumented.
// When a new root span is added, it should be added to this list.
pub const LH_BN_ROOT_SPAN_NAMES: &[&str] = &[
    SPAN_PENDING_COMPONENTS,
    SPAN_PROCESS_GOSSIP_DATA_COLUMN,
    SPAN_PROCESS_GOSSIP_BLOB,
    SPAN_PROCESS_GOSSIP_BLOCK,
    SPAN_OUTGOING_RANGE_REQUEST,
    SPAN_OUTGOING_CUSTODY_REQUEST,
    SPAN_PROCESS_RPC_BLOCK,
    SPAN_PROCESS_RPC_BLOBS,
    SPAN_PROCESS_RPC_CUSTODY_COLUMNS,
    SPAN_PROCESS_CHAIN_SEGMENT,
    SPAN_HANDLE_BLOCKS_BY_RANGE_REQUEST,
    SPAN_HANDLE_BLOBS_BY_RANGE_REQUEST,
    SPAN_HANDLE_DATA_COLUMNS_BY_RANGE_REQUEST,
    SPAN_HANDLE_BLOCKS_BY_ROOT_REQUEST,
    SPAN_HANDLE_BLOBS_BY_ROOT_REQUEST,
    SPAN_HANDLE_DATA_COLUMNS_BY_ROOT_REQUEST,
    SPAN_HANDLE_LIGHT_CLIENT_UPDATES_BY_RANGE,
    SPAN_HANDLE_LIGHT_CLIENT_BOOTSTRAP,
    SPAN_HANDLE_LIGHT_CLIENT_OPTIMISTIC_UPDATE,
    SPAN_HANDLE_LIGHT_CLIENT_FINALITY_UPDATE,
];
