//! This module contains root span identifiers for key code paths in the beacon node.
//!
//! TODO: These span identifiers will be used to implement selective tracing export (to be implemented),
//! where only the listed root spans and their descendants will be exported to the tracing backend.

/// Root span names for block production and publishing
pub const SPAN_PRODUCE_BLOCK_V2: &str = "produce_block_v2";
pub const SPAN_PRODUCE_BLOCK_V3: &str = "produce_block_v3";
pub const SPAN_PUBLISH_BLOCK: &str = "publish_block";

/// Data Availability checker span identifiers
pub const SPAN_PENDING_COMPONENTS: &str = "pending_components";

/// Gossip methods root spans
pub const SPAN_PROCESS_GOSSIP_DATA_COLUMN: &str = "process_gossip_data_column";
pub const SPAN_PROCESS_GOSSIP_BLOB: &str = "process_gossip_blob";
pub const SPAN_PROCESS_GOSSIP_BLOCK: &str = "process_gossip_block";

/// Sync methods root spans
pub const SPAN_SYNCING_CHAIN: &str = "syncing_chain";
pub const SPAN_OUTGOING_RANGE_REQUEST: &str = "outgoing_range_request";
pub const SPAN_SINGLE_BLOCK_LOOKUP: &str = "single_block_lookup";
pub const SPAN_OUTGOING_BLOCK_BY_ROOT_REQUEST: &str = "outgoing_block_by_root_request";
pub const SPAN_OUTGOING_CUSTODY_REQUEST: &str = "outgoing_custody_request";
pub const SPAN_PROCESS_RPC_BLOCK: &str = "process_rpc_block";
pub const SPAN_PROCESS_RPC_BLOBS: &str = "process_rpc_blobs";
pub const SPAN_PROCESS_RPC_CUSTODY_COLUMNS: &str = "process_rpc_custody_columns";
pub const SPAN_PROCESS_CHAIN_SEGMENT: &str = "process_chain_segment";
pub const SPAN_CUSTODY_BACKFILL_SYNC_BATCH_REQUEST: &str = "custody_backfill_sync_batch_request";
pub const SPAN_PROCESS_CHAIN_SEGMENT_BACKFILL: &str = "process_chain_segment_backfill";
pub const SPAN_CUSTODY_BACKFILL_SYNC_IMPORT_COLUMNS: &str = "custody_backfill_sync_import_columns";

/// Fork choice root spans
pub const SPAN_RECOMPUTE_HEAD: &str = "recompute_head_at_slot";

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

/// List of all root span names that are allowed to be exported to the tracing backend.
/// Only these spans and their descendants will be processed to reduce noise from
/// uninstrumented code paths. New root spans must be added to this list to be traced.
pub const LH_BN_ROOT_SPAN_NAMES: &[&str] = &[
    SPAN_PRODUCE_BLOCK_V2,
    SPAN_PRODUCE_BLOCK_V3,
    SPAN_PUBLISH_BLOCK,
    SPAN_PENDING_COMPONENTS,
    SPAN_PROCESS_GOSSIP_DATA_COLUMN,
    SPAN_PROCESS_GOSSIP_BLOB,
    SPAN_PROCESS_GOSSIP_BLOCK,
    SPAN_SYNCING_CHAIN,
    SPAN_OUTGOING_RANGE_REQUEST,
    SPAN_SINGLE_BLOCK_LOOKUP,
    SPAN_PROCESS_RPC_BLOCK,
    SPAN_PROCESS_RPC_BLOBS,
    SPAN_PROCESS_RPC_CUSTODY_COLUMNS,
    SPAN_PROCESS_CHAIN_SEGMENT,
    SPAN_PROCESS_CHAIN_SEGMENT_BACKFILL,
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
    SPAN_CUSTODY_BACKFILL_SYNC_BATCH_REQUEST,
    SPAN_CUSTODY_BACKFILL_SYNC_IMPORT_COLUMNS,
];
