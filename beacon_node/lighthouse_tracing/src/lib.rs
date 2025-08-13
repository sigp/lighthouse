use tracing::Subscriber;

use std::collections::HashSet;
use tracing::span::Id;
use tracing_subscriber::Layer;

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

// Only allowed root spans and its descendants are exported to the tracing backend, so that we don't
// get a lot of noise from code paths that are not instrumented.
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

/// A filtering layer that wraps another layer and only forwards spans from allowed root spans and their descendants
pub struct AllowedRootSpanLayer<L> {
    inner: L,
    allowed_names: &'static [&'static str],
    allowed_spans: std::sync::Mutex<HashSet<Id>>,
}

impl<L> AllowedRootSpanLayer<L> {
    pub fn new(inner: L, allowed_names: &'static [&'static str]) -> Self {
        AllowedRootSpanLayer {
            inner,
            allowed_names,
            allowed_spans: std::sync::Mutex::new(HashSet::new()),
        }
    }

    fn is_span_allowed(&self, span_id: &Id) -> bool {
        self.allowed_spans.lock().unwrap().contains(span_id)
    }

    fn mark_span_allowed(&self, span_id: Id) {
        self.allowed_spans.lock().unwrap().insert(span_id);
    }

    fn remove_span(&self, span_id: &Id) {
        self.allowed_spans.lock().unwrap().remove(span_id);
    }
}

impl<S, L> Layer<S> for AllowedRootSpanLayer<L>
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    L: Layer<S>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let should_allow = if let Some(parent_id) = ctx.current_span().id() {
            // This span has a parent - allow it if the parent is allowed
            self.is_span_allowed(parent_id)
        } else {
            // This is a root span - allow it if it's in the allowed list
            self.allowed_names.contains(&attrs.metadata().name())
        };

        if should_allow {
            self.mark_span_allowed(id.clone());
            // FIXME: this panics!
            self.inner.on_new_span(attrs, id, ctx);
        }
    }

    fn on_record(
        &self,
        span: &Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if self.is_span_allowed(span) {
            self.inner.on_record(span, values, ctx);
        }
    }

    fn on_follows_from(
        &self,
        span: &Id,
        follows: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if self.is_span_allowed(span) {
            self.inner.on_follows_from(span, follows, ctx);
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Check if we're in an allowed span context
        if let Some(current_span_id) = ctx.current_span().id()
            && self.is_span_allowed(current_span_id)
        {
            self.inner.on_event(event, ctx);
        }
        // If no current span, we could choose to allow or disallow events - for now, disallow
    }

    fn on_enter(&self, id: &Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if self.is_span_allowed(id) {
            self.inner.on_enter(id, ctx);
        }
    }

    fn on_exit(&self, id: &Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if self.is_span_allowed(id) {
            self.inner.on_exit(id, ctx);
        }
    }

    fn on_close(&self, id: Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if self.is_span_allowed(&id) {
            self.inner.on_close(id.clone(), ctx);
        }
        self.remove_span(&id);
    }
}
