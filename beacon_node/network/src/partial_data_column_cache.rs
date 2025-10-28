use lighthouse_network::PeerId;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::partial_data_column_sidecar::DanglingPartialDataColumn;
use types::{EthSpec, Hash256};

const BLOCK_LIMIT: usize = 16;
const SIDECAR_PER_BLOCK_LIMIT: usize = 16;
const EXPIRATION_TIME: Duration = Duration::from_secs(24);

/// Really dumb hacky implementation of a cache for partial data column sidecars.
///
/// The issue is that (with the current spec draft) we have to match up the dangling partial data
/// columns sidecars with the corresponding block. Of course, usually we have to take great care to
/// not be exploitable, but this cache design (for now) assumes no malicious behaviour.
///
/// Do not take anything in this file as an actual implementation suggestion, it is just a hack
/// while we discuss the spec!
pub struct PartialDataColumnCache<E: EthSpec> {
    per_block: HashMap<Hash256, Vec<CachedPartial<E>>>,
}

pub struct CachedPartial<E: EthSpec> {
    pub sidecar: Arc<DanglingPartialDataColumn<E>>,
    pub peer_id: PeerId,
    pub seen_duration: Duration,
}

impl<E: EthSpec> PartialDataColumnCache<E> {
    pub fn new() -> Self {
        Self {
            per_block: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        sidecar: Arc<DanglingPartialDataColumn<E>>,
        peer_id: PeerId,
        seen_duration: Duration,
    ) {
        let len = self.per_block.len();
        let entry = self.per_block.entry(sidecar.block_root);
        if matches!(entry, Entry::Vacant(_)) && len >= BLOCK_LIMIT {
            return;
        }

        let sidecars = entry.or_default();
        if sidecars.len() < SIDECAR_PER_BLOCK_LIMIT {
            sidecars.push(CachedPartial {
                sidecar,
                peer_id,
                seen_duration,
            });
        }
    }

    pub fn get_for_block(&mut self, block_root: Hash256) -> Vec<CachedPartial<E>> {
        self.per_block.remove(&block_root).unwrap_or_default()
    }

    pub fn clean(&mut self) {
        if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            self.per_block.retain(|_, sidecars| {
                sidecars
                    .iter()
                    .map(|cached| cached.seen_duration)
                    .max()
                    .map(|last_seen| now.saturating_sub(last_seen) < EXPIRATION_TIME)
                    .unwrap_or(false)
            });
        }
    }
}
