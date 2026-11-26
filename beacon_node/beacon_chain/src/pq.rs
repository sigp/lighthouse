use crate::chain_config::PqProverConfig;
use pq_prover::{ProverBackend, ReferenceBackend};
use prover_scheduler::ProverScheduler;
use std::sync::Arc;
use types::EthSpec;

pub(crate) mod attestation_preparation;
pub(crate) mod duties;
pub(crate) mod measurement;
pub(crate) mod prover_scheduler;
pub(crate) mod signature_pool;

pub(crate) struct Provers<E: EthSpec> {
    pub(crate) aggregate: Arc<dyn ProverBackend>,
    pub(crate) block: Arc<dyn ProverBackend>,
    pub(crate) scheduler: Arc<ProverScheduler<E>>,
    local_duties: duties::LocalDuties,
}

impl<E: EthSpec> Provers<E> {
    pub(crate) fn connect(config: &PqProverConfig) -> Result<Self, String> {
        match config {
            PqProverConfig::Reference => Ok(Self {
                aggregate: Arc::new(ReferenceBackend),
                block: Arc::new(ReferenceBackend),
                scheduler: Arc::default(),
                local_duties: duties::LocalDuties::default(),
            }),
            PqProverConfig::InProcess { threads } => {
                let backend = Arc::new(
                    pq_prover::InProcessBackend::new(*threads, 2)
                        .map_err(|error| format!("Unable to initialize leanVM: {error}"))?,
                );
                tracing::info!(
                    leanvm_revision = pq_prover::LEANVM_REV,
                    protocol_version = backend.protocol_version(),
                    configured_threads = threads,
                    "Initialized in-process PQ prover"
                );
                Ok(Self {
                    aggregate: backend.clone(),
                    block: backend,
                    scheduler: Arc::default(),
                    local_duties: duties::LocalDuties::default(),
                })
            }
        }
    }
}
