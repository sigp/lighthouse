use crate::chain_config::PqProverConfig;
use pq_prover::{ProverBackend, ReferenceBackend};
use prover_scheduler::ProverScheduler;
use std::sync::Arc;
use types::EthSpec;

pub(crate) mod attestation_preparation;
pub(crate) mod duties;
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
            #[cfg(unix)]
            PqProverConfig::Sidecar(path) => {
                use pq_prover::{SidecarBackend, SidecarConfig};
                use std::time::Duration;

                let mut config = SidecarConfig::new(path);
                config.prove_timeout = None;
                config.verify_timeout = Some(Duration::from_secs(2));
                let aggregate = SidecarBackend::connect(config.clone())
                    .map_err(|error| format!("Unable to connect to PQ prover: {error:?}"))?;
                // Block verification has a separate connection from gossip, whose queue
                // may be busy with a burst of aggregates at the end of the slot.
                let block = SidecarBackend::new(config);
                Ok(Self {
                    aggregate: Arc::new(aggregate),
                    block: Arc::new(block),
                    scheduler: Arc::default(),
                    local_duties: duties::LocalDuties::default(),
                })
            }
            #[cfg(not(unix))]
            PqProverConfig::Sidecar(_) => Err("PQ sidecar requires Unix sockets".into()),
        }
    }
}
