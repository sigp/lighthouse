use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tracing::{error, info};
use types::ChainSpec;
use validator_store::ValidatorStore;

pub struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
}

pub struct InclusionListService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for InclusionListService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for InclusionListService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S, T> InclusionListService<S, T>
where
    S: ValidatorStore + 'static,
    T: SlotClock + 'static,
{
    pub fn new(
        duties_service: Arc<DutiesService<S, T>>,
        validator_store: Arc<S>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        executor: TaskExecutor,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                executor,
                chain_spec,
            }),
        }
    }

    pub fn start_update_service(self) -> Result<(), String> {
        info!(
            inclusion_list_due_ms = self.chain_spec.get_inclusion_list_due().as_millis(),
            "Inclusion list service started"
        );
        let executor = self.executor.clone();

        let interval_fut = async move {
            loop {
                if let Err(e) = self.spawn_inclusion_list_tasks().await {
                    error!(error = e, "Failed to produce inclusion lists");
                }
            }
        };

        executor.spawn(interval_fut, "inclusion_list_service");

        Ok(())
    }

    async fn spawn_inclusion_list_tasks(&self) -> Result<(), String> {
        todo!("spawn_inclusion_list_tasks not yet implemented");
        Ok(())
    }
}
