use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use eth2::types::{InclusionListDuty, InclusionListTransactions};
use logging::crit;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec, Hash256, Slot};
use validator_store::ValidatorStore;

type DependentRoot = Hash256;

struct InclusionListData {
    slot: Slot,
    dependent_root: DependentRoot,
    transactions: InclusionListTransactions,
}

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
        let Some(slot) = self.wait_to_next_slot().await else {
            return Ok(());
        };

        let Some((duties, attestation_data)) =
            self.produce_inclusion_list_duties_data(slot).await?
        else {
            return Ok(());
        };

        let service = self.clone();
        self.executor.spawn(
            async move {
                if let Err(e) = service
                    .sign_and_publish(slot, duties, attestation_data)
                    .await
                {
                    crit!(error = e, %slot, "Failed to publish inclusion lists");
                }
            },
            "inclusion_list_producer",
        );
        Ok(())
    }

    async fn wait_to_next_slot(&self) -> Option<Slot> {
        let slot_duration = self.chain_spec.get_slot_duration();

        let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() else {
            error!("Failed to read slot clock");
            sleep(slot_duration).await;
            return None;
        };

        let Some(current_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock after trigger");
            return None;
        };

        // Ensure that the current slot is in the Heze fork
        if !self
            .chain_spec
            .fork_name_at_slot::<S::E>(current_slot)
            .heze_enabled()
        {
            let duration_to_next_epoch = self
                .slot_clock
                .duration_to_next_epoch(S::E::slots_per_epoch())
                .unwrap_or_else(|| {
                    self.chain_spec.get_slot_duration() * S::E::slots_per_epoch() as u32
                });
            sleep(duration_to_next_epoch).await;
            return None;
        }

        sleep(duration_to_next_slot).await;

        let Some(current_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock after sleep");
            return None;
        };

        Some(current_slot)
    }

    /// Produce the inclusion list data for `slot`, returned alongside the duties to sign.
    ///
    /// Returns `Ok(None)` when there is nothing to publish (no duties, or no inclusion list data for slot)
    /// and `Err` when data production failed.
    async fn produce_inclusion_list_duties_data(
        &self,
        slot: Slot,
    ) -> Result<Option<(Vec<InclusionListDuty>, InclusionListData)>, String> {
        let Some((dependent_root, duties)) = self.duties_service.get_il_duties_for_slot(slot)
        else {
            return Ok(None);
        };

        if duties.is_empty() {
            return Ok(None);
        }

        debug!(
            %slot,
            il_duties_count = duties.len(),
            "Producing inclusion lists"
        );

        // Fetch the inclusion list transactions for the given slot
        let transactions = self
            .beacon_nodes
            .first_success(|beacon_node| async move {
                beacon_node
                    .get_validator_inclusion_list(slot)
                    .await
                    .map(|resp| resp.data)
            })
            .await
            .map_err(|e| e.to_string())?;

        debug!(
            %slot,
            ?dependent_root,
            tx_count = transactions.transactions.len(),
            tx_bytes = transactions
                .transactions
                .iter()
                .map(|tx| tx.len())
                .sum::<usize>(),
            "Received inclusion list transactions"
        );

        let il_duties = InclusionListData {
            dependent_root,
            slot,
            transactions,
        };

        Ok(Some((duties, il_duties)))
    }

    async fn sign_and_publish(
        &self,
        slot: Slot,
        duties: Vec<InclusionListDuty>,
        inclusion_list_data: InclusionListData,
    ) -> Result<(), String> {
        todo!("Signing and publishing ILs is not yet implemented")
    }
}
