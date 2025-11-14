pub mod cli;
use environment::RuntimeContext;
use lean_network::{NetworkConfig, NetworkService};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use task_executor::TaskExecutor;
use tokio::time::{Duration, sleep};
use tracing::info;
use types::EthSpec;

pub struct ProductionLeanClient<E: EthSpec> {
    context: RuntimeContext<E>,
    slot_clock: SystemTimeSlotClock,
    executor: TaskExecutor,
}

impl<E: EthSpec> ProductionLeanClient<E> {
    pub async fn new(context: RuntimeContext<E>, executor: TaskExecutor) -> Result<Self, String> {
        let slot_clock = SystemTimeSlotClock::new(
            context.eth2_config.spec.genesis_slot,
            Duration::from_secs(0),
            Duration::from_secs(context.eth2_config.spec.seconds_per_slot),
        );

        Ok(Self {
            context,
            slot_clock,
            executor,
        })
    }

    pub async fn start_service(&mut self) -> Result<(), String> {
        let _slot_duration = Duration::from_secs(self.context.eth2_config.spec.seconds_per_slot);
        let _duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot");

        info!("Starting network service");
        let network_config = NetworkConfig::default();
        let network_service = NetworkService::new(network_config)
            .map_err(|e| format!("Failed to create network service: {}", e))?;
        network_service.start(self.executor.clone());

        let executor = self.executor.clone();
        let slot_clock = self.slot_clock.clone();

        info!("Starting lean node duties");
        let mut slot = 0;

        let interval_fut = async move {
            loop {
                if let Some(duration_to_next_slot) = slot_clock.duration_to_next_slot() {
                    sleep(duration_to_next_slot).await;
                    info!(?slot, "duties completed");
                    slot += 1;
                }
            }
        };

        executor.spawn(interval_fut, "lean_node_service");
        Ok(())
    }
}
