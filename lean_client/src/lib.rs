pub mod cli;

use environment::RuntimeContext;
use lean_attestation_service::AttestationService;
use lean_network::{NetworkConfig, NetworkService};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use task_executor::TaskExecutor;
use tokio::time::Duration;
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
        info!("Starting attestation service");
        let (attestation_service, network_tx) =
            AttestationService::<SystemTimeSlotClock, E>::new(self.slot_clock.clone());
        self.executor.spawn(attestation_service.run(), "attestation_service");

        info!("Starting network service");
        let network_config = NetworkConfig::default();
        let mut network_service = NetworkService::<E>::new(network_config)
            .map_err(|e| format!("Failed to create network service: {}", e))?;

        // Wire up the network service to send messages directly to attestation service
        network_service.set_message_sender(network_tx);

        self.executor.spawn(network_service.start(), "network_service");

        Ok(())
    }
}
