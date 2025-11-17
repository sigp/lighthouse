pub mod cli;

use environment::RuntimeContext;
use lean_attestation_service::{AttestationService, AttestationServiceMessage};
use lean_network::{NetworkConfig, NetworkMessage, NetworkService};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
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
        let (attestation_service, attestation_tx) =
            AttestationService::<SystemTimeSlotClock, E>::new(self.slot_clock.clone());
        self.executor.spawn(attestation_service.run(), "attestation_service");

        info!("Starting network service");
        let network_config = NetworkConfig::default();
        let mut network_service = NetworkService::new(network_config)
            .map_err(|e| format!("Failed to create network service: {}", e))?;

        // Create channel to forward network messages to attestation service
        let (network_msg_tx, mut network_msg_rx) = mpsc::unbounded_channel::<NetworkMessage>();
        network_service.set_message_sender(network_msg_tx);

        // Spawn task to forward network messages to attestation service
        let attestation_tx_clone = attestation_tx.clone();
        self.executor.spawn(
            async move {
                while let Some(msg) = network_msg_rx.recv().await {
                    let _ = attestation_tx_clone.send(AttestationServiceMessage::NetworkMessage {
                        topic: msg.topic,
                        data: msg.data,
                    });
                }
            },
            "network_message_forwarder",
        );

        self.executor.spawn(network_service.start(), "network_service");

        Ok(())
    }
}
