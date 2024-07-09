pub use eth2::types::{EventKind, SseBlock, SseFinalizedCheckpoint, SseHead};
use slog::{trace, Logger};
use tokio::sync::broadcast;
use tokio::sync::broadcast::{error::SendError, Receiver, Sender};
use types::EthSpec;

const DEFAULT_CHANNEL_CAPACITY: usize = 16;

pub struct ServerSentEventHandler<E: EthSpec> {
    attestation_tx: Sender<EventKind<E>>,
    block_tx: Sender<EventKind<E>>,
    blob_sidecar_tx: Sender<EventKind<E>>,
    finalized_tx: Sender<EventKind<E>>,
    head_tx: Sender<EventKind<E>>,
    exit_tx: Sender<EventKind<E>>,
    chain_reorg_tx: Sender<EventKind<E>>,
    contribution_tx: Sender<EventKind<E>>,
    payload_attributes_tx: Sender<EventKind<E>>,
    late_head: Sender<EventKind<E>>,
    light_client_finality_update_tx: Sender<EventKind<E>>,
    light_client_optimistic_update_tx: Sender<EventKind<E>>,
    block_reward_tx: Sender<EventKind<E>>,
    proposer_slashing_tx: Sender<EventKind<E>>,
    attester_slashing_tx: Sender<EventKind<E>>,
    bls_to_execution_change_tx: Sender<EventKind<E>>,
    log: Logger,
}

impl<E: EthSpec> ServerSentEventHandler<E> {
    pub fn new(log: Logger, capacity_multiplier: usize) -> Self {
        Self::new_with_capacity(
            log,
            capacity_multiplier.saturating_mul(DEFAULT_CHANNEL_CAPACITY),
        )
    }

    pub fn new_with_capacity(log: Logger, capacity: usize) -> Self {
        let (attestation_tx, _) = broadcast::channel(capacity);
        let (block_tx, _) = broadcast::channel(capacity);
        let (blob_sidecar_tx, _) = broadcast::channel(capacity);
        let (finalized_tx, _) = broadcast::channel(capacity);
        let (head_tx, _) = broadcast::channel(capacity);
        let (exit_tx, _) = broadcast::channel(capacity);
        let (chain_reorg_tx, _) = broadcast::channel(capacity);
        let (contribution_tx, _) = broadcast::channel(capacity);
        let (payload_attributes_tx, _) = broadcast::channel(capacity);
        let (late_head, _) = broadcast::channel(capacity);
        let (light_client_finality_update_tx, _) = broadcast::channel(capacity);
        let (light_client_optimistic_update_tx, _) = broadcast::channel(capacity);
        let (block_reward_tx, _) = broadcast::channel(capacity);
        let (proposer_slashing_tx, _) = broadcast::channel(capacity);
        let (attester_slashing_tx, _) = broadcast::channel(capacity);
        let (bls_to_execution_change_tx, _) = broadcast::channel(capacity);

        Self {
            attestation_tx,
            block_tx,
            blob_sidecar_tx,
            finalized_tx,
            head_tx,
            exit_tx,
            chain_reorg_tx,
            contribution_tx,
            payload_attributes_tx,
            late_head,
            light_client_finality_update_tx,
            light_client_optimistic_update_tx,
            block_reward_tx,
            proposer_slashing_tx,
            attester_slashing_tx,
            bls_to_execution_change_tx,
            log,
        }
    }

    pub fn register(&self, kind: EventKind<E>) {
        let log_count = |name, count| {
            trace!(
                self.log,
                "Registering server-sent event";
                "kind" => name,
                "receiver_count" => count
            );
        };
        let result = match &kind {
            EventKind::Attestation(_) => self
                .attestation_tx
                .send(kind)
                .map(|count| log_count("attestation", count)),
            EventKind::Block(_) => self
                .block_tx
                .send(kind)
                .map(|count| log_count("block", count)),
            EventKind::BlobSidecar(_) => self
                .blob_sidecar_tx
                .send(kind)
                .map(|count| log_count("blob sidecar", count)),
            EventKind::FinalizedCheckpoint(_) => self
                .finalized_tx
                .send(kind)
                .map(|count| log_count("finalized checkpoint", count)),
            EventKind::Head(_) => self
                .head_tx
                .send(kind)
                .map(|count| log_count("head", count)),
            EventKind::VoluntaryExit(_) => self
                .exit_tx
                .send(kind)
                .map(|count| log_count("exit", count)),
            EventKind::ChainReorg(_) => self
                .chain_reorg_tx
                .send(kind)
                .map(|count| log_count("chain reorg", count)),
            EventKind::ContributionAndProof(_) => self
                .contribution_tx
                .send(kind)
                .map(|count| log_count("contribution and proof", count)),
            EventKind::PayloadAttributes(_) => self
                .payload_attributes_tx
                .send(kind)
                .map(|count| log_count("payload attributes", count)),
            EventKind::LateHead(_) => self
                .late_head
                .send(kind)
                .map(|count| log_count("late head", count)),
            EventKind::LightClientFinalityUpdate(_) => self
                .light_client_finality_update_tx
                .send(kind)
                .map(|count| log_count("light client finality update", count)),
            EventKind::LightClientOptimisticUpdate(_) => self
                .light_client_optimistic_update_tx
                .send(kind)
                .map(|count| log_count("light client optimistic update", count)),
            EventKind::BlockReward(_) => self
                .block_reward_tx
                .send(kind)
                .map(|count| log_count("block reward", count)),
            EventKind::ProposerSlashing(_) => self
                .proposer_slashing_tx
                .send(kind)
                .map(|count| log_count("proposer slashing", count)),
            EventKind::AttesterSlashing(_) => self
                .attester_slashing_tx
                .send(kind)
                .map(|count| log_count("attester slashing", count)),
            EventKind::BlsToExecutionChange(_) => self
                .bls_to_execution_change_tx
                .send(kind)
                .map(|count| log_count("bls to execution change", count)),
        };
        if let Err(SendError(event)) = result {
            trace!(self.log, "No receivers registered to listen for event"; "event" => ?event);
        }
    }

    pub fn subscribe_attestation(&self) -> Receiver<EventKind<E>> {
        self.attestation_tx.subscribe()
    }

    pub fn subscribe_block(&self) -> Receiver<EventKind<E>> {
        self.block_tx.subscribe()
    }

    pub fn subscribe_blob_sidecar(&self) -> Receiver<EventKind<E>> {
        self.blob_sidecar_tx.subscribe()
    }

    pub fn subscribe_finalized(&self) -> Receiver<EventKind<E>> {
        self.finalized_tx.subscribe()
    }

    pub fn subscribe_head(&self) -> Receiver<EventKind<E>> {
        self.head_tx.subscribe()
    }

    pub fn subscribe_exit(&self) -> Receiver<EventKind<E>> {
        self.exit_tx.subscribe()
    }

    pub fn subscribe_reorgs(&self) -> Receiver<EventKind<E>> {
        self.chain_reorg_tx.subscribe()
    }

    pub fn subscribe_contributions(&self) -> Receiver<EventKind<E>> {
        self.contribution_tx.subscribe()
    }

    pub fn subscribe_payload_attributes(&self) -> Receiver<EventKind<E>> {
        self.payload_attributes_tx.subscribe()
    }

    pub fn subscribe_late_head(&self) -> Receiver<EventKind<E>> {
        self.late_head.subscribe()
    }

    pub fn subscribe_light_client_finality_update(&self) -> Receiver<EventKind<E>> {
        self.light_client_finality_update_tx.subscribe()
    }

    pub fn subscribe_light_client_optimistic_update(&self) -> Receiver<EventKind<E>> {
        self.light_client_optimistic_update_tx.subscribe()
    }

    pub fn subscribe_block_reward(&self) -> Receiver<EventKind<E>> {
        self.block_reward_tx.subscribe()
    }

    pub fn subscribe_attester_slashing(&self) -> Receiver<EventKind<E>> {
        self.attester_slashing_tx.subscribe()
    }

    pub fn subscribe_proposer_slashing(&self) -> Receiver<EventKind<E>> {
        self.proposer_slashing_tx.subscribe()
    }

    pub fn subscribe_bls_to_execution_change(&self) -> Receiver<EventKind<E>> {
        self.bls_to_execution_change_tx.subscribe()
    }

    pub fn has_attestation_subscribers(&self) -> bool {
        self.attestation_tx.receiver_count() > 0
    }

    pub fn has_block_subscribers(&self) -> bool {
        self.block_tx.receiver_count() > 0
    }

    pub fn has_blob_sidecar_subscribers(&self) -> bool {
        self.blob_sidecar_tx.receiver_count() > 0
    }

    pub fn has_finalized_subscribers(&self) -> bool {
        self.finalized_tx.receiver_count() > 0
    }

    pub fn has_head_subscribers(&self) -> bool {
        self.head_tx.receiver_count() > 0
    }

    pub fn has_exit_subscribers(&self) -> bool {
        self.exit_tx.receiver_count() > 0
    }

    pub fn has_reorg_subscribers(&self) -> bool {
        self.chain_reorg_tx.receiver_count() > 0
    }

    pub fn has_contribution_subscribers(&self) -> bool {
        self.contribution_tx.receiver_count() > 0
    }

    pub fn has_payload_attributes_subscribers(&self) -> bool {
        self.payload_attributes_tx.receiver_count() > 0
    }

    pub fn has_late_head_subscribers(&self) -> bool {
        self.late_head.receiver_count() > 0
    }

    pub fn has_block_reward_subscribers(&self) -> bool {
        self.block_reward_tx.receiver_count() > 0
    }

    pub fn has_proposer_slashing_subscribers(&self) -> bool {
        self.proposer_slashing_tx.receiver_count() > 0
    }

    pub fn has_attester_slashing_subscribers(&self) -> bool {
        self.attester_slashing_tx.receiver_count() > 0
    }

    pub fn has_bls_to_execution_change_subscribers(&self) -> bool {
        self.bls_to_execution_change_tx.receiver_count() > 0
    }
}
