pub use eth2::types::{EventKind, SseBlock, SseFinalizedCheckpoint, SseHead};
use slog::{trace, Logger};
use tokio::sync::broadcast;
use tokio::sync::broadcast::{error::SendError, Receiver, Sender};
use types::EthSpec;

const DEFAULT_CHANNEL_CAPACITY: usize = 16;

pub struct ServerSentEventHandler<T: EthSpec> {
    attestation_tx: Sender<EventKind<T>>,
    block_tx: Sender<EventKind<T>>,
    finalized_tx: Sender<EventKind<T>>,
    head_tx: Sender<EventKind<T>>,
    exit_tx: Sender<EventKind<T>>,
    chain_reorg_tx: Sender<EventKind<T>>,
    contribution_tx: Sender<EventKind<T>>,
    payload_attributes_tx: Sender<EventKind<T>>,
    late_head: Sender<EventKind<T>>,
    block_reward_tx: Sender<EventKind<T>>,
    log: Logger,
}

impl<T: EthSpec> ServerSentEventHandler<T> {
    pub fn new(log: Logger, capacity_multiplier: usize) -> Self {
        Self::new_with_capacity(
            log,
            capacity_multiplier.saturating_mul(DEFAULT_CHANNEL_CAPACITY),
        )
    }

    pub fn new_with_capacity(log: Logger, capacity: usize) -> Self {
        let (attestation_tx, _) = broadcast::channel(capacity);
        let (block_tx, _) = broadcast::channel(capacity);
        let (finalized_tx, _) = broadcast::channel(capacity);
        let (head_tx, _) = broadcast::channel(capacity);
        let (exit_tx, _) = broadcast::channel(capacity);
        let (chain_reorg_tx, _) = broadcast::channel(capacity);
        let (contribution_tx, _) = broadcast::channel(capacity);
        let (payload_attributes_tx, _) = broadcast::channel(capacity);
        let (late_head, _) = broadcast::channel(capacity);
        let (block_reward_tx, _) = broadcast::channel(capacity);

        Self {
            attestation_tx,
            block_tx,
            finalized_tx,
            head_tx,
            exit_tx,
            chain_reorg_tx,
            contribution_tx,
            payload_attributes_tx,
            late_head,
            block_reward_tx,
            log,
        }
    }

    pub fn register(&self, kind: EventKind<T>) {
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
            EventKind::BlockReward(_) => self
                .block_reward_tx
                .send(kind)
                .map(|count| log_count("block reward", count)),
        };
        if let Err(SendError(event)) = result {
            trace!(self.log, "No receivers registered to listen for event"; "event" => ?event);
        }
    }

    pub fn subscribe_attestation(&self) -> Receiver<EventKind<T>> {
        self.attestation_tx.subscribe()
    }

    pub fn subscribe_block(&self) -> Receiver<EventKind<T>> {
        self.block_tx.subscribe()
    }

    pub fn subscribe_finalized(&self) -> Receiver<EventKind<T>> {
        self.finalized_tx.subscribe()
    }

    pub fn subscribe_head(&self) -> Receiver<EventKind<T>> {
        self.head_tx.subscribe()
    }

    pub fn subscribe_exit(&self) -> Receiver<EventKind<T>> {
        self.exit_tx.subscribe()
    }

    pub fn subscribe_reorgs(&self) -> Receiver<EventKind<T>> {
        self.chain_reorg_tx.subscribe()
    }

    pub fn subscribe_contributions(&self) -> Receiver<EventKind<T>> {
        self.contribution_tx.subscribe()
    }

    pub fn subscribe_payload_attributes(&self) -> Receiver<EventKind<T>> {
        self.payload_attributes_tx.subscribe()
    }

    pub fn subscribe_late_head(&self) -> Receiver<EventKind<T>> {
        self.late_head.subscribe()
    }

    pub fn subscribe_block_reward(&self) -> Receiver<EventKind<T>> {
        self.block_reward_tx.subscribe()
    }

    pub fn has_attestation_subscribers(&self) -> bool {
        self.attestation_tx.receiver_count() > 0
    }

    pub fn has_block_subscribers(&self) -> bool {
        self.block_tx.receiver_count() > 0
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
}
