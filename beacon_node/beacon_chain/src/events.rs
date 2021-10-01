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
    late_head: Sender<EventKind<T>>,
    log: Logger,
}

impl<T: EthSpec> ServerSentEventHandler<T> {
    pub fn new(log: Logger) -> Self {
        Self::new_with_capacity(log, DEFAULT_CHANNEL_CAPACITY)
    }

    pub fn new_with_capacity(log: Logger, capacity: usize) -> Self {
        let (attestation_tx, _) = broadcast::channel(capacity);
        let (block_tx, _) = broadcast::channel(capacity);
        let (finalized_tx, _) = broadcast::channel(capacity);
        let (head_tx, _) = broadcast::channel(capacity);
        let (exit_tx, _) = broadcast::channel(capacity);
        let (chain_reorg_tx, _) = broadcast::channel(capacity);
        let (contribution_tx, _) = broadcast::channel(capacity);
        let (late_head, _) = broadcast::channel(capacity);

        Self {
            attestation_tx,
            block_tx,
            finalized_tx,
            head_tx,
            exit_tx,
            chain_reorg_tx,
            contribution_tx,
            late_head,
            log,
        }
    }

    pub fn register(&self, kind: EventKind<T>) {
        let result = match kind {
            EventKind::Attestation(attestation) => self
                .attestation_tx
                .send(EventKind::Attestation(attestation))
                .map(|count| trace!(self.log, "Registering server-sent attestation event"; "receiver_count" => count)),
            EventKind::Block(block) => self.block_tx.send(EventKind::Block(block))
                .map(|count| trace!(self.log, "Registering server-sent block event"; "receiver_count" => count)),
            EventKind::FinalizedCheckpoint(checkpoint) => self.finalized_tx
                .send(EventKind::FinalizedCheckpoint(checkpoint))
                .map(|count| trace!(self.log, "Registering server-sent finalized checkpoint event"; "receiver_count" => count)),
            EventKind::Head(head) => self.head_tx.send(EventKind::Head(head))
                .map(|count| trace!(self.log, "Registering server-sent head event"; "receiver_count" => count)),
            EventKind::VoluntaryExit(exit) => self.exit_tx.send(EventKind::VoluntaryExit(exit))
                .map(|count| trace!(self.log, "Registering server-sent voluntary exit event"; "receiver_count" => count)),
            EventKind::ChainReorg(reorg) => self.chain_reorg_tx.send(EventKind::ChainReorg(reorg))
                .map(|count| trace!(self.log, "Registering server-sent chain reorg event"; "receiver_count" => count)),
            EventKind::ContributionAndProof(contribution_and_proof) => self.contribution_tx.send(EventKind::ContributionAndProof(contribution_and_proof))
                .map(|count| trace!(self.log, "Registering server-sent contribution and proof event"; "receiver_count" => count)),
            EventKind::LateHead(late_head) => self.late_head.send(EventKind::LateHead(late_head))
                .map(|count| trace!(self.log, "Registering server-sent late head event"; "receiver_count" => count)),
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

    pub fn subscribe_late_head(&self) -> Receiver<EventKind<T>> {
        self.late_head.subscribe()
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

    pub fn has_late_head_subscribers(&self) -> bool {
        self.late_head.receiver_count() > 0
    }
}
