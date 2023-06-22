use crate::{
    service::NetworkMessage,
    sync::{manager::BlockProcessType, SyncMessage},
};
use beacon_chain::BeaconChain;
use beacon_chain::{BeaconChainTypes, GossipVerifiedBlock, NotifyExecutionLayer};
use beacon_processor::{
    work_reprocessing_queue::ReprocessQueueMessage, AsyncFn, DuplicateCache, Work,
    WorkEvent as BeaconWorkEvent,
};
use lighthouse_network::{
    rpc::{BlocksByRangeRequest, BlocksByRootRequest, LightClientBootstrapRequest, StatusMessage},
    types::ChainSegmentProcessId,
    Client, MessageId, NetworkGlobals, PeerId, PeerRequestId,
};
use slog::Logger;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, error::TrySendError};
use types::*;

mod worker;

#[derive(Debug)]
pub enum Error {
    ShuttingDown,
    TrySendError(String),
}

impl<T: Debug> From<TrySendError<T>> for Error {
    fn from(e: TrySendError<T>) -> Self {
        Error::TrySendError(format!("{}", e))
    }
}

/// Defines if and where we will store the SSZ files of invalid blocks.
#[derive(Clone)]
pub enum InvalidBlockStorage {
    Enabled(PathBuf),
    Disabled,
}

/// Provides an interface to a `BeaconProcessor` running in some other thread.
/// The wider `networking` crate should use this struct to interface with the
/// beacon processor.
pub struct NetworkBeaconProcessor<T: BeaconChainTypes> {
    pub beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
    pub duplicate_cache: DuplicateCache,
    pub chain: Arc<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub reprocess_tx: mpsc::Sender<ReprocessQueueMessage>,
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub invalid_block_storage: InvalidBlockStorage,
    pub log: Logger,
}

pub struct WorkEventBuilder<T: BeaconChainTypes> {
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
}

impl<T: BeaconChainTypes> WorkEventBuilder<T> {
    /// Create a new `Work` event for some unaggregated attestation.
    pub fn unaggregated_attestation(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Attestation<T::EthSpec>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    ) -> BeaconWorkEvent<T::EthSpec> {
        // Define a closure for processing individual attestations.
        let processor = self.network_beacon_processor.clone();
        let process_individual = move |attestation| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_attestation(
                message_id,
                peer_id,
                attestation,
                subnet_id,
                should_import,
                Some(reprocess_tx),
                seen_timestamp,
            )
        };

        // Define a closure for processing batches of attestations.
        let processor = self.network_beacon_processor;
        let process_batch = move |attestations| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_attestation_batch(attestations, Some(reprocess_tx))
        };

        BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipAttestation {
                attestation: Box::new(attestation),
                process_individual: Box::new(process_individual),
                process_batch: Box::new(process_batch),
            },
        }
    }

    /// Create a new `Work` event for some aggregated attestation.
    pub fn aggregated_attestation(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> BeaconWorkEvent<T::EthSpec> {
        // Define a closure for processing individual attestations.
        let processor = self.network_beacon_processor.clone();
        let process_individual = move |aggregate| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_aggregate(
                message_id,
                peer_id,
                aggregate,
                Some(reprocess_tx),
                seen_timestamp,
            )
        };

        // Define a closure for processing batches of attestations.
        let processor = self.network_beacon_processor;
        let process_batch = move |aggregates| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_aggregate_batch(aggregates, Some(reprocess_tx))
        };

        BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipAggregate {
                aggregate: Box::new(aggregate),
                process_individual: Box::new(process_individual),
                process_batch: Box::new(process_batch),
            },
        }
    }

    /// Create a new `Work` event for some block.
    pub fn gossip_beacon_block(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = async {
            let reprocess_tx = processor.reprocess_tx.clone();
            let invalid_block_storage = processor.invalid_block_storage.clone();
            let duplicate_cache = processor.duplicate_cache.clone();
            processor
                .process_gossip_block(
                    message_id,
                    peer_id,
                    peer_client,
                    block,
                    reprocess_tx,
                    duplicate_cache,
                    invalid_block_storage,
                    seen_timestamp,
                )
                .await
        };

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipBlock(Box::pin(process_fn)),
        }
    }

    /// Create a new `Work` event for some sync committee signature.
    pub fn gossip_sync_signature(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        sync_signature: SyncCommitteeMessage,
        subnet_id: SyncSubnetId,
        seen_timestamp: Duration,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = || {
            processor.process_gossip_sync_committee_signature(
                message_id,
                peer_id,
                sync_signature,
                subnet_id,
                seen_timestamp,
            )
        };

        BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipSyncSignature(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some sync committee contribution.
    pub fn gossip_sync_contribution(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        sync_contribution: SignedContributionAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = || {
            processor.process_sync_committee_contribution(
                message_id,
                peer_id,
                sync_contribution,
                seen_timestamp,
            )
        };

        BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipSyncContribution(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some exit.
    pub fn gossip_voluntary_exit(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn =
            || processor.process_gossip_voluntary_exit(message_id, peer_id, *voluntary_exit);

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipVoluntaryExit(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some proposer slashing.
    pub fn gossip_proposer_slashing(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn =
            || processor.process_gossip_proposer_slashing(message_id, peer_id, *proposer_slashing);

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipProposerSlashing(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some light client finality update.
    pub fn gossip_light_client_finality_update(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        light_client_finality_update: LightClientFinalityUpdate<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = || {
            processor.process_gossip_finality_update(
                message_id,
                peer_id,
                light_client_finality_update,
                seen_timestamp,
            )
        };

        BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipLightClientFinalityUpdate(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some light client optimistic update.
    pub fn gossip_light_client_optimistic_update(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        light_client_optimistic_update: LightClientOptimisticUpdate<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = || {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_optimistic_update(
                message_id,
                peer_id,
                light_client_optimistic_update,
                Some(reprocess_tx),
                seen_timestamp,
            )
        };

        BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipLightClientOptimisticUpdate(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some attester slashing.
    pub fn gossip_attester_slashing(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<T::EthSpec>>,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn =
            || processor.process_gossip_attester_slashing(message_id, peer_id, *attester_slashing);
        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipAttesterSlashing(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some BLS to execution change.
    pub fn gossip_bls_to_execution_change(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        bls_to_execution_change: Box<SignedBlsToExecutionChange>,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = || {
            processor.process_gossip_bls_to_execution_change(
                message_id,
                peer_id,
                *bls_to_execution_change,
            )
        };

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipBlsToExecutionChange(Box::new(process_fn)),
        }
    }

    /// Create a new `Work` event for some block, where the result from computation (if any) is
    /// sent to the other side of `result_tx`.
    pub fn rpc_beacon_block(
        self,
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::RpcBlock {
                should_process: true,
                process_fn: processor.process_fn_rpc_beacon_block(
                    block_root,
                    block,
                    seen_timestamp,
                    process_type,
                ),
            },
        }
    }

    /// Create a new work event to import `blocks` as a beacon chain segment.
    pub fn chain_segment(
        self,
        process_id: ChainSegmentProcessId,
        blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = async move {
            let notify_execution_layer = if processor
                .network_globals
                .sync_state
                .read()
                .is_syncing_finalized()
            {
                NotifyExecutionLayer::No
            } else {
                NotifyExecutionLayer::Yes
            };
            processor
                .process_chain_segment(process_id, blocks, notify_execution_layer)
                .await;
        };

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::ChainSegment {
                process_id,
                process_fn: Box::pin(process_fn),
            },
        }
    }

    /// Create a new work event to process `StatusMessage`s from the RPC network.
    pub fn status_message(
        self,
        peer_id: PeerId,
        message: StatusMessage,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = || processor.process_status(peer_id, message);

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::Status(Box::new(process_fn)),
        }
    }

    /// Create a new work event to process `BlocksByRangeRequest`s from the RPC network.
    pub fn blocks_by_range_request(
        self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRangeRequest,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = |send_idle_on_drop| {
            processor.handle_blocks_by_range_request(
                sub_executor,
                send_idle_on_drop,
                peer_id,
                request_id,
                request,
            )
        };

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRangeRequest(Box::new(process_fn)),
        }
    }

    /// Create a new work event to process `BlocksByRootRequest`s from the RPC network.
    pub fn blocks_by_roots_request(
        self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = |send_idle_on_drop| {
            processor.handle_blocks_by_root_request(
                sub_executor,
                send_idle_on_drop,
                peer_id,
                request_id,
                request,
            )
        };

        BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRootsRequest(Box::new(process_fn)),
        }
    }

    /// Create a new work event to process `LightClientBootstrap`s from the RPC network.
    pub fn lightclient_bootstrap_request(
        self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: LightClientBootstrapRequest,
    ) -> BeaconWorkEvent<T::EthSpec> {
        let processor = self.network_beacon_processor;
        let process_fn = || processor.handle_light_client_bootstrap(peer_id, request_id, request);
        BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientBootstrapRequest(Box::new(process_fn)),
        }
    }
}

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    /// Returns an async closure which processes a chain of beacon blocks.
    pub fn process_fn_process_chain_segment(
        self,
        sync_type: ChainSegmentProcessId,
        downloaded_blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> AsyncFn {
        let process_fn = async move {
            let notify_execution_layer = if self
                .network_globals
                .sync_state
                .read()
                .is_syncing_finalized()
            {
                NotifyExecutionLayer::No
            } else {
                NotifyExecutionLayer::Yes
            };
            self.process_chain_segment(sync_type, downloaded_blocks, notify_execution_layer)
                .await;
        };
        Box::pin(process_fn)
    }

    /// Returns an async closure which processes a beacon block which has
    /// already been verified via gossip.
    ///
    /// TODO(paul): delete me.
    pub fn process_fn_gossip_verified_block(
        self: Arc<Self>,
        peer_id: PeerId,
        verified_block: GossipVerifiedBlock<T>,
        seen_timestamp: Duration,
    ) -> AsyncFn {
        let process_fn = async move {
            let reprocess_tx = self.reprocess_tx.clone();
            let invalid_block_storage = self.invalid_block_storage.clone();
            self.process_gossip_verified_block(
                peer_id,
                verified_block,
                reprocess_tx,
                invalid_block_storage,
                seen_timestamp,
            )
            .await;
        };
        Box::pin(process_fn)
    }

    /// Returns an async closure which processes a beacon block which has
    /// already been verified via gossip.
    ///
    /// TODO(paul): delete me.
    pub fn process_fn_handle_blocks_by_range_request(
        self: Arc<Self>,
        peer_id: PeerId,
        verified_block: GossipVerifiedBlock<T>,
        seen_timestamp: Duration,
    ) -> AsyncFn {
        let process_fn = async move {
            let reprocess_tx = self.reprocess_tx.clone();
            let invalid_block_storage = self.invalid_block_storage.clone();
            self.process_gossip_verified_block(
                peer_id,
                verified_block,
                reprocess_tx,
                invalid_block_storage,
                seen_timestamp,
            )
            .await;
        };
        Box::pin(process_fn)
    }
}
