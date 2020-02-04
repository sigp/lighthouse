//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use crate::error;
use crate::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::topics::ATTESTATION_SUBNET_COUNT;
use eth2_libp2p::SubnetId;
use futures::prelude::*;
use hashmap_delay::HashMapDelay;
use slog::{debug, error, o, trace};
use std::boxed::Box;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use types::{Attestation, EthSpec};

/// The number of epochs in advance we try to discover peers for a shard subnet.
const EPOCHS_TO_DISCOVER_PEERS: u8 = 1;
/// The number of random subnets to be connected to per validator.
const RANDOM_SUBNETS_PER_VALIDATOR: u8 = 1;
/// The minimum number of epochs to remain subscribed to a random subnet.
const EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION: u16 = 256;

pub enum AttestationServiceMessage<T: EthSpec> {
    /// A raw attestation has been received.
    Attestation(SubnetId, Box<Attestation<T>>),
    /// A validator has been subscribed.
    ValidatorSubscription,
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// A channel to the network service, for instructing the network service to
    /// subscribe/unsubscribe from various shard subnets.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,

    /// A reference to the beacon chain to process received attestations.
    beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of currently subscribed random subnets.
    random_subnets: HashMapDelay<SubnetId, ()>,

    /// A collection of timeouts for when to start searching for peers for a particular shard.
    discover_peers: HashMapDelay<SubnetId, Instant>,

    /// A collection of timeouts for when to subscribe to a shard subnet.
    subscriptions: HashMapDelay<SubnetId, Instant>,

    /// A collection of timeouts for when to unsubscribe from a shard subnet.
    unsubscriptions: HashMapDelay<SubnetId, Instant>,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<AttestationServiceMessage<T::EthSpec>>> {
        let log = log.new(o!("service" => "attestation_service"));
        let err_log = log.clone();

        trace!(log, "Service starting");

        let (handler_send, mut handler_recv) = mpsc::unbounded_channel();

        // generate the Message handler
        let mut service = AttestationService {
            network_send,
            beacon_chain,
            random_subnets: HashMapDelay::default(),
            discover_peers: HashMapDelay::default(),
            subscriptions: HashMapDelay::default(),
            unsubscriptions: HashMapDelay::default(),
            log,
        };

        let main_task = {
            futures::future::poll_fn(move || {
                // handle any discovery events
                while let Async::Ready(Some(discover)) =
                    service.discover_peers.poll().map_err(|e| {
                        error!(err_log, "Failed to check for peer discovery requests"; "error"=> format!("{}", e));
                    })?
                {
                    service.handle_discover_peer(discover);
                }

                while let Async::Ready(Some(subscription)) = service.subscriptions.poll().map_err(|e| {
                        error!(err_log, "Failed to check for peer discovery requests"; "error"=> format!("{}", e));
                    })?
                {
                    service.handle_subscriptions(subscription);
                }

                while let Async::Ready(Some(subnet)) = service.random_subnets.poll().map_err(|e| { 
                        error!(err_log, "Failed to check for peer discovery requests"; "error"=> format!("{}", e));
                    })?
                {
                    service.handle_persistant_subnets(subnet);
                }

                while let Async::Ready(Some(msg)) = handler_recv.poll().map_err(|_| { 
                        debug!(err_log, "Attestation service terminated");
                    })?
                {
                    service.handle_message(msg);
                }

                Ok(Async::NotReady)

            })
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(main_task);

        Ok(handler_send)
    }

    /// It is time to run a discovery query to find peers for a particular subnet.
    fn handle_discover_peer(&mut self, discover: (SubnetId, Instant)) {
        debug!(self.log, "Searching for peers for subnet"; "subnet" => *discover.0);




    }

    fn handle_subscriptions(&mut self, _discover: (SubnetId, Instant)) {}

    fn handle_persistant_subnets(&mut self, _subnet: (SubnetId, ())) {}

    fn handle_attestation(&mut self, subnet: SubnetId, attestation: Box<Attestation<T::EthSpec>>) {}

    fn handle_validator_subscription(&mut self) {}


    fn handle_message(&mut self, msg: AttestationServiceMessage<T::EthSpec>) {
        match msg {
            AttestationServiceMessage::Attestation(subnet, attestation) => {
                self.handle_attestation(subnet, attestation);
            }
            AttestationServiceMessage::ValidatorSubscription => {
                self.handle_validator_subscription();
            }
        }
    }
}
