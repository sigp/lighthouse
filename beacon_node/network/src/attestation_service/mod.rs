//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::prelude::*;
use hashmap_delay::HashSetDelay;
use slog::{debug, error, o, warn, trace};
use std::boxed::Box;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use std::collections::VecDeque;
use types::{Attestation, SubnetId};
use rest_types::ValidatorSubscription;
use rand::seq::SliceRandom;
use eth2_libp2p::{NetworkGlobals, types::GossipKind};
use types::{EthSpec, Slot};
use slot_clock::SlotClock;

/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 1;
/// The number of slots ahead that we attempt to discover peers for a subscription. If the slot to
/// attest to is greater than this, we queue a discovery request for this many slots prior to
/// subscribing.
const TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 6;
/// The time (in seconds) before a last seen validator is considered absent and we unsubscribe from the random
/// gossip topics that we subscribed to due to the validator connection.
const LAST_SEEN_VALIDATOR_TIMEOUT: u64 = 1800; // 30 mins
/// The number of seconds in advance that we subscribe to a subnet before the required slot.
const ADVANCE_SUBSCRIBE_SECS: u64 = 3;

#[derive(Debug, PartialEq)]
pub enum AttServiceMessage {
    /// Subscribe to the specified subnet id.
    Subscribe(SubnetId),
    /// Add the `SubnetId` to the ENR bitfield.
    ENRAdd(SubnetId),
    /// Remove the `SubnetId` from the ENR bitfield.
    ENRRemove(SubnetId),
    /// Unsubscribe to the specified subnet id.
    Unsubscribe(SubnetId),
    /// Discover peers for a particular subnet.
    DiscoverPeers(SubnetId),
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<AttServiceMessage>,

    /// A collection of public network variables.
    network_globals: Arc<NetworkGlobals>,

    /// A reference to the beacon chain to process received attestations.
    beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of currently subscribed random subnets mapped to their expiry deadline.
    random_subnets: HashSetDelay<SubnetId>,

    /// A collection of timeouts for when to start searching for peers for a particular shard.
    discover_peers: HashSetDelay<(SubnetId, Slot)>,

    /// A collection of timeouts for when to subscribe to a shard subnet.
    subscriptions: HashSetDelay<(SubnetId, Slot)>,

    /// A collection of timeouts for when to unsubscribe from a shard subnet.
    unsubscriptions: HashSetDelay<(SubnetId, Slot)>,

    /// A collection of seen validators. These dictate how many random subnets we should be
    /// subscribed to. As these time out, we unsubscribe for the required random subnets and update
    /// our ENR.
    /// This is a set of validator indices.
    known_validators: HashSetDelay<u64>, 

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    pub fn new(beacon_chain: Arc<BeaconChain<T>>, network_globals: Arc<NetworkGlobals>, log: &slog::Logger) -> Self {
        let log = log.new(o!("service" => "attestation_service"));

        // calculate the random subnet duration from the spec constants
        let spec = &beacon_chain.spec;
        let random_subnet_duration_millis = spec.epochs_per_random_subnet_subscription.saturating_mul(T::EthSpec::slots_per_epoch()).saturating_mul(spec.milliseconds_per_slot);

        // generate the AttestationService
        AttestationService {
            events: VecDeque::with_capacity(10),
            network_globals,
            beacon_chain,
            random_subnets: HashSetDelay::new(Duration::from_millis(random_subnet_duration_millis)),
            discover_peers: HashSetDelay::default(),
            subscriptions: HashSetDelay::default(),
            unsubscriptions: HashSetDelay::default(),
            known_validators: HashSetDelay::new(Duration::from_secs(LAST_SEEN_VALIDATOR_TIMEOUT)),
            log,
        }
    }

    /// It is time to run a discovery query to find peers for a particular subnet.
    fn handle_discover_peer(&mut self, subnet_id: SubnetId) {
        debug!(self.log, "Searching for peers for subnet"; "subnet" => *subnet_id);
        self.events.push_back(AttServiceMessage::DiscoverPeers(subnet_id));
    }

    fn handle_subscriptions(&mut self, subnet_id: SubnetId) {
        debug!(self.log, "Subscribing to subnet"; "subnet" => *subnet_id);
        self.events.push_back(AttServiceMessage::Subscribe(subnet_id));
    }

    fn handle_persistant_subnets(&mut self, _subnet: SubnetId) {}

    fn handle_attestation(&mut self, subnet: SubnetId, attestation: Box<Attestation<T::EthSpec>>) {}

    /// Processes a list of validator subscriptions.
    ///
    /// This will:
    /// - Register new validators as being known.
    /// - Subscribe to the required number of random subnets.
    /// - Update the local ENR for new random subnets due to seeing new validators.
    /// - Search for peers for required subnets.
    /// - Request subscriptions for subnets on specific slots when required.
    /// - Build the timeouts for each of these events.
    ///
    /// This returns a result simply for the ergonomics of using ?. The result can be
    /// safely dropped.
    pub fn handle_validator_subscriptions(&mut self, subscriptions: Vec<ValidatorSubscription>) -> Result<(),()> {

        for subscription in subscriptions {
                //NOTE: We assume all subscriptions have been verified before reaching this service

                // Registers the validator with the attestation service.
                // This will subscribe to long-lived random subnets if required.
                self.add_known_validator(subscription.validator_index);

                let subnet_id =  SubnetId::new(subscription.attestation_committee_index % self.beacon_chain.spec.attestation_subnet_count);
                // determine if we should run a discovery lookup request and request it if required
                self.discover_peers_request(subnet_id, subscription.slot);

                // set the subscription timer to subscribe to the next subnet if required 
                self.subscribe_to_subnet(subnet_id, subscription.slot);
        }
        Ok(())
    }


    /// Checks if there are currently queued discovery requests and the time required to make the
    /// request. 
    ///
    /// If there is sufficient time and no other request exists, queues a peer discovery request
    /// for the required subnet.
    fn discover_peers_request(&mut self, subnet_id: SubnetId, subscription_slot: Slot) -> Result<(),()> {

        let current_slot = self.beacon_chain.slot_clock.now().ok_or_else(|| { warn!(self.log, "Could not get the current slot");})?;
        let slot_duration = Duration::from_millis(self.beacon_chain.spec.milliseconds_per_slot);

                // if there is enough time to perform a discovery lookup
                if subscription_slot >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD) {

                    // check if a discovery request already exists
                    if self.discover_peers.get(&(subnet_id, subscription_slot)).is_some() { 
                        // already a request queued, end
                        return Ok(());
                    }

                    // check current event log to see if there is a discovery event queued
                    if self.events.iter().find(|event| event == &&AttServiceMessage::DiscoverPeers(subnet_id)).is_some() {
                        // already queued a discovery event
                        return Ok(());
                    }

                    // if the slot is more than epoch away, add an event to start looking for peers
                    if subscription_slot < current_slot.saturating_add(TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD)  {
                        // then instantly add a discovery request
                        self.events.push_back(AttServiceMessage::DiscoverPeers(subnet_id));
                    }
                    else {
                            // Queue the discovery event to be executed for
                            // TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD
                            
                            let duration_to_discover = {
                                let duration_to_next_slot = self.beacon_chain.slot_clock.duration_to_next_slot().ok_or_else(|| { warn!(self.log, "Unable to determine duration to next slot");})?;
                            // The -1 is done here to exclude the current slot duration, as we will use
                            // `duration_to_next_slot`.
                            let slots_until_discover = subscription_slot.saturating_sub(current_slot).saturating_sub(1u64).saturating_sub(TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD);

                            duration_to_next_slot + slot_duration * (slots_until_discover.as_u64() as u32)
                            };
                            
                            self.discover_peers.insert_at((subnet_id, subscription_slot), duration_to_discover);
                    }
                }
        Ok(())
    }


    /// Checks the current random subnets and subscriptions to determine if a new subscription for this
    /// subnet is required for the given slot.
    ///
    /// If required, adds a subscription event and an associated unsubscription event.
    fn subscribe_to_subnet(&mut self, subnet_id: SubnetId, subscription_slot: Slot) -> Result<(),()> {

        // initialise timing variables
        let current_slot = self.beacon_chain.slot_clock.now().ok_or_else(|| { warn!(self.log, "Could not get the current slot");})?;
        let slot_duration = Duration::from_millis(self.beacon_chain.spec.milliseconds_per_slot);
        let advance_subscription_duration = Duration::from_secs(ADVANCE_SUBSCRIBE_SECS);

        // calculate the time to subscribe to the subnet
        let duration_to_subscribe = {
            let duration_to_next_slot = self.beacon_chain.slot_clock.duration_to_next_slot().ok_or_else(|| { warn!(self.log, "Unable to determine duration to next slot");})?;
            // The -1 is done here to exclude the current slot duration, as we will use
            // `duration_to_next_slot`.
            let slots_until_subscribe = subscription_slot.saturating_sub(current_slot).saturating_sub(1u64);

            duration_to_next_slot + slot_duration * (slots_until_subscribe.as_u64() as u32) - advance_subscription_duration 
        };
        // the duration until we no longer need this subscription. We assume a single slot is
        // sufficient.
        let expected_end_subscription_duration = duration_to_subscribe + slot_duration + advance_subscription_duration;

        // Checks on current subscriptions

        // first check if the subnet exists as a long-lasting random subnet
        if let Some(expiry) =  self.random_subnets.get(&subnet_id) {
            // we are subscribed via a random subnet, if this is to expire during the time we need
            // to be subscribed, just extend the expiry
            if expiry < &(Instant::now() + expected_end_subscription_duration)  {
                self.random_subnets.update_timeout(&subnet_id, expected_end_subscription_duration);
            }
            // we are already subscribed, end
            return Ok(());
        }

        // Return if we already have a subscription for this subnet_id and slot
        if self.subscriptions.contains_key(&(subnet_id, subscription_slot)) {
            return Ok(());
        }

        // We are not currently subscribed and have no waiting subscription, create one
        self.subscriptions.insert_at((subnet_id, subscription_slot), duration_to_subscribe); 
        // add an unsubscription event to remove ourselves from the subnet once completed
        self.unsubscriptions.insert_at((subnet_id, subscription_slot), expected_end_subscription_duration);
        Ok(())
    }

    /// Updates the known_validators mapping and subscribes to a set of random subnets if required. 
    /// 
    /// This also updates the ENR to indicate our long-lived subscription to the subnet
    fn add_known_validator(&mut self, validator_index: u64) {
        if self.known_validators.get(&validator_index).is_none() {
            // New validator has subscribed
            // Subscribe to random topics and update the ENR if needed.
           
            let spec = &self.beacon_chain.spec;

            if self.random_subnets.len() < spec.attestation_subnet_count as usize {
                // Still room for subscriptions
                self.subscribe_to_random_subnets(self.beacon_chain.spec.random_subnets_per_validator as usize);
            }
        }
        // add the new validator or update the current timeout for a known validator
        self.known_validators.insert(validator_index);
    }

    /// Subscribe to long-lived random subnets and update the local ENR bitfield.
    fn subscribe_to_random_subnets(&mut self, mut no_subnets_to_subscribe: usize) {
        let subnet_count = self.beacon_chain.spec.attestation_subnet_count;

        // Build a list of random subnets that we are not currently subscribed to.
        let available_subnets = (0..subnet_count).map(SubnetId::new).filter(|subnet_id| self.random_subnets.get(subnet_id).is_none()).collect::<Vec<_>>();

        let to_subscribe_subnets = {
        if available_subnets.len() < no_subnets_to_subscribe  {
            debug!(self.log, "Reached maximum random subnet subscriptions");
            no_subnets_to_subscribe = available_subnets.len();
            available_subnets
        } else {
        // select a random sample of available subnets
        available_subnets.choose_multiple(&mut rand::thread_rng(), no_subnets_to_subscribe).cloned().collect::<Vec<_>>()
        }
        };

        for subnet_id in to_subscribe_subnets {
            // remove this subnet from any immediate subscription/un-subscription events
            self.subscriptions.retain(|(map_subnet_id, _)|  map_subnet_id != &subnet_id);
            self.unsubscriptions.retain(|(map_subnet_id, _)|  map_subnet_id != &subnet_id);

            // This inserts a new random subnet
            self.random_subnets.insert(subnet_id);

            // if we are not already subscribed, then subscribe
            let topic_kind = &GossipKind::CommitteeIndex(subnet_id); 

            if let None = self.network_globals.gossipsub_subscriptions.read().iter().find(|topic| topic.kind() == topic_kind) {
                // Not already subscribed to the topic
                self.events.push_back(AttServiceMessage::Subscribe(subnet_id));
            }
            // add the subnet to the ENR bitfield
            self.events.push_back(AttServiceMessage::ENRAdd(subnet_id));
        }
    }
}


impl<T: BeaconChainTypes> Stream for AttestationService<T> {
    type Item = AttServiceMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {

                // handle any discovery events
                while let Async::Ready(Some((subnet_id, _slot))) =
                    self.discover_peers.poll().map_err(|e| {
                        error!(self.log, "Failed to check for peer discovery requests"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_discover_peer(subnet_id);
                }

                while let Async::Ready(Some((subnet_id, _slot))) = self.subscriptions.poll().map_err(|e| {
                        error!(self.log, "Failed to check for subnet subscription times"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_subscriptions(subnet_id);
                }

                while let Async::Ready(Some(subnet)) = self.random_subnets.poll().map_err(|e| { 
                        error!(self.log, "Failed to check for random subnet cycles"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_persistant_subnets(subnet);
                }

                // process any generated events
                if let Some(event) = self.events.pop_front() {
                    return Ok(Async::Ready(Some(event)));
                }

                Ok(Async::NotReady)
        }
}


