//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use delay_map::HashSetDelay;
use futures::prelude::*;
use lighthouse_network::{discv5::enr::NodeId, NetworkConfig, Subnet, SubnetDiscovery};
use slog::{debug, error, o, warn};
use slot_clock::SlotClock;
use types::{
    Attestation, EthSpec, Slot, SubnetId, SyncCommitteeSubscription, SyncSubnetId,
    ValidatorSubscription,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub enum SubnetServiceMessage {
    /// Subscribe to the specified subnet id.
    Subscribe(Subnet),
    /// Unsubscribe to the specified subnet id.
    Unsubscribe(Subnet),
    /// Add the `SubnetId` to the ENR bitfield.
    EnrAdd(Subnet),
    /// Remove a sync committee subnet from the ENR.
    EnrRemove(SyncSubnetId),
    /// Discover peers for a list of `SubnetDiscovery`.
    DiscoverPeers(Vec<SubnetDiscovery>),
}

use crate::metrics;

/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
/// Subnet discovery query takes at most 30 secs, 2 slots take 24s.
pub(crate) const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 2;
/// The fraction of a slot that we subscribe to a subnet before the required slot.
///
/// Currently a whole slot ahead.
const ADVANCE_SUBSCRIBE_SLOT_FRACTION: u32 = 1;

/// The number of slots after an aggregator duty where we remove the entry from
/// `aggregate_validators_on_subnet` delay map.
const UNSUBSCRIBE_AFTER_AGGREGATOR_DUTY: u32 = 2;

/// A particular subnet at a given slot. This is used for Attestation subnets and not for sync
/// committee subnets because the logic for handling subscriptions between these types is different.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct ExactSubnet {
    /// The `SubnetId` associated with this subnet.
    pub subnet: Subnet,
    /// For Attestations, this slot represents the start time at which we need to subscribe to the
    /// slot.
    pub slot: Slot,
}

/// The enum used to group all kinds of validator subscriptions
#[derive(Debug, Clone, PartialEq)]
pub enum Subscription {
    Attestation(ValidatorSubscription),
    SyncCommittee(SyncCommitteeSubscription),
}

pub struct SubnetService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<SubnetServiceMessage>,

    /// A reference to the beacon chain to process received attestations.
    pub(crate) beacon_chain: Arc<BeaconChain<T>>,

    /// Subnets we are currently subscribed to as short lived subscriptions.
    ///
    /// Once they expire, we unsubscribe from these.
    /// We subscribe to subnets when we are an aggregator for an exact subnet.
    // NOTE: When setup the default timeout is set for sync committee subscriptions.
    subscriptions: HashSetDelay<Subnet>,

    /// Subscriptions that need to be executed in the future.
    scheduled_subscriptions: HashSetDelay<ExactSubnet>,

    /// A list of permanent subnets that this node is subscribed to.
    // TODO: Shift this to a dynamic bitfield
    permanent_attestation_subscriptions: HashSet<Subnet>,

    /// A collection timeouts to track the existence of aggregate validator subscriptions at an
    /// `ExactSubnet`.
    aggregate_validators_on_subnet: Option<HashSetDelay<ExactSubnet>>,

    /// The waker for the current thread.
    waker: Option<std::task::Waker>,

    /// The discovery mechanism of lighthouse is disabled.
    discovery_disabled: bool,

    /// We are always subscribed to all subnets.
    subscribe_all_subnets: bool,

    /// Whether this node is a block proposer-only node.
    proposer_only: bool,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> SubnetService<T> {
    /* Public functions */

    /// Establish the service based on the passed configuration.
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        node_id: NodeId,
        config: &NetworkConfig,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "subnet_service"));

        let slot_duration = beacon_chain.slot_clock.slot_duration();

        if config.subscribe_all_subnets {
            slog::info!(log, "Subscribing to all subnets");
        }

        // Build the list of known permanent subscriptions, so that we know not to subscribe or
        // discover them.
        let mut permanent_attestation_subscriptions = HashSet::default();
        if config.subscribe_all_subnets {
            // We are subscribed to all subnets, set all the bits to true.
            for index in 0..beacon_chain.spec.attestation_subnet_count {
                permanent_attestation_subscriptions
                    .insert(Subnet::Attestation(SubnetId::from(index)));
            }
        } else {
            // Not subscribed to all subnets, so just calculate the required subnets from the node
            // id.
            for subnet_id in
                SubnetId::compute_attestation_subnets(node_id.raw(), &beacon_chain.spec)
            {
                permanent_attestation_subscriptions.insert(Subnet::Attestation(subnet_id));
            }
        }

        // Set up the sync committee subscriptions
        let spec = &beacon_chain.spec;
        let epoch_duration_secs =
            beacon_chain.slot_clock.slot_duration().as_secs() * T::EthSpec::slots_per_epoch();
        let default_sync_committee_duration = Duration::from_secs(
            epoch_duration_secs.saturating_mul(spec.epochs_per_sync_committee_period.as_u64()),
        );

        let track_validators = !config.import_all_attestations;
        let aggregate_validators_on_subnet =
            track_validators.then(|| HashSetDelay::new(slot_duration));

        let mut events = VecDeque::with_capacity(10);

        // Queue discovery queries for the permanent attestation subnets
        if !config.disable_discovery {
            events.push_back(SubnetServiceMessage::DiscoverPeers(
                permanent_attestation_subscriptions
                    .iter()
                    .cloned()
                    .map(|subnet| SubnetDiscovery {
                        subnet,
                        min_ttl: None,
                    })
                    .collect(),
            ));
        }

        // Pre-populate the events with permanent subscriptions
        for subnet in permanent_attestation_subscriptions.iter() {
            events.push_back(SubnetServiceMessage::Subscribe(*subnet));
            events.push_back(SubnetServiceMessage::EnrAdd(*subnet));
        }

        SubnetService {
            events,
            beacon_chain,
            subscriptions: HashSetDelay::new(default_sync_committee_duration),
            permanent_attestation_subscriptions,
            scheduled_subscriptions: HashSetDelay::default(),
            aggregate_validators_on_subnet,
            waker: None,
            discovery_disabled: config.disable_discovery,
            subscribe_all_subnets: config.subscribe_all_subnets,
            proposer_only: config.proposer_only,
            log,
        }
    }

    /// Return count of all currently subscribed short-lived subnets.
    #[cfg(test)]
    pub fn subscriptions(&self) -> impl Iterator<Item = &Subnet> {
        self.subscriptions.iter()
    }

    #[cfg(test)]
    pub fn permanent_subscriptions(&self) -> impl Iterator<Item = &Subnet> {
        self.permanent_attestation_subscriptions.iter()
    }

    /// Returns whether we are subscribed to a subnet for testing purposes.
    #[cfg(test)]
    pub(crate) fn is_subscribed(&self, subnet: &Subnet) -> bool {
        self.subscriptions.contains_key(subnet)
            || self.permanent_attestation_subscriptions.contains(subnet)
    }

    /// Processes a list of validator subscriptions.
    ///
    /// This is fundamentally called form the HTTP API when a validator requests duties from us
    /// This will:
    /// - Register new validators as being known.
    /// - Search for peers for required subnets.
    /// - Request subscriptions for subnets on specific slots when required.
    /// - Build the timeouts for each of these events.
    ///
    /// This returns a result simply for the ergonomics of using ?. The result can be
    /// safely dropped.
    pub fn validator_subscriptions(&mut self, subscriptions: impl Iterator<Item = Subscription>) {
        // If the node is in a proposer-only state, we ignore all subnet subscriptions.
        if self.proposer_only {
            return;
        }

        // Maps each subnet subscription to it's highest slot
        let mut subnets_to_discover: HashMap<Subnet, Slot> = HashMap::new();

        // Registers the validator with the attestation service.
        for general_subscription in subscriptions {
            match general_subscription {
                Subscription::Attestation(subscription) => {
                    metrics::inc_counter(&metrics::SUBNET_SUBSCRIPTION_REQUESTS);

                    // Compute the subnet that is associated with this subscription
                    let subnet = match SubnetId::compute_subnet::<T::EthSpec>(
                        subscription.slot,
                        subscription.attestation_committee_index,
                        subscription.committee_count_at_slot,
                        &self.beacon_chain.spec,
                    ) {
                        Ok(subnet_id) => Subnet::Attestation(subnet_id),
                        Err(e) => {
                            warn!(self.log,
                                "Failed to compute subnet id for validator subscription";
                                "error" => ?e,
                            );
                            continue;
                        }
                    };

                    // Ensure each subnet_id inserted into the map has the highest slot as it's value.
                    // Higher slot corresponds to higher min_ttl in the `SubnetDiscovery` entry.
                    if let Some(slot) = subnets_to_discover.get(&subnet) {
                        if subscription.slot > *slot {
                            subnets_to_discover.insert(subnet, subscription.slot);
                        }
                    } else if !self.discovery_disabled {
                        subnets_to_discover.insert(subnet, subscription.slot);
                    }

                    let exact_subnet = ExactSubnet {
                        subnet,
                        slot: subscription.slot,
                    };

                    // Determine if the validator is an aggregator. If so, we subscribe to the subnet and
                    // if successful add the validator to a mapping of known aggregators for that exact
                    // subnet.

                    if subscription.is_aggregator {
                        metrics::inc_counter(&metrics::SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS);
                        if let Err(e) = self.subscribe_to_subnet(exact_subnet) {
                            warn!(self.log,
                                "Subscription to subnet error";
                                "error" => e,
                            );
                        }
                    }
                }
                Subscription::SyncCommittee(subscription) => {
                    metrics::inc_counter(&metrics::SYNC_COMMITTEE_SUBSCRIPTION_REQUESTS);
                    // NOTE: We assume all subscriptions have been verified before reaching this service

                    // Registers the validator with the subnet service.
                    let subnet_ids =
                        match SyncSubnetId::compute_subnets_for_sync_committee::<T::EthSpec>(
                            &subscription.sync_committee_indices,
                        ) {
                            Ok(subnet_ids) => subnet_ids,
                            Err(e) => {
                                warn!(self.log,
                                    "Failed to compute subnet id for sync committee subscription";
                                    "error" => ?e,
                                    "validator_index" => subscription.validator_index
                                );
                                continue;
                            }
                        };

                    for subnet_id in subnet_ids {
                        let subnet = Subnet::SyncCommittee(subnet_id);
                        let slot_required_until = subscription
                            .until_epoch
                            .start_slot(T::EthSpec::slots_per_epoch());
                        subnets_to_discover.insert(subnet, slot_required_until);

                        let Some(duration_to_unsubscribe) = self
                            .beacon_chain
                            .slot_clock
                            .duration_to_slot(slot_required_until)
                        else {
                            warn!(self.log, "Subscription to sync subnet error"; "error" => "Unable to determine duration to unsubscription slot", "validator_index" => subscription.validator_index);
                            continue;
                        };

                        if duration_to_unsubscribe == Duration::from_secs(0) {
                            let current_slot = self
                                .beacon_chain
                                .slot_clock
                                .now()
                                .unwrap_or(Slot::from(0u64));
                            warn!(
                                self.log,
                                "Sync committee subscription is past expiration";
                                "subnet" => ?subnet,
                                "current_slot" => ?current_slot,
                                "unsubscribe_slot" => ?slot_required_until,                           );
                            continue;
                        }

                        self.subscribe_to_sync_subnet(
                            subnet,
                            duration_to_unsubscribe,
                            slot_required_until,
                        );
                    }
                }
            }
        }

        // If the discovery mechanism isn't disabled, attempt to set up a peer discovery for the
        // required subnets.
        if !self.discovery_disabled {
            if let Err(e) = self.discover_peers_request(subnets_to_discover.into_iter()) {
                warn!(self.log, "Discovery lookup request error"; "error" => e);
            };
        }
    }

    /// Checks if we have subscribed aggregate validators for the subnet. If not, checks the gossip
    /// verification, re-propagates and returns false.
    pub fn should_process_attestation(
        &self,
        subnet: Subnet,
        attestation: &Attestation<T::EthSpec>,
    ) -> bool {
        // Proposer-only mode does not need to process attestations
        if self.proposer_only {
            return false;
        }
        self.aggregate_validators_on_subnet
            .as_ref()
            .map(|tracked_vals| {
                tracked_vals.contains_key(&ExactSubnet {
                    subnet,
                    slot: attestation.data().slot,
                })
            })
            .unwrap_or(true)
    }

    /* Internal private functions */

    /// Adds an event to the event queue and notifies that this service is ready to be polled
    /// again.
    fn queue_event(&mut self, ev: SubnetServiceMessage) {
        self.events.push_back(ev);
        if let Some(waker) = &self.waker {
            waker.wake_by_ref()
        }
    }
    /// Checks if there are currently queued discovery requests and the time required to make the
    /// request.
    ///
    /// If there is sufficient time, queues a peer discovery request for all the required subnets.
    // NOTE: Sending early subscriptions results in early searching for peers on subnets.
    fn discover_peers_request(
        &mut self,
        subnets_to_discover: impl Iterator<Item = (Subnet, Slot)>,
    ) -> Result<(), &'static str> {
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let discovery_subnets: Vec<SubnetDiscovery> = subnets_to_discover
            .filter_map(|(subnet, relevant_slot)| {
                // We generate discovery requests for all subnets (even one's we are permenantly
                // subscribed to) in order to ensure our peer counts are satisfactory to perform the
                // necessary duties.

                // Check if there is enough time to perform a discovery lookup.
                if relevant_slot >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD)
                {
                    // Send out an event to start looking for peers.
                    // Require the peer for an additional slot to ensure we keep the peer for the
                    // duration of the subscription.
                    let min_ttl = self
                        .beacon_chain
                        .slot_clock
                        .duration_to_slot(relevant_slot + 1)
                        .map(|duration| std::time::Instant::now() + duration);
                    Some(SubnetDiscovery { subnet, min_ttl })
                } else {
                    // We may want to check the global PeerInfo to see estimated timeouts for each
                    // peer before they can be removed.
                    warn!(self.log,
                        "Not enough time for a discovery search";
                        "subnet_id" => ?subnet,
                    );
                    None
                }
            })
            .collect();

        if !discovery_subnets.is_empty() {
            self.queue_event(SubnetServiceMessage::DiscoverPeers(discovery_subnets));
        }
        Ok(())
    }

    // Subscribes to the subnet if it should be done immediately, or schedules it if required.
    fn subscribe_to_subnet(
        &mut self,
        ExactSubnet { subnet, slot }: ExactSubnet,
    ) -> Result<(), &'static str> {
        // If the subnet is one of our permanent subnets, we do not need to subscribe.
        if self.subscribe_all_subnets || self.permanent_attestation_subscriptions.contains(&subnet)
        {
            return Ok(());
        }

        let slot_duration = self.beacon_chain.slot_clock.slot_duration();

        // The short time we schedule the subscription before it's actually required. This
        // ensures we are subscribed on time, and allows consecutive subscriptions to the same
        // subnet to overlap, reducing subnet churn.
        let advance_subscription_duration = slot_duration / ADVANCE_SUBSCRIBE_SLOT_FRACTION;
        // The time to the required slot.
        let time_to_subscription_slot = self
            .beacon_chain
            .slot_clock
            .duration_to_slot(slot)
            .unwrap_or_default(); // If this is a past slot we will just get a 0 duration.

        // Calculate how long before we need to subscribe to the subnet.
        let time_to_subscription_start =
            time_to_subscription_slot.saturating_sub(advance_subscription_duration);

        // The time after a duty slot where we no longer need it in the `aggregate_validators_on_subnet`
        // delay map.
        let time_to_unsubscribe =
            time_to_subscription_slot + UNSUBSCRIBE_AFTER_AGGREGATOR_DUTY * slot_duration;
        if let Some(tracked_vals) = self.aggregate_validators_on_subnet.as_mut() {
            tracked_vals.insert_at(ExactSubnet { subnet, slot }, time_to_unsubscribe);
        }

        // If the subscription should be done in the future, schedule it. Otherwise subscribe
        // immediately.
        if time_to_subscription_start.is_zero() {
            // This is a current or past slot, we subscribe immediately.
            self.subscribe_to_subnet_immediately(subnet, slot + 1)?;
        } else {
            // This is a future slot, schedule subscribing.
            // We need to include the slot to make the key unique to prevent overwriting the entry
            // for the same subnet.
            self.scheduled_subscriptions
                .insert_at(ExactSubnet { subnet, slot }, time_to_subscription_start);
        }

        Ok(())
    }

    /// Adds a subscription event to the sync subnet.
    fn subscribe_to_sync_subnet(
        &mut self,
        subnet: Subnet,
        duration_to_unsubscribe: Duration,
        slot_required_until: Slot,
    ) {
        // Return if we have subscribed to all subnets
        if self.subscribe_all_subnets {
            return;
        }

        // Update the unsubscription duration if we already have a subscription for the subnet
        if let Some(current_instant_to_unsubscribe) = self.subscriptions.deadline(&subnet) {
            // The extra 500ms in the comparison accounts of the inaccuracy of the underlying
            // DelayQueue inside the delaymap struct.
            let current_duration_to_unsubscribe = (current_instant_to_unsubscribe
                + Duration::from_millis(500))
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

            if duration_to_unsubscribe > current_duration_to_unsubscribe {
                self.subscriptions
                    .update_timeout(&subnet, duration_to_unsubscribe);
            }
        } else {
            // We have not subscribed before, so subscribe
            self.subscriptions
                .insert_at(subnet, duration_to_unsubscribe);
            // We are not currently subscribed and have no waiting subscription, create one
            debug!(self.log, "Subscribing to subnet"; "subnet" => ?subnet, "until" => ?slot_required_until);
            self.events
                .push_back(SubnetServiceMessage::Subscribe(subnet));

            // add the sync subnet to the ENR bitfield
            self.events.push_back(SubnetServiceMessage::EnrAdd(subnet));
        }
    }

    /* A collection of functions that handle the various timeouts */

    /// Registers a subnet as subscribed.
    ///
    /// Checks that the time in which the subscription would end is not in the past. If we are
    /// already subscribed, extends the timeout if necessary. If this is a new subscription, we send
    /// out the appropriate events.
    fn subscribe_to_subnet_immediately(
        &mut self,
        subnet: Subnet,
        end_slot: Slot,
    ) -> Result<(), &'static str> {
        if self.subscribe_all_subnets {
            // Case not handled by this service.
            return Ok(());
        }

        let time_to_subscription_end = self
            .beacon_chain
            .slot_clock
            .duration_to_slot(end_slot)
            .unwrap_or_default();

        // First check this is worth doing.
        if time_to_subscription_end.is_zero() {
            return Err("Time when subscription would end has already passed.");
        }

        // Check if we already have this subscription. If we do, optionally update the timeout of
        // when we need the subscription, otherwise leave as is.
        // If this is a new subscription simply add it to our mapping and subscribe.
        match self.subscriptions.deadline(&subnet) {
            Some(current_end_slot_time) => {
                // We are already subscribed. Check if we need to extend the subscription.
                if current_end_slot_time
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::from_secs(0))
                    < time_to_subscription_end
                {
                    self.subscriptions
                        .update_timeout(&subnet, time_to_subscription_end);
                }
            }
            None => {
                // This is a new subscription. Add with the corresponding timeout and send the
                // notification.
                self.subscriptions
                    .insert_at(subnet, time_to_subscription_end);

                // Inform of the subscription.
                debug!(self.log, "Subscribing to subnet";
                    "subnet" => ?subnet,
                    "end_slot" => end_slot,
                );
                self.queue_event(SubnetServiceMessage::Subscribe(subnet));
            }
        }
        Ok(())
    }

    // Unsubscribes from a subnet that was removed.
    fn handle_removed_subnet(&mut self, subnet: Subnet) {
        if !self.subscriptions.contains_key(&subnet) {
            // Subscription no longer exists as short lived subnet
            debug!(self.log, "Unsubscribing from subnet"; "subnet" => ?subnet);
            self.queue_event(SubnetServiceMessage::Unsubscribe(subnet));

            // If this is a sync subnet, we need to remove it from our ENR.
            if let Subnet::SyncCommittee(sync_subnet_id) = subnet {
                self.queue_event(SubnetServiceMessage::EnrRemove(sync_subnet_id));
            }
        }
    }
}

impl<T: BeaconChainTypes> Stream for SubnetService<T> {
    type Item = SubnetServiceMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Update the waker if needed.
        if let Some(waker) = &self.waker {
            if waker.will_wake(cx.waker()) {
                self.waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(cx.waker().clone());
        }

        // Send out any generated events.
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Some(event));
        }

        // Process scheduled subscriptions that might be ready, since those can extend a soon to
        // expire subscription.
        match self.scheduled_subscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(exact_subnet))) => {
                let ExactSubnet { subnet, .. } = exact_subnet;
                let current_slot = self.beacon_chain.slot_clock.now().unwrap_or_default();
                if let Err(e) = self.subscribe_to_subnet_immediately(subnet, current_slot + 1) {
                    debug!(self.log, "Failed to subscribe to short lived subnet"; "subnet" => ?subnet, "err" => e);
                }
                self.waker
                    .as_ref()
                    .expect("Waker has been set")
                    .wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for scheduled subnet subscriptions"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }

        // Process any expired subscriptions.
        match self.subscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(subnet))) => {
                self.handle_removed_subnet(subnet);
                // We re-wake the task as there could be other subscriptions to process
                self.waker
                    .as_ref()
                    .expect("Waker has been set")
                    .wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for subnet unsubscription times"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }

        // Poll to remove entries on expiration, no need to act on expiration events.
        if let Some(tracked_vals) = self.aggregate_validators_on_subnet.as_mut() {
            if let Poll::Ready(Some(Err(e))) = tracked_vals.poll_next_unpin(cx) {
                error!(self.log, "Failed to check for aggregate validator on subnet expirations"; "error"=> e);
            }
        }

        Poll::Pending
    }
}

/// Note: This `PartialEq` impl is for use only in tests.
/// The `DiscoverPeers` comparison is good enough for testing only.
#[cfg(test)]
impl PartialEq for SubnetServiceMessage {
    fn eq(&self, other: &SubnetServiceMessage) -> bool {
        match (self, other) {
            (SubnetServiceMessage::Subscribe(a), SubnetServiceMessage::Subscribe(b)) => a == b,
            (SubnetServiceMessage::Unsubscribe(a), SubnetServiceMessage::Unsubscribe(b)) => a == b,
            (SubnetServiceMessage::EnrAdd(a), SubnetServiceMessage::EnrAdd(b)) => a == b,
            (SubnetServiceMessage::DiscoverPeers(a), SubnetServiceMessage::DiscoverPeers(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                for i in 0..a.len() {
                    if a[i].subnet != b[i].subnet || a[i].min_ttl != b[i].min_ttl {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }
}
