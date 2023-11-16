//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use super::SubnetServiceMessage;
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use delay_map::{HashMapDelay, HashSetDelay};
use futures::prelude::*;
use lighthouse_network::{discv5::enr::NodeId, NetworkConfig, Subnet, SubnetDiscovery};
use slog::{debug, error, info, o, trace, warn};
use slot_clock::SlotClock;
use types::{Attestation, EthSpec, Slot, SubnetId, ValidatorSubscription};

use crate::metrics;

/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
/// Subnet discovery query takes at most 30 secs, 2 slots take 24s.
pub(crate) const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 2;
/// The fraction of a slot that we subscribe to a subnet before the required slot.
///
/// Currently a whole slot ahead.
const ADVANCE_SUBSCRIBE_SLOT_FRACTION: u32 = 1;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum SubscriptionKind {
    /// Long lived subscriptions.
    ///
    /// These have a longer duration and are advertised in our ENR.
    LongLived,
    /// Short lived subscriptions.
    ///
    /// Subscribing to these subnets has a short duration and we don't advertise it in our ENR.
    ShortLived,
}

/// A particular subnet at a given slot.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct ExactSubnet {
    /// The `SubnetId` associated with this subnet.
    pub subnet_id: SubnetId,
    /// The `Slot` associated with this subnet.
    pub slot: Slot,
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<SubnetServiceMessage>,

    /// A reference to the beacon chain to process received attestations.
    pub(crate) beacon_chain: Arc<BeaconChain<T>>,

    /// Subnets we are currently subscribed to as short lived subscriptions.
    ///
    /// Once they expire, we unsubscribe from these.
    /// We subscribe to subnets when we are an aggregator for an exact subnet.
    short_lived_subscriptions: HashMapDelay<SubnetId, Slot>,

    /// Subnets we are currently subscribed to as long lived subscriptions.
    ///
    /// We advertise these in our ENR. When these expire, the subnet is removed from our ENR.
    /// These are required of all beacon nodes. The exact number is determined by the chain
    /// specification.
    long_lived_subscriptions: HashSet<SubnetId>,

    /// Short lived subscriptions that need to be executed in the future.
    scheduled_short_lived_subscriptions: HashSetDelay<ExactSubnet>,

    /// A collection timeouts to track the existence of aggregate validator subscriptions at an
    /// `ExactSubnet`.
    aggregate_validators_on_subnet: Option<HashSetDelay<ExactSubnet>>,

    /// The waker for the current thread.
    waker: Option<std::task::Waker>,

    /// The discovery mechanism of lighthouse is disabled.
    discovery_disabled: bool,

    /// We are always subscribed to all subnets.
    subscribe_all_subnets: bool,

    /// Our Discv5 node_id.
    node_id: NodeId,

    /// Future used to manage subscribing and unsubscribing from long lived subnets.
    next_long_lived_subscription_event: Pin<Box<tokio::time::Sleep>>,

    /// Whether this node is a block proposer-only node.
    proposer_only: bool,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    /* Public functions */

    /// Establish the service based on the passed configuration.
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        node_id: NodeId,
        config: &NetworkConfig,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "attestation_service"));

        let slot_duration = beacon_chain.slot_clock.slot_duration();

        if config.subscribe_all_subnets {
            slog::info!(log, "Subscribing to all subnets");
        } else {
            slog::info!(log, "Deterministic long lived subnets enabled"; "subnets_per_node" => beacon_chain.spec.subnets_per_node, "subscription_duration_in_epochs" => beacon_chain.spec.epochs_per_subnet_subscription);
        }

        let track_validators = !config.import_all_attestations;
        let aggregate_validators_on_subnet =
            track_validators.then(|| HashSetDelay::new(slot_duration));
        let mut service = AttestationService {
            events: VecDeque::with_capacity(10),
            beacon_chain,
            short_lived_subscriptions: HashMapDelay::new(slot_duration),
            long_lived_subscriptions: HashSet::default(),
            scheduled_short_lived_subscriptions: HashSetDelay::default(),
            aggregate_validators_on_subnet,
            waker: None,
            discovery_disabled: config.disable_discovery,
            subscribe_all_subnets: config.subscribe_all_subnets,
            node_id,
            next_long_lived_subscription_event: {
                // Set a dummy sleep. Calculating the current subnet subscriptions will update this
                // value with a smarter timing
                Box::pin(tokio::time::sleep(Duration::from_secs(1)))
            },
            proposer_only: config.proposer_only,
            log,
        };

        // If we are not subscribed to all subnets, handle the deterministic set of subnets
        if !config.subscribe_all_subnets {
            service.recompute_long_lived_subnets();
        }

        service
    }

    /// Return count of all currently subscribed subnets (long-lived **and** short-lived).
    #[cfg(test)]
    pub fn subscription_count(&self) -> usize {
        if self.subscribe_all_subnets {
            self.beacon_chain.spec.attestation_subnet_count as usize
        } else {
            let count = self
                .short_lived_subscriptions
                .keys()
                .chain(self.long_lived_subscriptions.iter())
                .collect::<HashSet<_>>()
                .len();
            count
        }
    }

    /// Returns whether we are subscribed to a subnet for testing purposes.
    #[cfg(test)]
    pub(crate) fn is_subscribed(
        &self,
        subnet_id: &SubnetId,
        subscription_kind: SubscriptionKind,
    ) -> bool {
        match subscription_kind {
            SubscriptionKind::LongLived => self.long_lived_subscriptions.contains(subnet_id),
            SubscriptionKind::ShortLived => self.short_lived_subscriptions.contains_key(subnet_id),
        }
    }

    #[cfg(test)]
    pub(crate) fn long_lived_subscriptions(&self) -> &HashSet<SubnetId> {
        &self.long_lived_subscriptions
    }

    /// Processes a list of validator subscriptions.
    ///
    /// This will:
    /// - Register new validators as being known.
    /// - Search for peers for required subnets.
    /// - Request subscriptions for subnets on specific slots when required.
    /// - Build the timeouts for each of these events.
    ///
    /// This returns a result simply for the ergonomics of using ?. The result can be
    /// safely dropped.
    pub fn validator_subscriptions(
        &mut self,
        subscriptions: Vec<ValidatorSubscription>,
    ) -> Result<(), String> {
        // If the node is in a proposer-only state, we ignore all subnet subscriptions.
        if self.proposer_only {
            return Ok(());
        }

        // Maps each subnet_id subscription to it's highest slot
        let mut subnets_to_discover: HashMap<SubnetId, Slot> = HashMap::new();

        // Registers the validator with the attestation service.
        for subscription in subscriptions {
            metrics::inc_counter(&metrics::SUBNET_SUBSCRIPTION_REQUESTS);

            trace!(self.log,
                "Validator subscription";
                "subscription" => ?subscription,
            );

            // Compute the subnet that is associated with this subscription
            let subnet_id = match SubnetId::compute_subnet::<T::EthSpec>(
                subscription.slot,
                subscription.attestation_committee_index,
                subscription.committee_count_at_slot,
                &self.beacon_chain.spec,
            ) {
                Ok(subnet_id) => subnet_id,
                Err(e) => {
                    warn!(self.log,
                        "Failed to compute subnet id for validator subscription";
                        "error" => ?e,
                        "validator_index" => subscription.validator_index
                    );
                    continue;
                }
            };
            // Ensure each subnet_id inserted into the map has the highest slot as it's value.
            // Higher slot corresponds to higher min_ttl in the `SubnetDiscovery` entry.
            if let Some(slot) = subnets_to_discover.get(&subnet_id) {
                if subscription.slot > *slot {
                    subnets_to_discover.insert(subnet_id, subscription.slot);
                }
            } else if !self.discovery_disabled {
                subnets_to_discover.insert(subnet_id, subscription.slot);
            }

            let exact_subnet = ExactSubnet {
                subnet_id,
                slot: subscription.slot,
            };

            // Determine if the validator is an aggregator. If so, we subscribe to the subnet and
            // if successful add the validator to a mapping of known aggregators for that exact
            // subnet.

            if subscription.is_aggregator {
                metrics::inc_counter(&metrics::SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS);
                if let Err(e) = self.subscribe_to_short_lived_subnet(exact_subnet) {
                    warn!(self.log,
                        "Subscription to subnet error";
                        "error" => e,
                        "validator_index" => subscription.validator_index,
                    );
                } else {
                    trace!(self.log,
                        "Subscribed to subnet for aggregator duties";
                        "exact_subnet" => ?exact_subnet,
                        "validator_index" => subscription.validator_index
                    );
                }
            }
        }

        // If the discovery mechanism isn't disabled, attempt to set up a peer discovery for the
        // required subnets.
        if !self.discovery_disabled {
            if let Err(e) = self.discover_peers_request(
                subnets_to_discover
                    .into_iter()
                    .map(|(subnet_id, slot)| ExactSubnet { subnet_id, slot }),
            ) {
                warn!(self.log, "Discovery lookup request error"; "error" => e);
            };
        }

        Ok(())
    }

    fn recompute_long_lived_subnets(&mut self) {
        // Ensure the next computation is scheduled even if assigning subnets fails.
        let next_subscription_event = self
            .recompute_long_lived_subnets_inner()
            .unwrap_or_else(|_| self.beacon_chain.slot_clock.slot_duration());

        debug!(self.log, "Recomputing deterministic long lived subnets");
        self.next_long_lived_subscription_event =
            Box::pin(tokio::time::sleep(next_subscription_event));

        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref();
        }
    }

    /// Gets the long lived subnets the node should be subscribed to during the current epoch and
    /// the remaining duration for which they remain valid.
    fn recompute_long_lived_subnets_inner(&mut self) -> Result<Duration, ()> {
        let current_epoch = self.beacon_chain.epoch().map_err(|e| {
            if !self
                .beacon_chain
                .slot_clock
                .is_prior_to_genesis()
                .unwrap_or(false)
            {
                error!(self.log, "Failed to get the current epoch from clock"; "err" => ?e)
            }
        })?;

        let (subnets, next_subscription_epoch) = SubnetId::compute_subnets_for_epoch::<T::EthSpec>(
            self.node_id.raw().into(),
            current_epoch,
            &self.beacon_chain.spec,
        )
        .map_err(|e| error!(self.log, "Could not compute subnets for current epoch"; "err" => e))?;

        let next_subscription_slot =
            next_subscription_epoch.start_slot(T::EthSpec::slots_per_epoch());
        let next_subscription_event = self
            .beacon_chain
            .slot_clock
            .duration_to_slot(next_subscription_slot)
            .ok_or_else(|| {
                error!(
                    self.log,
                    "Failed to compute duration to next to long lived subscription event"
                )
            })?;

        self.update_long_lived_subnets(subnets.collect());

        Ok(next_subscription_event)
    }

    /// Updates the long lived subnets.
    ///
    /// New subnets are registered as subscribed, removed subnets as unsubscribed and the Enr
    /// updated accordingly.
    fn update_long_lived_subnets(&mut self, mut subnets: HashSet<SubnetId>) {
        info!(self.log, "Subscribing to long-lived subnets"; "subnets" => ?subnets.iter().collect::<Vec<_>>());
        for subnet in &subnets {
            // Add the events for those subnets that are new as long lived subscriptions.
            if !self.long_lived_subscriptions.contains(subnet) {
                // Check if this subnet is new and send the subscription event if needed.
                if !self.short_lived_subscriptions.contains_key(subnet) {
                    debug!(self.log, "Subscribing to subnet";
                        "subnet" => ?subnet,
                        "subscription_kind" => ?SubscriptionKind::LongLived,
                    );
                    self.queue_event(SubnetServiceMessage::Subscribe(Subnet::Attestation(
                        *subnet,
                    )));
                }
                self.queue_event(SubnetServiceMessage::EnrAdd(Subnet::Attestation(*subnet)));
                if !self.discovery_disabled {
                    self.queue_event(SubnetServiceMessage::DiscoverPeers(vec![SubnetDiscovery {
                        subnet: Subnet::Attestation(*subnet),
                        min_ttl: None,
                    }]))
                }
            }
        }

        // Update the long_lived_subnets set and check for subnets that are being removed
        std::mem::swap(&mut self.long_lived_subscriptions, &mut subnets);
        for subnet in subnets {
            if !self.long_lived_subscriptions.contains(&subnet) {
                self.handle_removed_subnet(subnet, SubscriptionKind::LongLived);
            }
        }
    }

    /// Checks if we have subscribed aggregate validators for the subnet. If not, checks the gossip
    /// verification, re-propagates and returns false.
    pub fn should_process_attestation(
        &self,
        subnet: SubnetId,
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
                    subnet_id: subnet,
                    slot: attestation.data.slot,
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
    fn discover_peers_request(
        &mut self,
        exact_subnets: impl Iterator<Item = ExactSubnet>,
    ) -> Result<(), &'static str> {
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let discovery_subnets: Vec<SubnetDiscovery> = exact_subnets
            .filter_map(|exact_subnet| {
                // Check if there is enough time to perform a discovery lookup.
                if exact_subnet.slot
                    >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD)
                {
                    // Send out an event to start looking for peers.
                    // Require the peer for an additional slot to ensure we keep the peer for the
                    // duration of the subscription.
                    let min_ttl = self
                        .beacon_chain
                        .slot_clock
                        .duration_to_slot(exact_subnet.slot + 1)
                        .map(|duration| std::time::Instant::now() + duration);
                    Some(SubnetDiscovery {
                        subnet: Subnet::Attestation(exact_subnet.subnet_id),
                        min_ttl,
                    })
                } else {
                    // We may want to check the global PeerInfo to see estimated timeouts for each
                    // peer before they can be removed.
                    warn!(self.log,
                        "Not enough time for a discovery search";
                        "subnet_id" => ?exact_subnet
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
    fn subscribe_to_short_lived_subnet(
        &mut self,
        ExactSubnet { subnet_id, slot }: ExactSubnet,
    ) -> Result<(), &'static str> {
        let slot_duration = self.beacon_chain.slot_clock.slot_duration();

        // Calculate how long before we need to subscribe to the subnet.
        let time_to_subscription_start = {
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
            time_to_subscription_slot.saturating_sub(advance_subscription_duration)
        };

        if let Some(tracked_vals) = self.aggregate_validators_on_subnet.as_mut() {
            tracked_vals.insert(ExactSubnet { subnet_id, slot });
        }

        // If the subscription should be done in the future, schedule it. Otherwise subscribe
        // immediately.
        if time_to_subscription_start.is_zero() {
            // This is a current or past slot, we subscribe immediately.
            self.subscribe_to_short_lived_subnet_immediately(subnet_id, slot + 1)?;
        } else {
            // This is a future slot, schedule subscribing.
            trace!(self.log, "Scheduling subnet subscription"; "subnet" => ?subnet_id, "time_to_subscription_start" => ?time_to_subscription_start);
            self.scheduled_short_lived_subscriptions
                .insert_at(ExactSubnet { subnet_id, slot }, time_to_subscription_start);
        }

        Ok(())
    }

    /* A collection of functions that handle the various timeouts */

    /// Registers a subnet as subscribed.
    ///
    /// Checks that the time in which the subscription would end is not in the past. If we are
    /// already subscribed, extends the timeout if necessary. If this is a new subscription, we send
    /// out the appropriate events.
    ///
    /// On determinist long lived subnets, this is only used for short lived subscriptions.
    fn subscribe_to_short_lived_subnet_immediately(
        &mut self,
        subnet_id: SubnetId,
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

        let subscription_kind = SubscriptionKind::ShortLived;

        // We need to check and add a subscription for the right kind, regardless of the presence
        // of the subnet as a subscription of the other kind. This is mainly since long lived
        // subscriptions can be removed at any time when a validator goes offline.

        let (subscriptions, already_subscribed_as_other_kind) = (
            &mut self.short_lived_subscriptions,
            self.long_lived_subscriptions.contains(&subnet_id),
        );

        match subscriptions.get(&subnet_id) {
            Some(current_end_slot) => {
                // We are already subscribed. Check if we need to extend the subscription.
                if &end_slot > current_end_slot {
                    trace!(self.log, "Extending subscription to subnet";
                        "subnet" => ?subnet_id,
                        "prev_end_slot" => current_end_slot,
                        "new_end_slot" => end_slot,
                        "subscription_kind" => ?subscription_kind,
                    );
                    subscriptions.insert_at(subnet_id, end_slot, time_to_subscription_end);
                }
            }
            None => {
                // This is a new subscription. Add with the corresponding timeout and send the
                // notification.
                subscriptions.insert_at(subnet_id, end_slot, time_to_subscription_end);

                // Inform of the subscription.
                if !already_subscribed_as_other_kind {
                    debug!(self.log, "Subscribing to subnet";
                        "subnet" => ?subnet_id,
                        "end_slot" => end_slot,
                        "subscription_kind" => ?subscription_kind,
                    );
                    self.queue_event(SubnetServiceMessage::Subscribe(Subnet::Attestation(
                        subnet_id,
                    )));
                }
            }
        }

        Ok(())
    }

    // Unsubscribes from a subnet that was removed if it does not continue to exist as a
    // subscription of the other kind. For long lived subscriptions, it also removes the
    // advertisement from our ENR.
    fn handle_removed_subnet(&mut self, subnet_id: SubnetId, subscription_kind: SubscriptionKind) {
        let exists_in_other_subscriptions = match subscription_kind {
            SubscriptionKind::LongLived => self.short_lived_subscriptions.contains_key(&subnet_id),
            SubscriptionKind::ShortLived => self.long_lived_subscriptions.contains(&subnet_id),
        };

        if !exists_in_other_subscriptions {
            // Subscription no longer exists as short lived or long lived.
            debug!(self.log, "Unsubscribing from subnet"; "subnet" => ?subnet_id, "subscription_kind" => ?subscription_kind);
            self.queue_event(SubnetServiceMessage::Unsubscribe(Subnet::Attestation(
                subnet_id,
            )));
        }

        if subscription_kind == SubscriptionKind::LongLived {
            // Remove from our ENR even if we remain subscribed in other way.
            self.queue_event(SubnetServiceMessage::EnrRemove(Subnet::Attestation(
                subnet_id,
            )));
        }
    }
}

impl<T: BeaconChainTypes> Stream for AttestationService<T> {
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

        // If we aren't subscribed to all subnets, handle the deterministic long-lived subnets
        if !self.subscribe_all_subnets {
            match self.next_long_lived_subscription_event.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    self.recompute_long_lived_subnets();
                    // We re-wake the task as there could be other subscriptions to process
                    self.waker
                        .as_ref()
                        .expect("Waker has been set")
                        .wake_by_ref();
                }
                Poll::Pending => {}
            }
        }

        // Process scheduled subscriptions that might be ready, since those can extend a soon to
        // expire subscription.
        match self.scheduled_short_lived_subscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(ExactSubnet { subnet_id, slot }))) => {
                if let Err(e) =
                    self.subscribe_to_short_lived_subnet_immediately(subnet_id, slot + 1)
                {
                    debug!(self.log, "Failed to subscribe to short lived subnet"; "subnet" => ?subnet_id, "err" => e);
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

        // Finally process any expired subscriptions.
        match self.short_lived_subscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((subnet_id, _end_slot)))) => {
                self.handle_removed_subnet(subnet_id, SubscriptionKind::ShortLived);
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
