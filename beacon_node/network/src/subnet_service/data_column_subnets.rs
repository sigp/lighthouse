//! This service keeps track of which data column subnets the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to data column subnets and requests peer discoveries.

use futures::prelude::*;
use lighthouse_network::discv5::enr::NodeId;
use std::task::{Context, Poll};
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{Subnet, SubnetDiscovery};
use slog::{debug, error, o, trace, warn};
use slot_clock::SlotClock;
use types::{DataColumnSubnetId, Epoch, EthSpec};

use super::SubnetServiceMessage;

// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
/// Subnet discovery query takes at most 30 secs, 2 slots take 24s.
const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 2;

/// A particular subnet at a given slot.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ExactSubnet {
    /// The `DataColumnSubnetId` associated with this subnet.
    pub data_column_subnet_id: DataColumnSubnetId,
    /// The epoch until which we need to stay subscribed to the subnet.
    pub until_epoch: Epoch,
}

pub struct DataColumnService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<SubnetServiceMessage>,

    /// A reference to the beacon chain to process data columns.
    pub(crate) beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of all currently subscribed data column subnets by epoch.
    subscriptions: HashMap<DataColumnSubnetId, Epoch>,

    /// Future used to manage subscribing and unsubscribing from subnets.
    next_subscription_event: Pin<Box<tokio::time::Sleep>>,

    /// Our Discv5 node_id.
    node_id: NodeId,

    /// The waker for the current thread.
    waker: Option<std::task::Waker>,

    /// The logger for the data column service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> DataColumnService<T> {
    pub fn new(beacon_chain: Arc<BeaconChain<T>>, node_id: NodeId, log: &slog::Logger) -> Self {
        let log = log.new(o!("service" => "data_column_service"));

        Self {
            events: VecDeque::with_capacity(10),
            beacon_chain,
            subscriptions: HashMap::new(),
            next_subscription_event: {
                // Set a dummy sleep. Calculating the current subnet subscriptions will update this
                // value with a smarter timing
                Box::pin(tokio::time::sleep(Duration::from_secs(1)))
            },
            node_id,
            waker: None,
            log,
        }
    }

    fn recompute_subnets(&mut self) {
        // Ensure the next computation is scheduled even if assigning subnets fails.
        let next_subscription_event = self
            .recompute_subnets_inner()
            .unwrap_or_else(|_| self.beacon_chain.slot_clock.slot_duration());

        debug!(self.log, "Recomputing deterministic data column subnets");
        self.next_subscription_event = Box::pin(tokio::time::sleep(next_subscription_event));

        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref();
        }
    }

    fn recompute_subnets_inner(&mut self) -> Result<Duration, ()> {
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

        let (subnets, next_subscription_epoch) =
            DataColumnSubnetId::compute_subnets_for_data_column::<T::EthSpec>(
                self.node_id.raw().into(),
                current_epoch,
                &self.beacon_chain.spec,
            )
            .map_err(|_| error!(self.log, "Failed to compute data column subnets"))?;

        let next_subscription_slot =
            next_subscription_epoch.start_slot(T::EthSpec::slots_per_epoch());

        let next_subscription_event = self
            .beacon_chain
            .slot_clock
            .duration_to_slot(next_subscription_slot)
            .ok_or_else(|| {
                error!(
                    self.log,
                    "Failed to compute duration to next subscription event"
                )
            })?;

        if let Err(e) = self.data_column_subscriptions(subnets.collect(), current_epoch) {
            error!(self.log, "Failed to subscribe to data column subnets"; "err" => ?e);
        }

        Ok(next_subscription_event)
    }

    /// Process data column subscriptions for a given epoch
    /// This will
    /// - rotate data column custody requirements at epoch boundaries.
    /// - subscribe to required subnets and update enr fields.
    /// - search for peers for the required subnets.
    fn data_column_subscriptions(
        &mut self,
        data_column_subnet_ids: Vec<DataColumnSubnetId>,
        epoch: Epoch,
    ) -> Result<(), &'static str> {
        let mut subnets_to_discover = Vec::new();

        // unsubscribe from the previous epoch
        self.handle_unsubscriptions();

        for data_column_subnet_id in data_column_subnet_ids.iter() {
            // TODO(das) update required metrics values
            trace!(self.log,
                "data column subscription";
                "data_column_subnet_id" => ?data_column_subnet_id,
            );

            let exact_subnet = ExactSubnet {
                data_column_subnet_id: *data_column_subnet_id,
                until_epoch: epoch,
            };

            subnets_to_discover.push(exact_subnet.clone());

            if let Err(e) = self.subscribe_to_subnet(exact_subnet.clone()) {
                warn!(self.log,
                    "Subscription to sync data column subnet error";
                    "error" => e,
                    "subnet_id" => Into::<u64>::into(data_column_subnet_id)
                    ,
                );
            } else {
                trace!(self.log,
                    "Subscribed to data column subnet";
                    "exact_subnet" => ?exact_subnet,
                    "subnet_id" =>Into::<u64>::into(data_column_subnet_id)
                );
            }
        }

        self.beacon_chain
            .data_column_custody_tracker
            .set_custody_requirements(data_column_subnet_ids.iter().map(|id| id.into()).collect());

        if let Err(e) = self.discover_peers_request(subnets_to_discover.iter()) {
            warn!(self.log, "Discovery lookup request error"; "error" => e);
        };

        Ok(())
    }

    fn discover_peers_request<'a>(
        &mut self,
        exact_subnets: impl Iterator<Item = &'a ExactSubnet>,
    ) -> Result<(), &'static str> {
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let slots_per_epoch = T::EthSpec::slots_per_epoch();

        // TODO(das) discovery logic needs to be updated to match das requirements
        let discovery_subnets: Vec<SubnetDiscovery> = exact_subnets
            .filter_map(|exact_subnet| {
                let until_slot = exact_subnet.until_epoch.end_slot(slots_per_epoch);
                // check if there is enough time to perform a discovery lookup
                if until_slot >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD) {
                    // if the slot is more than epoch away, add an event to start looking for peers
                    // add one slot to ensure we keep the peer for the subscription slot
                    let min_ttl = self
                        .beacon_chain
                        .slot_clock
                        .duration_to_slot(until_slot + 1)
                        .map(|duration| std::time::Instant::now() + duration);
                    Some(SubnetDiscovery {
                        subnet: Subnet::DataColumn(exact_subnet.data_column_subnet_id),
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
            self.events
                .push_back(SubnetServiceMessage::DiscoverPeers(discovery_subnets));
        }

        Ok(())
    }

    fn subscribe_to_subnet(&mut self, exact_subnet: ExactSubnet) -> Result<(), &'static str> {
        // Return if we already have a subscription for exact_subnet
        if self.subscriptions.get(&exact_subnet.data_column_subnet_id)
            == Some(&exact_subnet.until_epoch)
        {
            return Ok(());
        }

        // Return if we already have subscription set to expire later than the current request.
        if let Some(until_epoch) = self.subscriptions.get(&exact_subnet.data_column_subnet_id) {
            if *until_epoch >= exact_subnet.until_epoch {
                return Ok(());
            }
        }

        // initialize timing variables
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let until_slot = exact_subnet.until_epoch.end_slot(slots_per_epoch);

        if current_slot >= until_slot {
            warn!(
                self.log,
                "data column subscription is past expiration";
                "current_slot" => current_slot,
                "exact_subnet" => ?exact_subnet,
            );
            return Ok(());
        }

        if let std::collections::hash_map::Entry::Vacant(e) =
            self.subscriptions.entry(exact_subnet.data_column_subnet_id)
        {
            e.insert(exact_subnet.until_epoch);

            self.events
                .push_back(SubnetServiceMessage::Subscribe(Subnet::DataColumn(
                    exact_subnet.data_column_subnet_id,
                )));

            // add the subnet to the ENR bitfield
            self.events
                .push_back(SubnetServiceMessage::EnrAdd(Subnet::DataColumn(
                    exact_subnet.data_column_subnet_id,
                )));
        }

        Ok(())
    }

    fn handle_unsubscriptions(&mut self) {
        let data_column_subnet_ids = self
            .beacon_chain
            .data_column_custody_tracker
            .get_custody_requirements();

        for data_column_subnet_id in data_column_subnet_ids {
            self.unsubscribe_to_subnet(data_column_subnet_id.into());
        }
    }

    /// handle unsubscribing from the subnet
    fn unsubscribe_to_subnet(&mut self, data_column_subnet_id: DataColumnSubnetId) {
        debug!(self.log, "Unsubscribing from data column subnet"; "subnet" => *data_column_subnet_id);

        self.subscriptions.remove(&data_column_subnet_id);
        self.events
            .push_back(SubnetServiceMessage::Unsubscribe(Subnet::DataColumn(
                data_column_subnet_id,
            )));

        self.events
            .push_back(SubnetServiceMessage::EnrRemove(Subnet::DataColumn(
                data_column_subnet_id,
            )));
    }
}

impl<T: BeaconChainTypes> Stream for DataColumnService<T> {
    type Item = SubnetServiceMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // update the waker if needed
        if let Some(waker) = &self.waker {
            if waker.will_wake(cx.waker()) {
                self.waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(cx.waker().clone());
        }

        match self.next_subscription_event.as_mut().poll(cx) {
            Poll::Ready(_) => {
                self.recompute_subnets();
                // We re-wake the task as there could be other subscriptions to process
                self.waker
                    .as_ref()
                    .expect("Waker has been set")
                    .wake_by_ref();
            }
            Poll::Pending => {}
        }

        // process any generated events
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Some(event));
        }

        Poll::Pending
    }
}
