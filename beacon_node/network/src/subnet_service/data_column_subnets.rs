//! This service keeps track of which data column subnets the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to data column subnets and requests peer discoveries.

use futures::prelude::*;
use std::collections::HashSet;
use std::task::{Context, Poll};
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::time::sleep;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use delay_map::HashSetDelay;
use lighthouse_network::{discovery::peer_id_to_node_id, NetworkGlobals, Subnet, SubnetDiscovery};
use slog::{debug, error, info, o, trace, warn};
use slot_clock::SlotClock;
use types::{ChainSpec, DataColumnSubnetId, Epoch, EthSpec};

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

    /// A reference to the nodes network globals
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// The collection of all currently subscribed data column subnets by epoch.
    subscriptions: HashMap<DataColumnSubnetId, Epoch>,

    /// A collection of timeouts for when to unsubscribe from a subnet.
    unsubscriptions: HashSetDelay<DataColumnSubnetId>,

    /// The waker for the current thread.
    waker: Option<std::task::Waker>,

    chain_spec: ChainSpec,

    /// The logger for the data column service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> DataColumnService<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        chain_spec: &ChainSpec,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "data_column_service"));
        let spec = &beacon_chain.spec;
        let epoch_duration_secs =
            beacon_chain.slot_clock.slot_duration().as_secs() * T::EthSpec::slots_per_epoch();
        let default_timeout =
            epoch_duration_secs.saturating_mul(spec.epochs_per_sync_committee_period.as_u64());

        Self {
            events: VecDeque::with_capacity(10),
            beacon_chain,
            network_globals,
            subscriptions: HashMap::new(),
            unsubscriptions: HashSetDelay::new(Duration::from_secs(default_timeout)),
            waker: None,
            chain_spec: chain_spec.clone(),
            log,
        }
    }

     /// Starts the service which periodically updates data column subscriptions.
     pub fn start_data_column_update_service(mut self) -> Result<(), &'static str> {
        let log = self.log.clone();
        
        let slot_duration = Duration::from_secs(self.chain_spec.seconds_per_slot);
        let duration_to_next_epoch = self
            .beacon_chain
            .slot_clock
            .duration_to_next_epoch(T::EthSpec::slots_per_epoch())
            .ok_or("Unable to determine duration to next epoch")?;

        info!(
            log,
            "Data column service started";
            "next_update_millis" => duration_to_next_epoch.as_millis()
        );

        let executor = self.beacon_chain.task_executor.clone();

        let interval_fut = async move {
            if let Some(duration_to_next_epoch) = self
                .beacon_chain
                .slot_clock
                .duration_to_next_epoch(T::EthSpec::slots_per_epoch())
            {
                // if we are two slots or less away from the current epoch boundary
                // subscribe to the next epoch
                if duration_to_next_epoch - 2 * slot_duration <= Duration::from_secs(0) {
                    let current_epoch = self
                        .beacon_chain
                        .slot_clock
                        .now()
                        .map(|s| s.epoch(T::EthSpec::slots_per_epoch()));

                    if let Some(current_epoch) = current_epoch {
                        if let Err(e) = self.data_column_subscriptions(current_epoch + 1) {
                            error!(
                                log,
                                "Data column service failed";
                                "error" => e
                            )
                        }
                    }
                }

            }
        };

        executor.spawn(interval_fut, "");
        Ok(())
    }

    /// Process data column subscriptions for a given epoch
    /// This will
    /// - calculate the nodes data column custody requirements based on the epoch.
    /// - search for peers for the required subnets.
    /// - request data columns from the required subnets.
    pub fn data_column_subscriptions(&mut self, epoch: Epoch) -> Result<(), &'static str> {
        let node_id = peer_id_to_node_id(&self.network_globals.local_peer_id())
            .map_err(|_| "Could not get the local node id")?;

        let mut subnets_to_discover = Vec::new();

        let data_column_subnet_ids = DataColumnSubnetId::compute_subnets_for_data_column::<
            T::EthSpec,
        >(node_id.raw().into(), &self.chain_spec);

        // TODO(das) write column subscription requirements to the beacon chain

        for data_column_subnet_id in data_column_subnet_ids {
            // TODO(das) update required metrics values
            trace!(self.log,
                "data column subscription";
                "data_column_subnet_id" => ?data_column_subnet_id,
            );

            let exact_subnet = ExactSubnet {
                data_column_subnet_id,
                until_epoch: epoch,
            };

            subnets_to_discover.push(exact_subnet.clone());

            if let Err(e) = self.subscribe_to_subnet(exact_subnet.clone()) {
                warn!(self.log,
                    "Subscription to sync subnet error";
                    "error" => e,
                    "subnet_id" => *data_column_subnet_id
                    ,
                );
            } else {
                trace!(self.log,
                    "Subscribed to subnet for sync committee duties";
                    "exact_subnet" => ?exact_subnet,
                    "subnet_id" => *data_column_subnet_id
                );
            }
        }

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
        // Calculate the duration to the un-subscription event.
        let expected_end_subscription_duration = if current_slot >= until_slot {
            warn!(
                self.log,
                "data column subscription is past expiration";
                "current_slot" => current_slot,
                "exact_subnet" => ?exact_subnet,
            );
            return Ok(());
        } else {
            let slot_duration = self.beacon_chain.slot_clock.slot_duration();

            // the duration until we no longer need this subscription. We assume a single slot is
            // sufficient.
            self.beacon_chain
                .slot_clock
                .duration_to_slot(until_slot)
                .ok_or("Unable to determine duration to un-subscription slot")?
                + slot_duration
        };

        if !self
            .subscriptions
            .contains_key(&exact_subnet.data_column_subnet_id)
        {
            self.subscriptions.insert(
                exact_subnet.data_column_subnet_id.clone(),
                exact_subnet.until_epoch.clone(),
            );
            self.events
                .push_back(SubnetServiceMessage::Subscribe(Subnet::DataColumn(
                    exact_subnet.data_column_subnet_id,
                )));

            // add the subnet to the ENR bitfield
            self.events
                .push_back(SubnetServiceMessage::EnrAdd(Subnet::DataColumn(
                    exact_subnet.data_column_subnet_id,
                )));

            // add an unsubscription event to remove ourselves from the subnet once completed
            self.unsubscriptions.insert_at(
                exact_subnet.data_column_subnet_id,
                expected_end_subscription_duration,
            );
        } else {
            // We are already subscribed, extend the unsubscription duration
            self.unsubscriptions.update_timeout(
                &exact_subnet.data_column_subnet_id,
                expected_end_subscription_duration,
            );
        }

        return Ok(());
    }

    /// A queued unsubscription is ready.
    fn handle_unsubscriptions(&mut self, data_column_subnet_id: DataColumnSubnetId) {
        debug!(self.log, "Unsubscribing from subnet"; "subnet" => *data_column_subnet_id);

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

        // process any un-subscription events
        match self.unsubscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(exact_subnet))) => self.handle_unsubscriptions(exact_subnet),
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for subnet unsubscription times"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }

        // process any generated events
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Some(event));
        }

        Poll::Pending
    }
}
