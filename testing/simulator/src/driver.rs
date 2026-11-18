//! Drives a simulation by moving the shared slot clock forward one duty deadline at a time.
//!
//! After each move the driver waits until every checked beacon node holds what the duties before
//! that deadline should have produced, e.g. the block at the start of the slot or every
//! attestation at the attestation deadline. Only then does it move the clock again, so a slow
//! machine makes the simulation take longer rather than making a checked duty miss its deadline.

use crate::local_network::LocalNetwork;
use beacon_chain::chain_config::FORK_CHOICE_LOOKAHEAD_FACTOR;
use beacon_chain::{BeaconChain, BeaconChainTypes, StateSkipConfig};
use fork_choice::ForkChoiceStore;
use slot_clock::SlotClock;
use state_processing::common::get_attesting_indices_from_state;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch, Slot};

/// How long to wait for the nodes at one step. They normally take milliseconds, so this only
/// needs to be longer than a slow machine could take.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for validator client duties in the first epoch, where they may be missed.
const FIRST_EPOCH_SETTLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often to check whether the nodes have finished.
const SETTLE_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// What the nodes should hold once the duties before a deadline are done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Expectation {
    /// The block for the slot (and on Gloas its payload envelope) is the head.
    Block,
    /// Every unaggregated attestation for the slot is in the naive aggregation pool.
    Attestations,
    /// Every sync committee message for the slot is in the naive sync aggregation pool.
    SyncMessages,
    /// The aggregates in the operation pool cover every attester of the slot.
    AttestationAggregates,
    /// The sync contributions in the operation pool cover the whole sync committee.
    SyncContributions,
    /// The payload attestations in the operation pool cover the whole PTC.
    PayloadAttestations,
    /// Fork choice has run for the next slot, as it does near the end of every slot.
    ForkChoiceAdvanced,
}

impl Expectation {
    /// Whether this checks the validator clients' attestations or sync committee messages.
    fn is_duty(&self) -> bool {
        !matches!(self, Expectation::Block | Expectation::ForkChoiceAdvanced)
    }
}

pub struct SimDriver<E: EthSpec> {
    network: LocalNetwork<E>,
    spec: Arc<ChainSpec>,
    /// Beacon nodes, by index into `network.beacon_nodes`, that the driver doesn't check, e.g. a
    /// node that is still syncing or has lost its execution layer.
    excluded_beacon_nodes: parking_lot::RwLock<HashSet<usize>>,
}

impl<E: EthSpec> SimDriver<E> {
    pub fn new(network: LocalNetwork<E>, spec: Arc<ChainSpec>) -> Self {
        Self {
            network,
            spec,
            excluded_beacon_nodes: <_>::default(),
        }
    }

    /// Stops checking the beacon node at `index` in `network.beacon_nodes`.
    pub fn exclude_beacon_node(&self, index: usize) {
        self.excluded_beacon_nodes.write().insert(index);
    }

    /// Moves the clock to the start of the genesis slot once every beacon node is connected to
    /// every other one and every validator client knows the indices of all its validators, then
    /// waits for every validator client to start.
    pub async fn start_at_genesis(
        &self,
        validator_client_count: usize,
        validator_count: usize,
    ) -> Result<(), String> {
        let node_count = self.network.beacon_node_count() + self.network.proposer_node_count();
        self.wait_for(
            "beacon nodes to connect to each other",
            SETTLE_TIMEOUT,
            || async {
                for (index, remote_node) in self.network.remote_nodes()?.iter().enumerate() {
                    let peer_count = remote_node
                        .get_node_peer_count()
                        .await
                        .map_err(|e| format!("Unable to get peer count of node {index}: {e:?}"))?
                        .data
                        .connected;
                    if (peer_count as usize) < node_count - 1 {
                        return Err(format!(
                            "node {index} has {peer_count} of {} peers",
                            node_count - 1
                        ));
                    }
                }
                Ok(())
            },
        )
        .await?;

        // Before genesis, validator clients send proposer preparations for every validator whose
        // index they know. Once all have arrived, the validator clients' first duties requests
        // after genesis cover every validator.
        self.wait_for(
            "validator clients to learn their validator indices",
            SETTLE_TIMEOUT,
            || async {
                let mut missing = vec![];
                for index in 0..validator_count as u64 {
                    let mut prepared = false;
                    for (_, chain) in self.checked_beacon_chains(true)? {
                        if let Some(execution_layer) = &chain.execution_layer
                            && execution_layer.has_proposer_preparation_data(index).await
                        {
                            prepared = true;
                            break;
                        }
                    }
                    if !prepared {
                        missing.push(index);
                    }
                }
                if missing.is_empty() {
                    Ok(())
                } else {
                    Err(format!(
                        "no proposer preparation for validators {missing:?}"
                    ))
                }
            },
        )
        .await?;

        self.advance_to(*self.network.slot_clock.genesis_duration());

        // Validator clients are added to the network once they have started, which happens at
        // genesis.
        self.wait_for("validator clients to start", SETTLE_TIMEOUT, || async {
            let started = self.network.validator_client_count();
            if started == validator_client_count {
                Ok(())
            } else {
                Err(format!("{started} of {validator_client_count} started"))
            }
        })
        .await
    }

    /// Runs `slot`: moves the clock to each duty deadline in turn and waits for the duties to be
    /// done before moving it again.
    pub async fn run_slot(&self, slot: Slot) -> Result<(), String> {
        let spec = &self.spec;
        let slot_start = self
            .network
            .slot_clock
            .start_of(slot)
            .ok_or_else(|| format!("Unable to get start of slot {slot}"))?;
        let fork_name = spec.fork_name_at_slot::<E>(slot);

        // Each expectation with the time into the slot at which it must hold.
        let slot_duration = spec.get_slot_duration();
        let mut steps = vec![(
            slot_duration - slot_duration / FORK_CHOICE_LOOKAHEAD_FACTOR,
            Expectation::ForkChoiceAdvanced,
        )];
        // There's no block at the genesis slot, and validator clients only learn their first
        // duties at the start of the next slot.
        if slot > spec.genesis_slot {
            steps.extend([
                (Duration::ZERO, Expectation::Block),
                (
                    spec.get_attestation_due::<E>(slot),
                    Expectation::Attestations,
                ),
                (
                    spec.get_aggregate_attestation_due::<E>(slot),
                    Expectation::AttestationAggregates,
                ),
            ]);
            if fork_name.altair_enabled() {
                steps.extend([
                    (
                        spec.get_sync_message_due::<E>(slot),
                        Expectation::SyncMessages,
                    ),
                    (
                        spec.get_contribution_message_due::<E>(slot),
                        Expectation::SyncContributions,
                    ),
                ]);
            }
            if fork_name.gloas_enabled() {
                steps.push((
                    spec.get_payload_attestation_due(),
                    Expectation::PayloadAttestations,
                ));
            }
        }
        steps.sort();

        // Validator clients start at genesis. During the first epoch they fetch their first duties
        // and compute aggregator selection proofs while the driver moves the clock, so a duty can
        // be missed. Their duties must be done from the second epoch on.
        let first_epoch = spec.genesis_slot.epoch(E::slots_per_epoch());
        let check_duties = slot.epoch(E::slots_per_epoch()) > first_epoch;

        for (due, expectation) in steps {
            self.advance_to(slot_start + due);
            let description = format!("slot {slot}: {expectation:?}");
            let check = || async { self.check(slot, expectation) };
            if check_duties || !expectation.is_duty() {
                self.wait_for(&description, SETTLE_TIMEOUT, check).await?;
            } else if let Err(e) = self
                .wait_for(&description, FIRST_EPOCH_SETTLE_TIMEOUT, check)
                .await
            {
                // Waiting still gives the validator clients time to act before the clock moves
                // on, so they don't fall behind and skip later slots.
                eprintln!("{e}, not required in the first epoch");
            }
        }

        if (slot + 1) % E::slots_per_epoch() == 0 {
            println!("Finished epoch {}", slot.epoch(E::slots_per_epoch()));
        }
        Ok(())
    }

    /// Waits until the beacon node at `index` in `network.beacon_nodes` has imported the head
    /// block of every other checked node and has a head that its execution layer has verified,
    /// then checks that node again.
    pub async fn include_beacon_node_once_synced(&self, index: usize) -> Result<(), String> {
        self.wait_for(
            &format!("beacon node {index} to sync"),
            SETTLE_TIMEOUT,
            || async {
                let chain = self.beacon_chain(index)?;
                let head_root = chain.canonical_head.cached_head().head_block_root();
                for (other_index, other) in self.checked_beacon_chains(true)? {
                    let other_head = other.canonical_head.cached_head().head_block_root();
                    if other_head != head_root && !chain.block_is_known_to_fork_choice(&other_head)
                    {
                        return Err(format!(
                            "node {index} is missing head {other_head:?} of node {other_index}"
                        ));
                    }
                }
                if chain
                    .is_optimistic_or_invalid_head()
                    .map_err(|e| format!("Unable to read execution status: {e:?}"))?
                {
                    return Err(format!("node {index} has an optimistic head"));
                }
                Ok(())
            },
        )
        .await?;
        self.excluded_beacon_nodes.write().remove(&index);
        Ok(())
    }

    fn advance_to(&self, time: Duration) {
        let slot_clock = &self.network.slot_clock;
        if slot_clock.now_duration() < Some(time) {
            slot_clock.set_current_time(time);
        }
    }

    /// Polls `condition` until it returns `Ok`, or errors with its last error after `timeout`.
    async fn wait_for<F, Fut>(
        &self,
        description: &str,
        timeout: Duration,
        condition: F,
    ) -> Result<(), String>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let start = Instant::now();
        loop {
            let result = condition().await;
            match result {
                Ok(()) => return Ok(()),
                Err(e) if start.elapsed() > timeout => {
                    return Err(format!(
                        "Timed out after {timeout:?} waiting for {description}: {e}"
                    ));
                }
                Err(_) => tokio::time::sleep(SETTLE_POLL_INTERVAL).await,
            }
        }
    }

    fn check(&self, slot: Slot, expectation: Expectation) -> Result<(), String> {
        // Proposer-only nodes don't import unaggregated attestations.
        let include_proposer_nodes = expectation != Expectation::Attestations;
        for (index, chain) in self.checked_beacon_chains(include_proposer_nodes)? {
            let result = match expectation {
                Expectation::Block => check_block(&chain, slot),
                Expectation::Attestations => check_attestations(&chain, slot, false),
                Expectation::AttestationAggregates => check_attestations(&chain, slot, true),
                Expectation::SyncMessages => check_sync_committee(&chain, slot, false),
                Expectation::SyncContributions => check_sync_committee(&chain, slot, true),
                Expectation::PayloadAttestations => check_payload_attestations(&chain, slot),
                Expectation::ForkChoiceAdvanced => check_fork_choice_advanced(&chain, slot),
            };
            result.map_err(|e| format!("node {index}: {e}"))?;
        }
        Ok(())
    }

    fn beacon_chain(&self, index: usize) -> Result<SimChain<E>, String> {
        self.network
            .beacon_nodes
            .read()
            .get(index)
            .and_then(|node| node.client.beacon_chain())
            .ok_or_else(|| format!("No beacon chain for node {index}"))
    }

    /// Returns the beacon chains of the checked nodes, labelled with their index into
    /// `network.beacon_nodes`, or `proposer <index>` for proposer-only nodes.
    fn checked_beacon_chains(
        &self,
        include_proposer_nodes: bool,
    ) -> Result<Vec<(String, SimChain<E>)>, String> {
        let excluded = self.excluded_beacon_nodes.read();
        let mut chains = vec![];
        for (index, node) in self.network.beacon_nodes.read().iter().enumerate() {
            if !excluded.contains(&index) {
                let chain = node.client.beacon_chain().ok_or("No beacon chain")?;
                chains.push((index.to_string(), chain));
            }
        }
        if include_proposer_nodes {
            for (index, node) in self.network.proposer_nodes.read().iter().enumerate() {
                let chain = node.client.beacon_chain().ok_or("No beacon chain")?;
                chains.push((format!("proposer {index}"), chain));
            }
        }
        Ok(chains)
    }
}

type SimChain<E> = Arc<BeaconChain<SimTypes<E>>>;

type SimTypes<E> = beacon_chain::builder::Witness<
    slot_clock::ManualSlotClock,
    E,
    beacon_chain::store::database::interface::BeaconNodeBackend,
    beacon_chain::store::database::interface::BeaconNodeBackend,
>;

/// Returns the head state with the committee cache for its current epoch built.
fn head_state<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<BeaconState<T::EthSpec>, String> {
    let mut state = chain.head_beacon_state_cloned();
    state
        .build_committee_cache(RelativeEpoch::Current, &chain.spec)
        .map_err(|e| format!("Unable to build committee cache: {e:?}"))?;
    Ok(state)
}

fn check_block<T: BeaconChainTypes>(chain: &BeaconChain<T>, slot: Slot) -> Result<(), String> {
    let head = chain.canonical_head.cached_head();
    if head.head_slot() != slot {
        return Err(format!("head is at slot {}", head.head_slot()));
    }
    if chain
        .spec
        .fork_name_at_slot::<T::EthSpec>(slot)
        .gloas_enabled()
        && chain
            .get_payload_envelope(&head.head_block_root())
            .map_err(|e| format!("Unable to read payload envelope: {e:?}"))?
            .is_none()
    {
        return Err("payload envelope for the head block is missing".to_string());
    }
    Ok(())
}

/// Checks that the attestations for `slot` in the naive aggregation pool, or with `aggregated`
/// the operation pool, cover every member of the slot's committees.
fn check_attestations<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    slot: Slot,
    aggregated: bool,
) -> Result<(), String> {
    let state = head_state(chain)?;
    let expected = state
        .get_beacon_committees_at_slot(slot)
        .map_err(|e| format!("Unable to get committees: {e:?}"))?
        .iter()
        .flat_map(|committee| committee.committee.iter().map(|index| *index as u64))
        .collect::<BTreeSet<_>>();

    let attestations = if aggregated {
        chain
            .op_pool
            .get_filtered_attestations(|data, _| data.slot == slot)
    } else {
        chain
            .naive_aggregation_pool
            .read()
            .iter()
            .filter(|attestation| attestation.data().slot == slot)
            .cloned()
            .collect()
    };
    let mut attesters = BTreeSet::new();
    for attestation in &attestations {
        let indices = get_attesting_indices_from_state(&state, attestation.to_ref())
            .map_err(|e| format!("Unable to get attesting indices: {e:?}"))?;
        attesters.extend(indices);
    }

    let missing = expected.difference(&attesters).collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("missing attestations from validators {missing:?}"))
    }
}

/// Checks that the sync committee messages for `slot` in the naive sync aggregation pool, or with
/// `aggregated` the sync aggregate the operation pool builds from them, cover every sync committee
/// position.
fn check_sync_committee<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    slot: Slot,
    aggregated: bool,
) -> Result<(), String> {
    let mut positions = BTreeSet::new();
    if aggregated {
        // The operation pool builds the sync aggregate for the block at the next slot from the
        // contributions for `slot`.
        let state = chain
            .state_at_slot(slot + 1, StateSkipConfig::WithStateRoots)
            .map_err(|e| format!("Unable to get state at the next slot: {e:?}"))?;
        if let Some(sync_aggregate) = chain
            .op_pool
            .get_sync_aggregate(&state)
            .map_err(|e| format!("Unable to get sync aggregate: {e:?}"))?
        {
            for (position, set) in sync_aggregate.sync_committee_bits.iter().enumerate() {
                if set {
                    positions.insert(position);
                }
            }
        }
    } else {
        let subcommittee_size = <T::EthSpec as EthSpec>::sync_subcommittee_size();
        for contribution in chain
            .naive_sync_aggregation_pool
            .read()
            .iter()
            .filter(|contribution| contribution.slot == slot)
        {
            let offset = contribution.subcommittee_index as usize * subcommittee_size;
            for (bit, set) in contribution.aggregation_bits.iter().enumerate() {
                if set {
                    positions.insert(offset + bit);
                }
            }
        }
    }

    let missing = (0..<T::EthSpec as EthSpec>::sync_committee_size())
        .filter(|position| !positions.contains(position))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("missing sync committee positions {missing:?}"))
    }
}

/// Checks that fork choice has run for the slot after `slot`.
fn check_fork_choice_advanced<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    slot: Slot,
) -> Result<(), String> {
    let fork_choice_slot = chain
        .canonical_head
        .fork_choice_read_lock()
        .fc_store()
        .get_current_slot();
    if fork_choice_slot > slot {
        Ok(())
    } else {
        Err(format!("fork choice is at slot {fork_choice_slot}"))
    }
}

/// Checks that the payload attestations for `slot` in the operation pool cover the whole PTC.
fn check_payload_attestations<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    slot: Slot,
) -> Result<(), String> {
    let mut positions = BTreeSet::new();
    for attestation in chain
        .op_pool
        .get_all_payload_attestations(|data| data.slot == slot)
    {
        for (position, set) in attestation.aggregation_bits.iter().enumerate() {
            if set {
                positions.insert(position);
            }
        }
    }

    let missing = (0..<T::EthSpec as EthSpec>::ptc_size())
        .filter(|position| !positions.contains(position))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing payload attestations from PTC positions {missing:?}"
        ))
    }
}
