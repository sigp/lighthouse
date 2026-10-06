#![cfg(not(debug_assertions))]
#![cfg(test)]
use super::UNSUBSCRIBE_DELAY_EPOCHS;
use crate::persisted_dht::load_dht;
use crate::{NetworkConfig, NetworkMessage, NetworkService};
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use beacon_processor::{BeaconProcessorChannels, BeaconProcessorConfig};
use futures::StreamExt;
use libp2p::gossipsub;
use lighthouse_network::identity::secp256k1;
use lighthouse_network::types::{GossipEncoding, GossipKind, core_topics_to_subscribe};
use lighthouse_network::{Enr, GossipTopic, NetworkGlobals};
use slot_clock::SlotClock;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use types::{
    BlobParameters, BlobSchedule, ChainSpec, Epoch, EthSpec, ForkName, MinimalEthSpec, Slot,
    SubnetId,
};

impl<T: BeaconChainTypes> NetworkService<T> {
    fn get_topic_params(&self, topic: GossipTopic) -> Option<&gossipsub::TopicScoreParams> {
        self.libp2p.get_topic_params(topic)
    }
}

#[test]
fn test_dht_persistence() {
    let beacon_chain = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .build()
        .chain;

    let store = beacon_chain.store.clone();

    let enr1 = Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap();
    let enr2 = Enr::from_str("enr:-IS4QJ2d11eu6dC7E7LoXeLMgMP3kom1u3SE8esFSWvaHoo0dP1jg8O3-nx9ht-EO3CmG7L6OkHcMmoIh00IYWB92QABgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQIB_c-jQMOXsbjWkbN-Oj99H57gfId5pfb4wa1qxwV4CIN1ZHCCIyk").unwrap();
    let enrs = vec![enr1, enr2];

    let runtime = Arc::new(Runtime::new().unwrap());

    let (signal, exit) = async_channel::bounded(1);
    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
    let executor = task_executor::TaskExecutor::new(Arc::downgrade(&runtime), exit, shutdown_tx);

    let mut config = NetworkConfig::default();
    config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, 21212, 21212, 21213);
    config.discv5_config.table_filter = |_| true; // Do not ignore local IPs
    config.upnp_enabled = false;
    config.boot_nodes_enr = enrs.clone();
    let config = Arc::new(config);
    runtime.block_on(async move {
        // Create a new network service which implicitly gets dropped at the
        // end of the block.

        let BeaconProcessorChannels {
            beacon_processor_tx,
            beacon_processor_rx: _beacon_processor_rx,
        } = <_>::default();

        let _network_service = NetworkService::start(
            beacon_chain.clone(),
            config,
            executor,
            None,
            beacon_processor_tx,
            secp256k1::Keypair::generate().into(),
        )
        .await
        .unwrap();
        drop(signal);
    });

    let raw_runtime = Arc::try_unwrap(runtime).unwrap();
    raw_runtime.shutdown_timeout(tokio::time::Duration::from_secs(300));

    // Load the persisted dht from the store
    let persisted_enrs = load_dht(store);
    assert!(
        persisted_enrs.contains(&enrs[0]),
        "should have persisted the first ENR to store"
    );
    assert!(
        persisted_enrs.contains(&enrs[1]),
        "should have persisted the second ENR to store"
    );
}

// Test removing topic weight on old topics when a fork happens.
#[test]
fn test_removing_topic_weight_on_old_topics() {
    let runtime = Arc::new(Runtime::new().unwrap());

    // Capella spec. Fork at epoch 2 so genesis is outside the subscribe window.
    let mut spec = MinimalEthSpec::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));
    spec.bellatrix_fork_epoch = Some(Epoch::new(0));
    spec.capella_fork_epoch = Some(Epoch::new(2));

    // Build beacon chain.
    let beacon_chain = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec.clone().into())
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build()
        .chain;
    let (next_fork_epoch, _) = beacon_chain.duration_to_next_digest().expect("next fork");
    assert_eq!(Some(next_fork_epoch), spec.capella_fork_epoch);

    // Build network service.
    let (mut network_service, network_globals, _network_senders) = runtime.block_on(async {
        let (_, exit) = async_channel::bounded(1);
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor =
            task_executor::TaskExecutor::new(Arc::downgrade(&runtime), exit, shutdown_tx);

        let mut config = NetworkConfig::default();
        config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, 21214, 21214, 21215);
        config.discv5_config.table_filter = |_| true; // Do not ignore local IPs
        config.upnp_enabled = false;
        let config = Arc::new(config);

        let beacon_processor_channels =
            BeaconProcessorChannels::new(&BeaconProcessorConfig::default());
        NetworkService::build(
            beacon_chain.clone(),
            config,
            executor.clone(),
            None,
            beacon_processor_channels.beacon_processor_tx,
            secp256k1::Keypair::generate().into(),
        )
        .await
        .unwrap()
    });

    // Subscribe to the topics.
    runtime.block_on(async {
        while network_globals.gossipsub_subscriptions.read().len() < 2 {
            if let Some(msg) = network_service.subnet_service.next().await {
                network_service.on_subnet_service_msg(msg);
            }
        }
    });

    // Make sure the service is subscribed to the topics.
    let (old_topic1, old_topic2) = {
        let mut subnets = SubnetId::compute_attestation_subnets(
            network_globals.local_enr().node_id().raw(),
            &spec,
        )
        .collect::<Vec<_>>();
        assert_eq!(2, subnets.len());

        let old_fork_digest = beacon_chain.enr_fork_id().fork_digest;
        let old_topic1 = GossipTopic::new(
            GossipKind::Attestation(subnets.pop().unwrap()),
            GossipEncoding::SSZSnappy,
            old_fork_digest,
        );
        let old_topic2 = GossipTopic::new(
            GossipKind::Attestation(subnets.pop().unwrap()),
            GossipEncoding::SSZSnappy,
            old_fork_digest,
        );

        (old_topic1, old_topic2)
    };
    let subscriptions = network_globals.gossipsub_subscriptions.read().clone();
    assert_eq!(2, subscriptions.len());
    assert!(subscriptions.contains(&old_topic1));
    assert!(subscriptions.contains(&old_topic2));
    let old_topic_params1 = network_service
        .get_topic_params(old_topic1.clone())
        .expect("topic score params");
    assert!(old_topic_params1.topic_weight > 0.0);
    let old_topic_params2 = network_service
        .get_topic_params(old_topic2.clone())
        .expect("topic score params");
    assert!(old_topic_params2.topic_weight > 0.0);

    // Advance slot to the next fork
    beacon_chain.slot_clock.set_slot(
        next_fork_epoch
            .start_slot(MinimalEthSpec::slots_per_epoch())
            .as_u64(),
    );

    runtime.block_on(async {
        network_service.update_next_fork_digest();
    });

    // Check that topic_weight on the old topics has been zeroed.
    let old_topic_params1 = network_service
        .get_topic_params(old_topic1)
        .expect("topic score params");
    assert_eq!(0.0, old_topic_params1.topic_weight);

    let old_topic_params2 = network_service
        .get_topic_params(old_topic2)
        .expect("topic score params");
    assert_eq!(0.0, old_topic_params2.topic_weight);
}

type TestBeaconChain = Arc<BeaconChain<EphemeralHarnessType<MinimalEthSpec>>>;

fn build_beacon_chain(spec: ChainSpec, slot: Slot) -> TestBeaconChain {
    let beacon_chain = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec.into())
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build()
        .chain;
    beacon_chain.slot_clock.set_slot(slot.as_u64());
    beacon_chain
}

fn network_config(port: u16) -> Arc<NetworkConfig> {
    let mut config = NetworkConfig::default();
    config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, port, port, port + 1);
    config.discv5_config.table_filter = |_| true; // Do not ignore local IPs
    config.upnp_enabled = false;
    Arc::new(config)
}

/// Steps the network service slot by slot through a Gloas fork and a later BPO fork, and checks
/// the topics after every slot.
#[test]
fn test_fork_topic_subscriptions_across_schedules() {
    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();
    let mut port = 21222;
    for gloas_epoch in [2, 3] {
        for bpo_gap in 1..=4 {
            let inside_gloas_window =
                Epoch::new(gloas_epoch).start_slot(slots_per_epoch) - slots_per_epoch + 1;
            // Sync at genesis, sync inside the Gloas window, start inside the Gloas window.
            for (start_slot, sync_slot) in [
                (Slot::new(0), Slot::new(0)),
                (Slot::new(0), inside_gloas_window),
                (inside_gloas_window, inside_gloas_window),
            ] {
                let mut spec = ForkName::Fulu.make_genesis_spec(MinimalEthSpec::default_spec());
                spec.gloas_fork_epoch = Some(Epoch::new(gloas_epoch));
                spec.blob_schedule = BlobSchedule::new(vec![BlobParameters {
                    epoch: Epoch::new(gloas_epoch + bpo_gap),
                    max_blobs_per_block: 12,
                }]);
                run_fork_schedule(spec, start_slot, sync_slot, port);
                port += 2;
            }
        }
    }
}

/// Runs one schedule. Sends `SubscribeCoreTopics` at `sync_slot`.
fn run_fork_schedule(spec: ChainSpec, start_slot: Slot, sync_slot: Slot, port: u16) {
    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();
    let last_digest_epoch = spec.all_digest_epochs().last().unwrap();
    let end_slot = (last_digest_epoch + UNSUBSCRIBE_DELAY_EPOCHS + 1).start_slot(slots_per_epoch);
    let beacon_chain = build_beacon_chain(spec, start_slot);
    // Paused time keeps the service timers in step with the slot clock.
    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap(),
    );

    runtime.block_on(async {
        let (_exit_signal, exit) = async_channel::bounded(1);
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor =
            task_executor::TaskExecutor::new(Arc::downgrade(&runtime), exit, shutdown_tx);
        let BeaconProcessorChannels {
            beacon_processor_tx,
            beacon_processor_rx: _beacon_processor_rx,
        } = <_>::default();
        let (network_globals, network_senders) = NetworkService::start(
            beacon_chain.clone(),
            network_config(port),
            executor,
            None,
            beacon_processor_tx,
            secp256k1::Keypair::generate().into(),
        )
        .await
        .unwrap();

        // Real timers fire a little late, so the slot clock reads just past each slot start.
        let lag = Duration::from_millis(1);
        let mut slot = start_slot;
        loop {
            if slot == sync_slot {
                network_senders
                    .network_send()
                    .send(NetworkMessage::SubscribeCoreTopics)
                    .unwrap();
            }
            settle().await;
            check_fork_topic_subscriptions(&beacon_chain, &network_globals, slot, sync_slot);

            if slot == end_slot {
                break;
            }
            slot += 1;
            let slot_start = beacon_chain.slot_clock.start_of(slot).unwrap();
            beacon_chain.slot_clock.set_current_time(slot_start + lag);
            tokio::time::advance(beacon_chain.spec.get_slot_duration() - lag).await;
            settle().await;
            tokio::time::advance(lag).await;
        }
    });
}

/// Lets the service handle ready events.
async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

/// Checks that:
/// - after sync, we are on the current digest's core topics
/// - after sync, we join a fork's core topics at least one epoch before the fork
/// - two epochs after a digest change, we are no longer on an older digest
fn check_fork_topic_subscriptions(
    beacon_chain: &TestBeaconChain,
    network_globals: &NetworkGlobals<MinimalEthSpec>,
    slot: Slot,
    sync_slot: Slot,
) {
    let spec = &beacon_chain.spec;
    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();
    let epoch = slot.epoch(slots_per_epoch);
    let next_digest_epoch = spec.next_digest_epoch(epoch);
    let subscriptions = network_globals.gossipsub_subscriptions.read().clone();
    let context = format!(
        "slot {slot}, sync slot {sync_slot}, {:?}",
        spec.all_digest_epochs().collect::<Vec<_>>()
    );

    let assert_on_core_topics = |digest_epoch: Epoch| {
        let digest = beacon_chain.compute_fork_digest(digest_epoch);
        for kind in core_topics_to_subscribe::<MinimalEthSpec>(
            spec.fork_name_at_epoch(digest_epoch),
            &network_globals.as_topic_config(),
            spec,
        ) {
            let topic = GossipTopic::new(kind, GossipEncoding::default(), digest);
            assert!(subscriptions.contains(&topic), "{context}: missing {topic}");
        }
    };
    if slot >= sync_slot {
        assert_on_core_topics(epoch);
        if let Some(next_digest_epoch) = next_digest_epoch
            && epoch + 1 >= next_digest_epoch
        {
            assert_on_core_topics(next_digest_epoch);
        }
    }

    let last_change_epoch = spec
        .all_digest_epochs()
        .filter(|digest_epoch| *digest_epoch <= epoch)
        .last()
        .unwrap_or(Epoch::new(0));
    if epoch >= last_change_epoch + UNSUBSCRIBE_DELAY_EPOCHS {
        let mut allowed_digests = vec![beacon_chain.compute_fork_digest(epoch)];
        if let Some(next_digest_epoch) = next_digest_epoch
            && epoch + 1 >= next_digest_epoch
        {
            allowed_digests.push(beacon_chain.compute_fork_digest(next_digest_epoch));
        }
        for topic in &subscriptions {
            assert!(
                allowed_digests.contains(&topic.fork_digest),
                "{context}: stale {topic}"
            );
        }
    }
}
