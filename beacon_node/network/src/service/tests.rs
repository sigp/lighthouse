#[cfg(not(debug_assertions))]
#[cfg(test)]
mod tests {
    use crate::persisted_dht::load_dht;
    use crate::{NetworkConfig, NetworkService};
    use beacon_chain::test_utils::BeaconChainHarness;
    use beacon_chain::BeaconChainTypes;
    use beacon_processor::{BeaconProcessorChannels, BeaconProcessorConfig};
    use futures::StreamExt;
    use lighthouse_network::types::{GossipEncoding, GossipKind};
    use lighthouse_network::{Enr, GossipTopic};
    use slog::{o, Drain, Level, Logger};
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::runtime::Runtime;
    use types::{Epoch, EthSpec, ForkName, MinimalEthSpec, SubnetId};

    impl<T: BeaconChainTypes> NetworkService<T> {
        fn get_topic_params(&self, topic: GossipTopic) -> Option<&gossipsub::TopicScoreParams> {
            self.libp2p.get_topic_params(topic)
        }
    }

    fn get_logger(actual_log: bool) -> Logger {
        if actual_log {
            let drain = {
                let decorator = slog_term::TermDecorator::new().build();
                let decorator =
                    logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
                let drain = slog_term::FullFormat::new(decorator).build().fuse();
                let drain = slog_async::Async::new(drain).chan_size(2048).build();
                drain.filter_level(Level::Debug)
            };

            Logger::root(drain.fuse(), o!())
        } else {
            let builder = NullLoggerBuilder;
            builder.build().expect("should build logger")
        }
    }

    #[test]
    fn test_dht_persistence() {
        let log = get_logger(false);

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
        let executor = task_executor::TaskExecutor::new(
            Arc::downgrade(&runtime),
            exit,
            log.clone(),
            shutdown_tx,
        );

        let mut config = NetworkConfig::default();
        config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, 21212, 21212, 21213);
        config.discv5_config.table_filter = |_| true; // Do not ignore local IPs
        config.upnp_enabled = false;
        config.boot_nodes_enr = enrs.clone();
        runtime.block_on(async move {
            // Create a new network service which implicitly gets dropped at the
            // end of the block.

            let BeaconProcessorChannels {
                beacon_processor_tx,
                beacon_processor_rx: _beacon_processor_rx,
                work_reprocessing_tx,
                work_reprocessing_rx: _work_reprocessing_rx,
            } = <_>::default();

            let _network_service = NetworkService::start(
                beacon_chain.clone(),
                &config,
                executor,
                None,
                beacon_processor_tx,
                work_reprocessing_tx,
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

        // Capella spec
        let mut spec = MinimalEthSpec::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        spec.capella_fork_epoch = Some(Epoch::new(1));

        // Build beacon chain.
        let beacon_chain = BeaconChainHarness::builder(MinimalEthSpec)
            .spec(spec.clone())
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build()
            .chain;
        let (next_fork_name, _) = beacon_chain.duration_to_next_fork().expect("next fork");
        assert_eq!(next_fork_name, ForkName::Capella);

        // Build network service.
        let (mut network_service, network_globals, _network_senders) = runtime.block_on(async {
            let (_, exit) = async_channel::bounded(1);
            let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
            let executor = task_executor::TaskExecutor::new(
                Arc::downgrade(&runtime),
                exit,
                get_logger(false),
                shutdown_tx,
            );

            let mut config = NetworkConfig::default();
            config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, 21214, 21214, 21215);
            config.discv5_config.table_filter = |_| true; // Do not ignore local IPs
            config.upnp_enabled = false;

            let beacon_processor_channels =
                BeaconProcessorChannels::new(&BeaconProcessorConfig::default());
            NetworkService::build(
                beacon_chain.clone(),
                &config,
                executor.clone(),
                None,
                beacon_processor_channels.beacon_processor_tx,
                beacon_processor_channels.work_reprocessing_tx,
            )
            .await
            .unwrap()
        });

        // Subscribe to the topics.
        runtime.block_on(async {
            while network_globals.gossipsub_subscriptions.read().len() < 2 {
                if let Some(msg) = network_service.attestation_service.next().await {
                    network_service.on_attestation_service_msg(msg);
                }
            }
        });

        // Make sure the service is subscribed to the topics.
        let (old_topic1, old_topic2) = {
            let mut subnets = SubnetId::compute_subnets_for_epoch::<MinimalEthSpec>(
                network_globals.local_enr().node_id().raw().into(),
                beacon_chain.epoch().unwrap(),
                &spec,
            )
            .unwrap()
            .0
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
        for _ in 0..MinimalEthSpec::slots_per_epoch() {
            beacon_chain.slot_clock.advance_slot();
        }

        // Run `NetworkService::update_next_fork()`.
        runtime.block_on(async {
            network_service.update_next_fork();
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
}
