use crate::common::{fork_context, spec_with_all_forks_enabled};
use lighthouse_network::discovery::load_enr_from_disk;
use lighthouse_network::rpc::methods::MetaDataV2;
use lighthouse_network::service::{Network, utils::METADATA_FILENAME};
use lighthouse_network::{Context, Eth2Enr, GossipTopic, NetworkConfig, NetworkGlobals, Subnet};
use ssz::{Decode, Encode};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use task_executor::test_utils::TestRuntime;
use types::{ChainSpec, EnrForkId, ForkContext, ForkName, Spec};

type E = Spec;

async fn build_network(
    runtime: &TestRuntime,
    path: &Path,
    fork: ForkName,
    spec: Arc<ChainSpec>,
    subscribe_all_subnets: bool,
) -> (Network<E>, Arc<NetworkGlobals<E>>, Arc<ForkContext>) {
    let mut config = NetworkConfig::default();
    config.network_dir = path.to_path_buf();
    config.disable_discovery = true;
    config.subscribe_all_subnets = subscribe_all_subnets;
    config.set_ipv4_listening_address(Ipv4Addr::LOCALHOST, 0, 0, 0);
    let context = Arc::new(fork_context(fork, &spec));
    let (network, globals) = Network::<E>::new(
        runtime.task_executor.clone(),
        Context {
            config: Arc::new(config),
            enr_fork_id: EnrForkId {
                fork_digest: context.current_fork_digest(),
                ..Default::default()
            },
            fork_context: context.clone(),
            chain_spec: spec.clone(),
            libp2p_registry: None,
        },
        spec.custody_requirement,
        lighthouse_network::identity::Keypair::generate_secp256k1(),
    )
    .await
    .unwrap();
    (network, globals, context)
}

fn check_advertisement(globals: &NetworkGlobals<E>, attnets: [u8; 8], syncnets: [u8; 1]) {
    for enr in [
        globals.local_enr(),
        load_enr_from_disk(&globals.config.network_dir).unwrap(),
    ] {
        assert_eq!(
            enr.attestation_bitfield::<E>().unwrap().as_ssz_bytes(),
            attnets
        );
        assert_eq!(
            enr.sync_committee_bitfield::<E>().unwrap().as_ssz_bytes(),
            syncnets
        );
    }
    let stored = std::fs::read(globals.config.network_dir.join(METADATA_FILENAME)).unwrap();
    let persisted = MetaDataV2::<E>::from_ssz_bytes(&stored).unwrap();
    let metadata = globals.local_metadata.read();
    assert_eq!(metadata.attnets().as_ssz_bytes(), attnets);
    assert_eq!(metadata.syncnets().unwrap().as_ssz_bytes(), syncnets);
    assert_eq!(persisted.attnets, *metadata.attnets());
    assert_eq!(persisted.syncnets, *metadata.syncnets().unwrap());
    assert_eq!(persisted.seq_number, *metadata.seq_number());
}

fn check_pq_topics(network: &Network<E>, digest: [u8; 4]) {
    let mut attestation_subnets = vec![];
    for subnet in network
        .gossipsub()
        .topics()
        .map(|hash| GossipTopic::decode(hash.as_str()).unwrap())
        .filter(|topic| topic.fork_digest == digest)
        .filter_map(|topic| topic.subnet_id())
    {
        match subnet {
            Subnet::Attestation(id) => attestation_subnets.push(*id),
            Subnet::SyncCommittee(id) => panic!("Unexpected PQ sync committee subnet {id:?}"),
            Subnet::DataColumn(_) => continue,
        }
    }
    attestation_subnets.sort_unstable();
    assert_eq!(attestation_subnets, (0..16).collect::<Vec<_>>());
}

#[tokio::test]
async fn pq_at_genesis_advertises_only_the_active_subnets() {
    let runtime = TestRuntime::default();
    let path = tempfile::tempdir().unwrap();
    let spec = Arc::new(ForkName::Pq.make_genesis_spec(spec_with_all_forks_enabled()));
    let (mut network, globals, context) =
        build_network(&runtime, path.path(), ForkName::Pq, spec, true).await;
    check_advertisement(&globals, [0; 8], [0]);

    let digest = context.current_fork_digest();
    network.subscribe_new_fork_topics(ForkName::Pq, digest);
    network.update_core_subnet_advertisement();
    check_advertisement(&globals, [255, 255, 0, 0, 0, 0, 0, 0], [0]);
    check_pq_topics(&network, digest);

    let seq = *globals.local_metadata.read().seq_number();
    network.update_core_subnet_advertisement();
    assert_eq!(*globals.local_metadata.read().seq_number(), seq);
}

#[tokio::test]
async fn pq_transition_clears_legacy_subnet_advertisements() {
    let runtime = TestRuntime::default();
    let spec = Arc::new(spec_with_all_forks_enabled());
    for subscribe_all in [true, false] {
        let path = tempfile::tempdir().unwrap();
        let (mut network, globals, context) = build_network(
            &runtime,
            path.path(),
            ForkName::Gloas,
            spec.clone(),
            subscribe_all,
        )
        .await;
        network.subscribe_new_fork_topics(ForkName::Gloas, context.current_fork_digest());
        if subscribe_all {
            network.update_core_subnet_advertisement();
            check_advertisement(&globals, [255; 8], [15]);
        } else {
            network.update_enr_subnet(Subnet::Attestation(1.into()), true);
            network.update_enr_subnet(Subnet::Attestation(17.into()), true);
            network.update_enr_subnet(Subnet::SyncCommittee(0.into()), true);
            check_advertisement(&globals, [2, 0, 2, 0, 0, 0, 0, 0], [1]);
        }

        let pq_context = fork_context(ForkName::Pq, &spec);
        let digest = pq_context.current_fork_digest();
        network.subscribe_new_fork_topics(ForkName::Pq, digest);
        context.update_current_fork(ForkName::Pq, digest, pq_context.current_fork_epoch());
        network.update_fork_version(EnrForkId {
            fork_digest: digest,
            ..Default::default()
        });

        let expected = if subscribe_all {
            [255, 255, 0, 0, 0, 0, 0, 0]
        } else {
            [2, 0, 0, 0, 0, 0, 0, 0]
        };
        check_advertisement(&globals, expected, [0]);
        let seq = *globals.local_metadata.read().seq_number();
        network.update_enr_subnet(Subnet::Attestation(17.into()), true);
        network.update_enr_subnet(Subnet::SyncCommittee(0.into()), true);
        network.update_core_subnet_advertisement();
        check_advertisement(&globals, expected, [0]);
        assert_eq!(*globals.local_metadata.read().seq_number(), seq);
        if subscribe_all {
            check_pq_topics(&network, digest);
        }
    }
}
