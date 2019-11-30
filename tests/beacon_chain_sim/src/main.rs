mod simulated_network;

use futures::{future, stream, Future, IntoFuture, Stream};
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, ClientGenesis, LocalBeaconNode,
    LocalValidatorClient, ProductionClient, ValidatorConfig,
};
use simulated_network::LocalNetwork;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::timer::Delay;
use types::{Epoch, EthSpec, MinimalEthSpec};

pub type E = MinimalEthSpec;
pub type BeaconNode<E> = LocalBeaconNode<ProductionClient<E>>;
pub type ValidatorClient<E> = LocalValidatorClient<E>;

fn main() {
    let nodes = 4;
    let validators_per_node = 64 / nodes;

    match async_sim(nodes, validators_per_node, 4) {
        Ok(()) => println!("Simulation exited successfully"),
        Err(e) => println!("Simulation exited with error: {}", e),
    }
}

fn async_sim(
    node_count: usize,
    validators_per_node: usize,
    speed_up_factor: u64,
) -> Result<(), String> {
    let mut env = EnvironmentBuilder::minimal()
        .async_logger("debug")?
        .multi_threaded_tokio_runtime()?
        .build()?;

    env.eth2_config.spec.milliseconds_per_slot =
        env.eth2_config.spec.milliseconds_per_slot / speed_up_factor;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("should get system time")
        .as_secs();

    let mut beacon_config = testing_client_config();
    beacon_config.genesis = ClientGenesis::Interop {
        genesis_time: now,
        validator_count: node_count * validators_per_node,
    };

    let slot_duration = Duration::from_millis(env.eth2_config.spec.milliseconds_per_slot);

    let network = LocalNetwork::new(env.core_context(), beacon_config.clone())?;

    let network_1 = network.clone();
    let network_2 = network.clone();
    let network_3 = network.clone();

    let future = future::ok(())
        .and_then(move |()| {
            let network = network_1;

            for _ in 0..node_count - 1 {
                network.add_beacon_node(beacon_config.clone())?;
            }

            Ok(())
        })
        .and_then(move |()| {
            let network = network_2;

            stream::unfold(0..node_count, move |mut iter| {
                iter.next().map(|i| {
                    let indices = (i * validators_per_node..(i + 1) * validators_per_node)
                        .collect::<Vec<_>>();

                    network
                        .add_validator_client(ValidatorConfig::default(), i, indices)
                        .map(|()| ((), iter))
                })
            })
            .collect()
            .map(|_| ())
        })
        .and_then(move |_| {
            epoch_delay(Epoch::new(4), slot_duration, E::slots_per_epoch())
                .and_then(|()| verify_all_finalized_at(network_3, Epoch::new(2)))
        });

    env.runtime().block_on(future)
}

/// Delays for `epochs`, plus half a slot extra.
fn epoch_delay(
    epochs: Epoch,
    slot_duration: Duration,
    slots_per_epoch: u64,
) -> impl Future<Item = (), Error = String> {
    let duration = slot_duration * (epochs.as_u64() * slots_per_epoch) as u32 + slot_duration / 2;

    Delay::new(Instant::now() + duration).map_err(|e| format!("Epoch delay failed: {:?}", e))
}

fn verify_all_finalized_at<E: EthSpec>(
    network: LocalNetwork<E>,
    epoch: Epoch,
) -> impl Future<Item = (), Error = String> {
    network
        .remote_nodes()
        .into_future()
        .and_then(|remote_nodes| {
            stream::unfold(remote_nodes.into_iter(), |mut iter| {
                iter.next().map(|remote_node| {
                    remote_node
                        .http
                        .beacon()
                        .get_head()
                        .map(|head| head.finalized_slot.epoch(E::slots_per_epoch()))
                        .map(|epoch| (epoch, iter))
                        .map_err(|e| format!("Get head via http failed: {:?}", e))
                })
            })
            .collect()
        })
        .and_then(move |epochs| {
            if epochs.iter().any(|node_epoch| *node_epoch != epoch) {
                Err(format!(
                    "Nodes are not finalized at epoch {}. Finalized epochs: {:?}",
                    epoch, epochs
                ))
            } else {
                Ok(())
            }
        })
}
