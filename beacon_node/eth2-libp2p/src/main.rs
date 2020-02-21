use enr::Enr;
use eth2_libp2p::rpc::*;
use eth2_libp2p::NetworkConfig;
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::{Libp2pEvent, RPCEvent};
use slog::{o, warn, Drain, Level};
use std::time::Duration;
use tokio::prelude::*;
use types::{BeaconBlock, Epoch, EthSpec, Hash256, MinimalEthSpec, Slot};

type E = MinimalEthSpec;

pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    if enabled {
        slog::Logger::root(drain.filter_level(level).fuse(), o!())
    } else {
        slog::Logger::root(drain.filter(|_| false).fuse(), o!())
    }
}

pub fn build_config(
    port: u16,
    mut boot_nodes: Vec<Enr>,
    secret_key: Option<String>,
) -> NetworkConfig {
    let mut config = NetworkConfig::default();
    config.libp2p_port = port; // tcp port
    config.discovery_port = port; // udp port
    config.boot_nodes.append(&mut boot_nodes);
    config.secret_key_hex = secret_key;
    config.network_dir.push(port.to_string());
    // Reduce gossipsub heartbeat parameters
    config.gs_config.heartbeat_initial_delay = Duration::from_millis(500);
    config.gs_config.heartbeat_interval = Duration::from_millis(500);
    config
}

pub fn build_libp2p_instance(
    port: u16,
    boot_nodes: Vec<Enr>,
    secret_key: Option<String>,
    log: slog::Logger,
) -> LibP2PService<E> {
    let config = build_config(port, boot_nodes, secret_key);
    // launch libp2p service
    LibP2PService::new(&config, log.clone()).unwrap().1
}

fn main() {
    let log_level = Level::Trace;
    let enable_logging = true;

    let log = build_log(log_level, enable_logging);
    let service_log = log.clone();
    let args: Vec<String> = std::env::args().collect();
    let enr_text = "enr:-Iu4QFKG1suBpEE7ZvlGkPcrs9X0C_epWIX_1bvbsvoG3xF5X8Rc43n4Kj3WysUELA4BAaN0trsQ-iSsfkYS5L1xxoiAgmlkgnY0gmlwhKwSAAGJc2VjcDI1NmsxoQIeBk9GK-K12BydByZoNivFhXlvHyX2TdOq_6rzmeHaQIN0Y3CCIyiDdWRwgiMo";

    // 2nd argument must be enr if supplied
    let enrs = match args.len() {
        2 => match args[1].parse::<Enr>() {
            Ok(enr) => vec![enr],
            Err(_) => panic!("Pass valid enr"),
        },
        _ => vec![enr_text.parse::<Enr>().expect("should be valid enr")],
    };
    let mut service = build_libp2p_instance(9001, enrs, None, log);

    // Dummy STATUS RPC message
    let status_response = RPCResponse::Status(StatusMessage {
        fork_version: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });
    let spec = E::default_spec();
    // Dummy BLOCKS_BY_RANGE response
    let blocks_range_response = RPCResponse::BlocksByRange(Box::new(BeaconBlock::empty(&spec)));

    let service_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match service.poll().unwrap() {
                Async::Ready(Some(Libp2pEvent::RPC(peer_id, event))) => match event {
                    RPCEvent::Request(id, request) => {
                        match request {
                            RPCRequest::Status(m) => {
                                // send the response
                                warn!(service_log, "Receiver Received status request");
                                dbg!(m);
                                service.swarm.send_rpc(
                                    peer_id,
                                    RPCEvent::Response(
                                        id,
                                        RPCErrorResponse::Success(status_response.clone()),
                                    ),
                                );
                            }
                            RPCRequest::Goodbye(m) => {
                                warn!(service_log, "Receiver Received goodbye request");
                                dbg!(m);
                                return Ok(Async::Ready(true));
                            }
                            RPCRequest::BlocksByRange(m) => {
                                warn!(service_log, "Receiver Received block by range request");
                                dbg!(&m);
                                for _ in 0..m.count {
                                    service.swarm.send_rpc(
                                        peer_id.clone(),
                                        RPCEvent::Response(
                                            id,
                                            RPCErrorResponse::Success(
                                                blocks_range_response.clone(),
                                            ),
                                        ),
                                    );
                                }
                                // send the stream termination
                                service.swarm.send_rpc(
                                    peer_id,
                                    RPCEvent::Response(
                                        id,
                                        RPCErrorResponse::StreamTermination(
                                            ResponseTermination::BlocksByRange,
                                        ),
                                    ),
                                );
                            }
                            _ => (),
                        }
                    }
                    e => panic!("Received invalid RPC message {}", e),
                },
                Async::Ready(Some(_)) => println!("Here"),
                Async::Ready(None) | Async::NotReady => {
                    return Ok(Async::NotReady);
                }
            };
        }
    });

    let future = service_future.map_err(move |_| println!("Bakchodi"));
    tokio::run(future.map(|b| println!("{}", b)));
}
