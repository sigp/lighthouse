//! The main bootnode server execution.

use super::BootNodeConfig;
use eth2_libp2p::{
    discv5::{enr::NodeId, Discv5, Discv5Event},
    EnrExt, Eth2Enr,
};
use slog::info;
use types::EthSpec;

pub async fn run<T: EthSpec>(config: BootNodeConfig<T>, log: slog::Logger) {
    // Print out useful information about the generated ENR

    let enr_socket = config.local_enr.udp_socket().expect("Enr has a UDP socket");
    let eth2_field = config
        .local_enr
        .eth2()
        .map(|fork_id| hex::encode(fork_id.fork_digest))
        .unwrap_or_default();

    info!(log, "Configuration parameters"; "listening_address" => format!("{}:{}", config.listen_socket.ip(), config.listen_socket.port()), "broadcast_address" => format!("{}:{}",enr_socket.ip(), enr_socket.port()), "eth2" => eth2_field);

    info!(log, "Identity established"; "peer_id" => config.local_enr.peer_id().to_string(), "node_id" => config.local_enr.node_id().to_string());

    // build the contactable multiaddr list, adding the p2p protocol
    info!(log, "Contact information"; "enr" => config.local_enr.to_base64());
    info!(log, "Contact information"; "multiaddrs" => format!("{:?}", config.local_enr.multiaddr_p2p()));

    // construct the discv5 server
    let mut discv5 = Discv5::new(
        config.local_enr.clone(),
        config.local_key,
        config.discv5_config,
    )
    .unwrap();

    // If there are any bootnodes add them to the routing table
    for enr in config.boot_nodes {
        info!(
            log,
            "Adding bootnode";
            "address" => ?enr.udp_socket(),
            "peer_id" => enr.peer_id().to_string(),
            "node_id" => enr.node_id().to_string()
        );
        if enr != config.local_enr {
            if let Err(e) = discv5.add_enr(enr) {
                slog::warn!(log, "Failed adding ENR"; "error" => e.to_string());
            }
        }
    }

    // start the server
    if let Err(e) = discv5.start(config.listen_socket).await {
        slog::crit!(log, "Could not start discv5 server"; "error" => e.to_string());
        return;
    }

    // if there are peers in the local routing table, establish a session by running a query
    if !discv5.table_entries_id().is_empty() {
        info!(log, "Executing bootstrap query...");
        let _ = discv5.find_node(NodeId::random()).await;
    }

    // respond with metrics every 10 seconds
    let mut metric_interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

    // get an event stream
    let mut event_stream = match discv5.event_stream().await {
        Ok(stream) => stream,
        Err(e) => {
            slog::crit!(log, "Failed to obtain event stream"; "error" => e.to_string());
            return;
        }
    };

    // listen for events
    loop {
        tokio::select! {
            _ = metric_interval.tick() => {
                // display server metrics
                let metrics = discv5.metrics();
                info!(log, "Server metrics"; "connected_peers" => discv5.connected_peers(), "active_sessions" => metrics.active_sessions, "requests/s" => format!("{:.2}", metrics.unsolicited_requests_per_second));
            }
            Some(event) = event_stream.recv() => {
                match event {
                    Discv5Event::Discovered(_enr) => {
                        // An ENR has bee obtained by the server
                        // Ignore these events here
                    }
                    Discv5Event::EnrAdded { .. } => {}     // Ignore
                    Discv5Event::TalkRequest(_)  => {}     // Ignore
                    Discv5Event::NodeInserted { .. } => {} // Ignore
                    Discv5Event::SocketUpdated(socket_addr) => {
                        info!(log, "External socket address updated"; "socket_addr" => format!("{:?}", socket_addr));
                    }
                }
            }
        }
    }
}
