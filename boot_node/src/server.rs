//! The main bootnode server execution.

use super::BootNodeConfig;
use lighthouse_network::{
    discv5::{enr::NodeId, Discv5, Discv5Event},
    EnrExt, Eth2Enr,
};
use slog::info;
use types::EthSpec;

pub async fn run<T: EthSpec>(config: BootNodeConfig<T>, log: slog::Logger) {
    let BootNodeConfig {
        listen_socket,
        boot_nodes,
        local_enr,
        local_key,
        discv5_config,
        ..
    } = config;
    // Print out useful information about the generated ENR

    let enr_socket = local_enr.udp4_socket().expect("Enr has a UDP socket");
    let eth2_field = local_enr
        .eth2()
        .map(|fork_id| hex::encode(fork_id.fork_digest))
        .unwrap_or_default();

    info!(log, "Configuration parameters"; "listening_address" => %listen_socket, "broadcast_address" => %enr_socket, "eth2" => eth2_field);

    info!(log, "Identity established"; "peer_id" => %local_enr.peer_id(), "node_id" => %local_enr.node_id());

    // build the contactable multiaddr list, adding the p2p protocol
    info!(log, "Contact information"; "enr" => local_enr.to_base64());
    info!(log, "Contact information"; "multiaddrs" => ?local_enr.multiaddr_p2p());

    // construct the discv5 server
    let mut discv5 = Discv5::new(local_enr.clone(), local_key, discv5_config).unwrap();

    // If there are any bootnodes add them to the routing table
    for enr in boot_nodes {
        info!(
            log,
            "Adding bootnode";
            "address" => ?enr.udp4_socket(),
            "peer_id" => ?enr.peer_id(),
            "node_id" => ?enr.node_id()
        );
        if enr != local_enr {
            if let Err(e) = discv5.add_enr(enr) {
                slog::warn!(log, "Failed adding ENR"; "error" => ?e);
            }
        }
    }

    // start the server
    if let Err(e) = discv5.start(listen_socket).await {
        slog::crit!(log, "Could not start discv5 server"; "error" => %e);
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
            slog::crit!(log, "Failed to obtain event stream"; "error" => %e);
            return;
        }
    };

    // listen for events
    loop {
        tokio::select! {
            _ = metric_interval.tick() => {
                // display server metrics
                let metrics = discv5.metrics();
                info!(log, "Server metrics"; "connected_peers" => discv5.connected_peers(), "active_sessions" => metrics.active_sessions, "requests/s" => format_args!("{:.2}", metrics.unsolicited_requests_per_second));
            }
            Some(event) = event_stream.recv() => {
                match event {
                    Discv5Event::Discovered(_enr) => {
                        // An ENR has bee obtained by the server
                        // Ignore these events here
                    }
                    Discv5Event::EnrAdded { .. } => {}     // Ignore
                    Discv5Event::TalkRequest(_) => {}     // Ignore
                    Discv5Event::NodeInserted { .. } => {} // Ignore
                    Discv5Event::SocketUpdated(socket_addr) => {
                        info!(log, "Advertised socket address updated"; "socket_addr" => %socket_addr);
                    }
                    Discv5Event::SessionEstablished{ .. } => {} // Ignore
                }
            }
        }
    }
}
