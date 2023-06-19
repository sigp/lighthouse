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
        boot_nodes,
        local_enr,
        local_key,
        discv5_config,
        ..
    } = config;

    // Print out useful information about the generated ENR

    let enr_v4_socket = local_enr.udp4_socket();
    let enr_v6_socket = local_enr.udp6_socket();
    let eth2_field = local_enr
        .eth2()
        .map(|fork_id| hex::encode(fork_id.fork_digest))
        .unwrap_or_default();

    let pretty_v4_socket = enr_v4_socket.as_ref().map(|addr| addr.to_string());
    let pretty_v6_socket = enr_v6_socket.as_ref().map(|addr| addr.to_string());
    info!(
        log, "Configuration parameters";
        "listening_address" => ?discv5_config.listen_config,
        "advertised_v4_address" => ?pretty_v4_socket,
        "advertised_v6_address" => ?pretty_v6_socket,
        "eth2" => eth2_field
    );

    info!(log, "Identity established"; "peer_id" => %local_enr.peer_id(), "node_id" => %local_enr.node_id());

    // build the contactable multiaddr list, adding the p2p protocol
    info!(log, "Contact information"; "enr" => local_enr.to_base64());
    info!(log, "Enr details"; "enr" => ?local_enr);
    info!(log, "Contact information"; "multiaddrs" => ?local_enr.multiaddr_p2p());

    // construct the discv5 server
    let mut discv5: Discv5 = Discv5::new(local_enr.clone(), local_key, discv5_config).unwrap();

    // If there are any bootnodes add them to the routing table
    for enr in boot_nodes {
        info!(
            log,
            "Adding bootnode";
            "ipv4_address" => ?enr.udp4_socket(),
            "ipv6_address" => ?enr.udp6_socket(),
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
    if let Err(e) = discv5.start().await {
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
                // Get some ipv4/ipv6 stats to add in the metrics.
                let mut ipv4_only_reachable: usize = 0;
                let mut ipv6_only_reachable: usize= 0;
                let mut ipv4_ipv6_reachable: usize = 0;
                let mut unreachable_nodes: usize = 0;
                for enr in discv5.kbuckets().iter_ref().filter_map(|entry| entry.status.is_connected().then_some(entry.node.value)) {
                    let declares_ipv4 = enr.udp4_socket().is_some();
                    let declares_ipv6 = enr.udp6_socket().is_some();
                    match (declares_ipv4, declares_ipv6) {
                        (true, true) => ipv4_ipv6_reachable += 1,
                        (true, false) => ipv4_only_reachable += 1,
                        (false, true) => ipv6_only_reachable += 1,
                        (false, false) => unreachable_nodes += 1,
                    }
                }

                // display server metrics
                let metrics = discv5.metrics();
                info!(
                    log, "Server metrics";
                    "connected_peers" => discv5.connected_peers(),
                    "active_sessions" => metrics.active_sessions,
                    "requests/s" => format_args!("{:.2}", metrics.unsolicited_requests_per_second),
                    "ipv4_nodes" => ipv4_only_reachable,
                    "ipv6_nodes" => ipv6_only_reachable,
                    "ipv6_and_ipv4_nodes" => ipv4_ipv6_reachable,
                    "unreachable_nodes" => unreachable_nodes,
                );

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
