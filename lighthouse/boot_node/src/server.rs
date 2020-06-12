//! The main bootnode server execution.

use super::BootNodeConfig;
use eth2_libp2p::EnrExt;
use discv5::{Discv5Event, Discv5,Discv5ConfigBuilder};
use slog::info;

pub async fn run(config: BootNodeConfig, log: slog::Logger) {

    // Print out useful information about the generated ENR
    
    let enr_socket = config.local_enr.udp_socket().expect("Enr has a UDP socket");
    info!(log, "Configuration parameters"; "listening_address" => format!("{}:{}", config.listen_socket.ip(), config.listen_socket.port()), "broadcast_address" => format!("{}:{}",enr_socket.ip(), enr_socket.port())); 

    info!(log, "Identity established"; "peer_id" => config.local_enr.peer_id().to_string(), "node_id" => config.local_enr.node_id().to_string());
    
    // build the contactable multiaddr list, adding the p2p protocol
    info!(log, "Contact information"; "multiaddrs" => format!("{:?}", config.local_enr.multiaddr_p2p()), "enr" => config.local_enr.to_base64()); 

    // Build the discv5 server

    // default configuration with packet filtering

    let discv5_config = { 
        let mut builder = Discv5ConfigBuilder::new();
        builder.enable_packet_filter();
        if !config.auto_update {
            builder.disable_enr_update();
        }
        builder.build()
    };

    // construct the discv5 server
    let mut discv5 = Discv5::new(config.local_enr, config.local_key, discv5_config).unwrap();

    // If there are any bootnodes add them to the routing table
    for enr in config.boot_nodes {
        info!(log, "Adding bootnode"; "address" => format!("{:?}", enr.udp_socket()), "peer_id" => enr.peer_id().to_string(), "node_id" => enr.node_id().to_string());
        if let Err(e) = discv5.add_enr(enr) {
            slog::warn!(log, "Failed adding ENR"; "error" => e.to_string());
        }
    }

    // start the server
    discv5.start(config.listen_socket);

    // get an event stream
    let mut event_stream = match discv5.event_stream().await {
        Ok(stream) => stream, 
        Err(e) => {
            slog::crit!(log, "Failed to obtain event stream"; "error" => e);
            return;
        }
    };

    // listen for events
    while let Some(event) = event_stream.recv().await {
        match event {
            Discv5Event::Discovered(_enr) => {
                // An ENR has bee obtained by the server
                // Ignore these events here
            },
            Discv5Event::EnrAdded { .. } => {} // Ignore
            Discv5Event::NodeInserted {.. } => {} // Ignore
            Discv5Event::SocketUpdated(socket_addr) => {
                info!(log, "External socket address updated"; "socket_addr" => format!("{:?}", socket_addr));
            }
        }
    }
}

