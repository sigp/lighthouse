#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;
extern crate clap;
extern crate libp2p_peerstore;

pub mod p2p;
pub mod pubkeystore;
pub mod state;
pub mod utils;

use p2p::keys;
use p2p::floodsub;
use slog::Drain;
use clap::{ App, SubCommand};
use std::sync::Arc;
use std::time::Duration;
use libp2p_peerstore::{ PeerAccess, Peerstore };
use libp2p_peerstore::memory_peerstore::MemoryPeerstore;

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    let matches = App::new("Lighthouse")
        .version("0.0.1")
        .author("Paul H. <paul@sigmaprime.io>")
        .about("Eth 2.0 Client")
        .subcommand(SubCommand::with_name("generate-keys"))
            .about("Generates a new set of random keys for p2p dev.")
        .get_matches();

    if let Some(_) = matches.subcommand_matches("generate-keys") {
        keys::generate_keys(&log).expect("Failed to generate keys");
    } else {
        let (s256k1_public, _s256k1_secret) = keys::load_local_keys(&log);
        let peer_id = keys::peer_id_from_pub_key(&s256k1_public);
        let bootstrap_peer_id = 
            keys::peer_id_from_pub_key(&keys::load_bootstrap_pk(&log));
        
       let peer_store = Arc::new(MemoryPeerstore::empty());

       peer_store.peer_or_create(&bootstrap_peer_id).add_addr(
           "/ip4/127.0.0.1/tcp/10101/ws".parse().unwrap(),
           Duration::from_secs(3600 * 24 * 356)
        );
        
        floodsub::listen(peer_id, peer_store, &log);
    }
    info!(log, "Exiting.");
}
