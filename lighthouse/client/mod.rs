use std::sync::{ Arc, RwLock };
use std::thread;
use super::db::{ DB, open_db };
use super::config::LighthouseConfig;
use super::futures::sync::mpsc::{
    unbounded,
};
use super::network_libp2p::service::listen as network_listen;
use super::network_libp2p::state::NetworkState;
use super::slog::Logger;
use super::sync::start_sync;

pub struct Client {
    pub db: Arc<RwLock<DB>>,
    pub threads: Vec<thread::JoinHandle<()>>
}

impl Client {
    pub fn new(config: LighthouseConfig,
               log: Logger)
        -> Self
    {
        // Open the local db
        let db = {
            let db = open_db(&config.data_dir);
            Arc::new(RwLock::new(db))
        };

        // Start the network thread
        let network_state = NetworkState::new(
            &config.data_dir,
            &config.p2p_listen_port,
            &log).expect("Network setup failed");
        let (network_thread, network_tx, network_rx) = {
            let (message_sender, message_receiver) = unbounded();
            let (event_sender, event_receiver) = unbounded();
            let network_log = log.new(o!());
            let thread = thread::spawn(move || {
                network_listen(
                    network_state,
                    event_sender,
                    message_receiver,
                    network_log,
                );
            });
            (thread, message_sender, event_receiver)
        };

        // Start the sync thread
        let (sync_thread, _sync_tx, _sync_rx) = {
            let (sync_out_sender, sync_out_receiver) = unbounded();
            let (sync_in_sender, sync_in_receiver) = unbounded();
            let sync_log = log.new(o!());
            let sync_db = Arc::clone(&db);
            let thread = thread::spawn(move || {
                start_sync(
                    sync_db,
                    network_tx.clone(),
                    network_rx,
                    sync_out_sender,
                    sync_in_receiver,
                    sync_log,
                );
            });
            (thread, sync_in_sender, sync_out_receiver)
        };

        // Return the client struct
        Self {
            db: db,
            threads: vec![sync_thread, network_thread]
        }
    }
}
