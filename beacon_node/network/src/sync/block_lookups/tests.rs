use std::sync::Arc;

use crate::NetworkMessage;

use super::*;

use beacon_chain::builder::Witness;
use beacon_chain::eth1_chain::CachingEth1Backend;
use lighthouse_network::NetworkGlobals;
use slog::{Drain, Level};
use slot_clock::SystemTimeSlotClock;
use store::MemoryStore;
use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use types::MinimalEthSpec as E;

type T = Witness<SystemTimeSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

struct TestRig {
    beacon_processor_rx: mpsc::Receiver<WorkEvent<T>>,
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    rng: XorShiftRng,
}

impl TestRig {
    fn test_setup(log_level: Option<Level>) -> (BlockLookups<T>, Self, SyncNetworkContext<E>) {
        let log = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();

            if let Some(log_level) = log_level {
                slog::Logger::root(drain.filter_level(log_level).fuse(), slog::o!())
            } else {
                slog::Logger::root(drain.filter(|_| false).fuse(), slog::o!())
            }
        };

        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(10);
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let rng = XorShiftRng::from_seed([42; 16]);
        let rig = TestRig {
            beacon_processor_rx,
            network_rx,
            rng,
        };
        let bl = BlockLookups::new(
            beacon_processor_tx,
            log.new(slog::o!("component" => "block_lookups")),
        );
        let cx = {
            let globals = Arc::new(NetworkGlobals::new_test_globals(&log));
            SyncNetworkContext::new(
                network_tx,
                globals.clone(),
                log.new(slog::o!("component" => "network_context")),
            )
        };

        (bl, rig, cx)
    }

    fn rand_block(&mut self) -> SignedBeaconBlock<E> {
        SignedBeaconBlock::from_block(
            types::BeaconBlock::Base(types::BeaconBlockBase {
                ..<_>::random_for_test(&mut self.rng)
            }),
            types::Signature::random_for_test(&mut self.rng),
        )
    }
}
