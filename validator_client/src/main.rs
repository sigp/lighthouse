use crate::block_producer::{BlockProducer, BlockProducerService};
use grpcio::{ChannelBuilder, EnvBuilder};
use protos::services_grpc::BeaconBlockServiceClient;
use slog::{info, o, Drain};
use slot_clock::SystemTimeSlotClock;
use spec::ChainSpec;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

mod block_producer;

fn main() {
    // gRPC
    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect("localhost:50051");
    let client = Arc::new(BeaconBlockServiceClient::new(ch));

    // Logging
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    // Ethereum
    let spec = Arc::new(ChainSpec::foundation());

    let duration = spec
        .slot_duration
        .checked_mul(1_000)
        .expect("Slot duration overflow when converting from seconds to millis.");

    let epoch_map = Arc::new(RwLock::new(HashMap::new()));
    let slot_clock = {
        info!(log, "Genesis time"; "unix_epoch_seconds" => spec.genesis_time);
        let clock = SystemTimeSlotClock::new(spec.genesis_time, spec.slot_duration)
            .expect("Unable to instantiate SystemTimeSlotClock.");
        Arc::new(RwLock::new(clock))
    };

    let block_producer =
        BlockProducer::new(spec.clone(), epoch_map.clone(), slot_clock.clone(), client);

    info!(log, "Slot duration"; "milliseconds" => duration);

    let mut block_producer_service = BlockProducerService {
        block_producer,
        poll_interval_millis: spec.epoch_length * 1000 / 100, // 1% epoch time precision.
        log: log.clone(),
    };

    block_producer_service.run();
}

#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub struct EpochDuties {
    block_production_slot: Option<u64>,
    shard: Option<u64>,
}

impl EpochDuties {
    pub fn is_block_production_slot(&self, slot: u64) -> bool {
        match self.block_production_slot {
            Some(s) if s == slot => true,
            _ => false,
        }
    }

    pub fn has_shard(&self) -> bool {
        self.shard.is_some()
    }
}
