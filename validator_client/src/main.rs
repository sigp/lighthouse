mod block_producer;

use spec::ChainSpec;
use tokio::prelude::*;
use tokio::timer::Interval;

use crate::block_producer::{BlockProducer, PollOutcome as BlockProducerPollOutcome};

use std::time::{Duration, Instant};

use std::sync::{Arc, RwLock};

use std::collections::HashMap;

use slot_clock::SystemTimeSlotClock;

use grpcio::{ChannelBuilder, EnvBuilder};
use protos::services_grpc::BeaconBlockServiceClient;

use slog::{error, info, o, warn, Drain};

fn main() {
    // gRPC
    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect("localhost:50051");
    let client = BeaconBlockServiceClient::new(ch);

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

    let mut block_producer =
        BlockProducer::new(spec.clone(), epoch_map.clone(), slot_clock.clone(), client);

    info!(log, "Slot duration"; "milliseconds" => duration);

    let task = Interval::new(Instant::now(), Duration::from_millis(duration))
        // .take(10)
        .for_each(move |_instant| {
            match block_producer.poll() {
                Err(error) => {
                    error!(log, "Block producer poll error"; "error" => format!("{:?}", error))
                }
                Ok(BlockProducerPollOutcome::BlockProduced) => info!(log, "Produced block"),
                Ok(BlockProducerPollOutcome::SlashableBlockNotProduced) => {
                    warn!(log, "Slashable block was not signed")
                }
                Ok(BlockProducerPollOutcome::BlockProductionNotRequired) => {
                    info!(log, "Block production not required")
                }
                Ok(BlockProducerPollOutcome::ProducerDutiesUnknown) => {
                    error!(log, "Block production duties unknown")
                }
                Ok(BlockProducerPollOutcome::SlotAlreadyProcessed) => {
                    warn!(log, "Attempted to re-process slot")
                }
                Ok(BlockProducerPollOutcome::BeaconNodeUnableToProduceBlock) => {
                    error!(log, "Beacon node unable to produce block")
                }
            };
            Ok(())
        })
        .map_err(|e| panic!("Block producer interval errored; err={:?}", e));

    tokio::run(task);
}

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
