mod beacon_block_grpc_client;
// mod block_producer_service;

use block_proposer::{
    BeaconNode, BlockProducer, DutiesReader, PollOutcome as BlockProducerPollOutcome, Signer,
};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use std::time::Duration;

pub use self::beacon_block_grpc_client::BeaconBlockGrpcClient;

pub struct BlockProducerService<U: BeaconNode, W: Signer> {
    pub block_producer: BlockProducer<U, W>,
    pub poll_interval_millis: u64,
    pub log: Logger,
}

impl<U: BeaconNode, W: Signer> BlockProducerService<U, W> {
    /// Run a loop which polls the block producer each `poll_interval_millis` millseconds.
    ///
    /// Logs the results of the polls.
    pub fn run(&mut self) {
        loop {
            /* Don't do polling any more
            match self.block_producer.poll() {
                Err(error) => {
                    error!(self.log, "Block producer poll error"; "error" => format!("{:?}", error))
                }
                Ok(BlockProducerPollOutcome::BlockProduced(slot)) => {
                    info!(self.log, "Produced block"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::SlashableBlockNotProduced(slot)) => {
                    warn!(self.log, "Slashable block was not signed"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::BlockProductionNotRequired(slot)) => {
                    info!(self.log, "Block production not required"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::ProducerDutiesUnknown(slot)) => {
                    error!(self.log, "Block production duties unknown"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::SlotAlreadyProcessed(slot)) => {
                    warn!(self.log, "Attempted to re-process slot"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::BeaconNodeUnableToProduceBlock(slot)) => {
                    error!(self.log, "Beacon node unable to produce block"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::SignerRejection(slot)) => {
                    error!(self.log, "The cryptographic signer refused to sign the block"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::ValidatorIsUnknown(slot)) => {
                    error!(self.log, "The Beacon Node does not recognise the validator"; "slot" => slot)
                }
                Ok(BlockProducerPollOutcome::UnableToGetFork(slot)) => {
                    error!(self.log, "Unable to get a `Fork` struct to generate signature domains"; "slot" => slot)
                }
            };
            */

            println!("Legacy polling still happening...");
            std::thread::sleep(Duration::from_millis(self.poll_interval_millis));
        }
    }
}
