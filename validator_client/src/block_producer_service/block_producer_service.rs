use block_proposer::{
    BeaconNode, BlockProposer, DutiesReader, PollOutcome as BlockProposerPollOutcome, Signer,
};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use std::time::Duration;

pub struct BlockProposerService<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> {
    pub block_proposer: BlockProposer<T, U, V, W>,
    pub poll_interval_millis: u64,
    pub log: Logger,
}

impl<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> BlockProposerService<T, U, V, W> {
    /// Run a loop which polls the block proposer each `poll_interval_millis` millseconds.
    ///
    /// Logs the results of the polls.
    pub fn run(&mut self) {
        loop {
            match self.block_proposer.poll() {
                Err(error) => {
                    error!(self.log, "Block proposer poll error"; "error" => format!("{:?}", error))
                }
                Ok(BlockProposerPollOutcome::BlockProposed(slot)) => {
                    info!(self.log, "Proposed block"; "slot" => slot)
                }
                Ok(BlockProposerPollOutcome::SlashableBlockNotProposed(slot)) => {
                    warn!(self.log, "Slashable block was not signed"; "slot" => slot)
                }
                Ok(BlockProposerPollOutcome::BlockProductionNotRequired(slot)) => {
                    info!(self.log, "Block production not required"; "slot" => slot)
                }
                Ok(BlockProposerPollOutcome::ProposerDutiesUnknown(slot)) => {
                    error!(self.log, "Block production duties unknown"; "slot" => slot)
                }
                Ok(BlockProposerPollOutcome::SlotAlreadyProcessed(slot)) => {
                    warn!(self.log, "Attempted to re-process slot"; "slot" => slot)
                }
                Ok(BlockProposerPollOutcome::BeaconNodeUnableToProposeBlock(slot)) => {
                    error!(self.log, "Beacon node unable to propose block"; "slot" => slot)
                }
                Ok(BlockProposerPollOutcome::SignerRejection(slot)) => {
                    error!(self.log, "The cryptographic signer refused to sign the block"; "slot" => slot)
                }
                Ok(BlockProposerPollOutcome::ValidatorIsUnknown(slot)) => {
                    error!(self.log, "The Beacon Node does not recognise the validator"; "slot" => slot)
                }
            };

            std::thread::sleep(Duration::from_millis(self.poll_interval_millis));
        }
    }
}
