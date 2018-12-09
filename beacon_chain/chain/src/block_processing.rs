use super::BeaconChain;
use db::ClientDB;
use types::Hash256;

pub enum BlockProcessingOutcome {
    BlockAlreadyKnown,
    NewCanonicalBlock,
    NewReorgBlock,
    NewForkBlock,
}

pub enum Error {
    NotImplemented,
}

impl<T> BeaconChain<T>
where
    T: ClientDB + Sized,
{
    pub fn process_block(
        &mut self,
        ssz: &[u8],
        present_slot: u64,
    ) -> Result<(BlockProcessingOutcome, Hash256), Error> {
        // TODO: block processing has been removed.
        // https://github.com/sigp/lighthouse/issues/98
        Err(Error::NotImplemented)
    }
}
