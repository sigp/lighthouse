use crate::{
    AbstractExecPayload, BlindedBlobSidecar, BlindedPayload, BlobSidecar, BlockType, EthSpec,
    FullPayload, Sidecar,
};
use std::fmt::Debug;

pub trait BlockProposal<T: EthSpec>: Send + Sized + Clone + Debug {
    type Payload: AbstractExecPayload<T>;
    type Sidecar: Sidecar<T>;
    fn block_type() -> BlockType;
}

#[derive(Clone, Debug)]
pub struct FullBlockProposal {}
impl<T: EthSpec> BlockProposal<T> for FullBlockProposal {
    type Payload = FullPayload<T>;
    type Sidecar = BlobSidecar<T>;

    fn block_type() -> BlockType {
        BlockType::Full
    }
}

#[derive(Clone, Debug)]
pub struct BlindedBlockProposal {}
impl<T: EthSpec> BlockProposal<T> for BlindedBlockProposal {
    type Payload = BlindedPayload<T>;
    type Sidecar = BlindedBlobSidecar;

    fn block_type() -> BlockType {
        BlockType::Blinded
    }
}
