use crate::{
    AbstractExecPayload, BlindedBlobSidecar, BlindedPayload, BlobSidecar, EthSpec, FullPayload,
    Sidecar,
};

pub trait BlockProposal<T: EthSpec>: Send {
    type Payload: AbstractExecPayload<T>;
    type Sidecar: Sidecar<T>;
}

pub struct FullBlockProposal {}
impl<T: EthSpec> BlockProposal<T> for FullBlockProposal {
    type Payload = FullPayload<T>;
    type Sidecar = BlobSidecar<T>;
}

pub struct BlindedBlockProposal {}
impl<T: EthSpec> BlockProposal<T> for BlindedBlockProposal {
    type Payload = BlindedPayload<T>;
    type Sidecar = BlindedBlobSidecar;
}
