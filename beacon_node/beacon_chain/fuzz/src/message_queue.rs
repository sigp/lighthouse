use types::{Attestation, EthSpec, Hash256, SignedBeaconBlock};

#[derive(Debug, Clone)]
#[must_use]
pub enum Message<E: EthSpec> {
    Attestation(Attestation<E>),
    Block(SignedBeaconBlock<E>),
}

impl<E: EthSpec> Message<E> {
    pub fn block_root(&self) -> Hash256 {
        match self {
            Self::Attestation(att) => att.data.beacon_block_root,
            Self::Block(block) => block.canonical_root(),
        }
    }

    /// The root of a block which must be processed before this message can be processed.
    pub fn dependent_block_root(&self) -> Hash256 {
        match self {
            Self::Attestation(att) => att.data.beacon_block_root,
            Self::Block(block) => block.parent_root(),
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self, Message::Block(_))
    }
}
