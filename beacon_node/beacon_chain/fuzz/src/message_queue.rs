use types::{Attestation, EthSpec, Hash256, SignedBeaconBlock};

#[derive(Debug, Clone)]
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

    pub fn is_block(&self) -> bool {
        matches!(self, Message::Block(_))
    }
}
