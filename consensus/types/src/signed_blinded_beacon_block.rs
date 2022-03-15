use crate::*;
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use superstruct::superstruct;

/// A `BlindedBeaconBlock` and a signature from its proposer.
#[superstruct(
    variants(Base, Altair, Merge),
    variant_attributes(
        derive(Debug, PartialEq, Clone, Serialize, Deserialize,),
        serde(bound = "E: EthSpec")
    )
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
pub struct SignedBlindedBeaconBlock<E: EthSpec> {
    #[superstruct(only(Base), partial_getter(rename = "message_base"))]
    pub message: BlindedBeaconBlockBase<E>,
    #[superstruct(only(Altair), partial_getter(rename = "message_altair"))]
    pub message: BlindedBeaconBlockAltair<E>,
    #[superstruct(only(Merge), partial_getter(rename = "message_merge"))]
    pub message: BlindedBeaconBlockMerge<E>,
    pub signature: Signature,
}

impl<E: EthSpec> From<SignedBeaconBlock<E, BlindedTransactions>> for SignedBlindedBeaconBlock<E> {
    fn from(block: SignedBeaconBlock<E, BlindedTransactions>) -> Self {
        match block {
            SignedBeaconBlock::Base(b) => {
                let SignedBeaconBlockBase { message, signature } = b;
                SignedBlindedBeaconBlock::Base(SignedBlindedBeaconBlockBase {
                    message: message.into(),
                    signature,
                })
            }
            SignedBeaconBlock::Altair(b) => {
                let SignedBeaconBlockAltair { message, signature } = b;
                SignedBlindedBeaconBlock::Altair(SignedBlindedBeaconBlockAltair {
                    message: message.into(),
                    signature,
                })
            }
            SignedBeaconBlock::Merge(b) => {
                let SignedBeaconBlockMerge { message, signature } = b;
                SignedBlindedBeaconBlock::Merge(SignedBlindedBeaconBlockMerge {
                    message: message.into(),
                    signature,
                })
            }
        }
    }
}
