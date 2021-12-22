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
                let BeaconBlockBase {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = message;
                let BeaconBlockBodyBase {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    _phantom,
                } = body;
                SignedBlindedBeaconBlock::Base(SignedBlindedBeaconBlockBase {
                    message: BlindedBeaconBlockBase {
                        slot,
                        proposer_index,
                        parent_root,
                        state_root,
                        body: BlindedBeaconBlockBodyBase {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                        },
                    },
                    signature,
                })
            }
            SignedBeaconBlock::Altair(b) => {
                let SignedBeaconBlockAltair { message, signature } = b;
                let BeaconBlockAltair {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = message;
                let BeaconBlockBodyAltair {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    _phantom,
                } = body;
                SignedBlindedBeaconBlock::Altair(SignedBlindedBeaconBlockAltair {
                    message: BlindedBeaconBlockAltair {
                        slot,
                        proposer_index,
                        parent_root,
                        state_root,
                        body: BlindedBeaconBlockBodyAltair {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                        },
                    },
                    signature,
                })
            }
            SignedBeaconBlock::Merge(b) => {
                let SignedBeaconBlockMerge { message, signature } = b;
                let BeaconBlockMerge {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = message;
                let BeaconBlockBodyMerge {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload,
                } = body;
                SignedBlindedBeaconBlock::Merge(SignedBlindedBeaconBlockMerge {
                    message: BlindedBeaconBlockMerge {
                        slot,
                        proposer_index,
                        parent_root,
                        state_root,
                        body: BlindedBeaconBlockBodyMerge {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload_header: execution_payload.into(),
                        },
                    },
                    signature,
                })
            }
        }
    }
}
