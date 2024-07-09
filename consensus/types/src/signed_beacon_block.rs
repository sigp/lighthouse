use crate::beacon_block_body::format_kzg_commitments;
use crate::*;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::fmt;
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(arbitrary::Arbitrary, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SignedBeaconBlockHash(Hash256);

impl fmt::Debug for SignedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedBeaconBlockHash({:?})", self.0)
    }
}

impl fmt::Display for SignedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash256> for SignedBeaconBlockHash {
    fn from(hash: Hash256) -> SignedBeaconBlockHash {
        SignedBeaconBlockHash(hash)
    }
}

impl From<SignedBeaconBlockHash> for Hash256 {
    fn from(signed_beacon_block_hash: SignedBeaconBlockHash) -> Hash256 {
        signed_beacon_block_hash.0
    }
}

/// A `BeaconBlock` and a signature from its proposer.
#[superstruct(
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
        arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
    ),
    map_into(BeaconBlock),
    map_ref_into(BeaconBlockRef),
    map_ref_mut_into(BeaconBlockRefMut)
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct SignedBeaconBlock<E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    #[superstruct(only(Base), partial_getter(rename = "message_base"))]
    pub message: BeaconBlockBase<E, Payload>,
    #[superstruct(only(Altair), partial_getter(rename = "message_altair"))]
    pub message: BeaconBlockAltair<E, Payload>,
    #[superstruct(only(Bellatrix), partial_getter(rename = "message_bellatrix"))]
    pub message: BeaconBlockBellatrix<E, Payload>,
    #[superstruct(only(Capella), partial_getter(rename = "message_capella"))]
    pub message: BeaconBlockCapella<E, Payload>,
    #[superstruct(only(Deneb), partial_getter(rename = "message_deneb"))]
    pub message: BeaconBlockDeneb<E, Payload>,
    #[superstruct(only(Electra), partial_getter(rename = "message_electra"))]
    pub message: BeaconBlockElectra<E, Payload>,
    pub signature: Signature,
}

pub type SignedBlindedBeaconBlock<E> = SignedBeaconBlock<E, BlindedPayload<E>>;

impl<E: EthSpec, Payload: AbstractExecPayload<E>> SignedBeaconBlock<E, Payload> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        self.message().fork_name(spec)
    }

    /// Returns the name of the fork pertaining to `self`
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        self.message().fork_name_unchecked()
    }

    /// SSZ decode with fork variant determined by slot.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, |bytes| BeaconBlock::from_ssz_bytes(bytes, spec))
    }

    /// SSZ decode with explicit fork variant.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, |bytes| {
            BeaconBlock::from_ssz_bytes_for_fork(bytes, fork_name)
        })
    }

    /// SSZ decode which attempts to decode all variants (slow).
    pub fn any_from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, BeaconBlock::any_from_ssz_bytes)
    }

    /// SSZ decode with custom decode function.
    pub fn from_ssz_bytes_with(
        bytes: &[u8],
        block_decoder: impl FnOnce(&[u8]) -> Result<BeaconBlock<E, Payload>, ssz::DecodeError>,
    ) -> Result<Self, ssz::DecodeError> {
        // We need the customer decoder for `BeaconBlock`, which doesn't compose with the other
        // SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Signature>()?;

        let mut decoder = builder.build()?;

        // Read the first item as a `BeaconBlock`.
        let message = decoder.decode_next_with(block_decoder)?;
        let signature = decoder.decode_next()?;

        Ok(Self::from_block(message, signature))
    }

    /// Create a new `SignedBeaconBlock` from a `BeaconBlock` and `Signature`.
    pub fn from_block(block: BeaconBlock<E, Payload>, signature: Signature) -> Self {
        match block {
            BeaconBlock::Base(message) => {
                SignedBeaconBlock::Base(SignedBeaconBlockBase { message, signature })
            }
            BeaconBlock::Altair(message) => {
                SignedBeaconBlock::Altair(SignedBeaconBlockAltair { message, signature })
            }
            BeaconBlock::Bellatrix(message) => {
                SignedBeaconBlock::Bellatrix(SignedBeaconBlockBellatrix { message, signature })
            }
            BeaconBlock::Capella(message) => {
                SignedBeaconBlock::Capella(SignedBeaconBlockCapella { message, signature })
            }
            BeaconBlock::Deneb(message) => {
                SignedBeaconBlock::Deneb(SignedBeaconBlockDeneb { message, signature })
            }
            BeaconBlock::Electra(message) => {
                SignedBeaconBlock::Electra(SignedBeaconBlockElectra { message, signature })
            }
        }
    }

    /// Deconstruct the `SignedBeaconBlock` into a `BeaconBlock` and `Signature`.
    ///
    /// This is necessary to get a `&BeaconBlock` from a `SignedBeaconBlock` because
    /// `SignedBeaconBlock` only contains a `BeaconBlock` _variant_.
    pub fn deconstruct(self) -> (BeaconBlock<E, Payload>, Signature) {
        map_signed_beacon_block_into_beacon_block!(self, |block, beacon_block_cons| {
            (beacon_block_cons(block.message), block.signature)
        })
    }

    /// Accessor for the block's `message` field as a ref.
    pub fn message<'a>(&'a self) -> BeaconBlockRef<'a, E, Payload> {
        map_signed_beacon_block_ref_into_beacon_block_ref!(
            &'a _,
            self.to_ref(),
            |inner, cons| cons(&inner.message)
        )
    }

    /// Accessor for the block's `message` as a mutable reference (for testing only).
    pub fn message_mut<'a>(&'a mut self) -> BeaconBlockRefMut<'a, E, Payload> {
        map_signed_beacon_block_ref_mut_into_beacon_block_ref_mut!(
            &'a _,
            self.to_mut(),
            |inner, cons| cons(&mut inner.message)
        )
    }

    /// Verify `self.signature`.
    ///
    /// If the root of `block.message` is already known it can be passed in via `object_root_opt`.
    /// Otherwise, it will be computed locally.
    pub fn verify_signature(
        &self,
        object_root_opt: Option<Hash256>,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        // Refuse to verify the signature of a block if its structure does not match the fork at
        // `self.slot()`.
        if self.fork_name(spec).is_err() {
            return false;
        }

        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconProposer,
            fork,
            genesis_validators_root,
        );

        let message = if let Some(object_root) = object_root_opt {
            SigningData {
                object_root,
                domain,
            }
            .tree_hash_root()
        } else {
            self.message().signing_root(domain)
        };

        self.signature().verify(pubkey, message)
    }

    /// Produce a signed beacon block header corresponding to this block.
    pub fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: self.message().block_header(),
            signature: self.signature().clone(),
        }
    }

    /// Convenience accessor for the block's slot.
    pub fn slot(&self) -> Slot {
        self.message().slot()
    }

    /// Convenience accessor for the block's epoch.
    pub fn epoch(&self) -> Epoch {
        self.message().slot().epoch(E::slots_per_epoch())
    }

    /// Convenience accessor for the block's parent root.
    pub fn parent_root(&self) -> Hash256 {
        self.message().parent_root()
    }

    /// Convenience accessor for the block's state root.
    pub fn state_root(&self) -> Hash256 {
        self.message().state_root()
    }

    /// Returns the `tree_hash_root` of the block.
    pub fn canonical_root(&self) -> Hash256 {
        self.message().tree_hash_root()
    }

    pub fn num_expected_blobs(&self) -> usize {
        self.message()
            .body()
            .blob_kzg_commitments()
            .map(|c| c.len())
            .unwrap_or(0)
    }

    /// Used for displaying commitments in logs.
    pub fn commitments_formatted(&self) -> String {
        let Ok(commitments) = self.message().body().blob_kzg_commitments() else {
            return "[]".to_string();
        };

        format_kzg_commitments(commitments.as_ref())
    }
}

// We can convert pre-Bellatrix blocks without payloads into blocks with payloads.
impl<E: EthSpec> From<SignedBeaconBlockBase<E, BlindedPayload<E>>>
    for SignedBeaconBlockBase<E, FullPayload<E>>
{
    fn from(signed_block: SignedBeaconBlockBase<E, BlindedPayload<E>>) -> Self {
        let SignedBeaconBlockBase { message, signature } = signed_block;
        SignedBeaconBlockBase {
            message: message.into(),
            signature,
        }
    }
}

impl<E: EthSpec> From<SignedBeaconBlockAltair<E, BlindedPayload<E>>>
    for SignedBeaconBlockAltair<E, FullPayload<E>>
{
    fn from(signed_block: SignedBeaconBlockAltair<E, BlindedPayload<E>>) -> Self {
        let SignedBeaconBlockAltair { message, signature } = signed_block;
        SignedBeaconBlockAltair {
            message: message.into(),
            signature,
        }
    }
}

// Post-Bellatrix blocks can be "unblinded" by adding the full payload.
// NOTE: It might be nice to come up with a `superstruct` pattern to abstract over this before
// the first fork after Bellatrix.
impl<E: EthSpec> SignedBeaconBlockBellatrix<E, BlindedPayload<E>> {
    pub fn into_full_block(
        self,
        execution_payload: ExecutionPayloadBellatrix<E>,
    ) -> SignedBeaconBlockBellatrix<E, FullPayload<E>> {
        let SignedBeaconBlockBellatrix {
            message:
                BeaconBlockBellatrix {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body:
                        BeaconBlockBodyBellatrix {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload: BlindedPayloadBellatrix { .. },
                        },
                },
            signature,
        } = self;
        SignedBeaconBlockBellatrix {
            message: BeaconBlockBellatrix {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BeaconBlockBodyBellatrix {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: FullPayloadBellatrix { execution_payload },
                },
            },
            signature,
        }
    }
}

impl<E: EthSpec> SignedBeaconBlockCapella<E, BlindedPayload<E>> {
    pub fn into_full_block(
        self,
        execution_payload: ExecutionPayloadCapella<E>,
    ) -> SignedBeaconBlockCapella<E, FullPayload<E>> {
        let SignedBeaconBlockCapella {
            message:
                BeaconBlockCapella {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body:
                        BeaconBlockBodyCapella {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload: BlindedPayloadCapella { .. },
                            bls_to_execution_changes,
                        },
                },
            signature,
        } = self;
        SignedBeaconBlockCapella {
            message: BeaconBlockCapella {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BeaconBlockBodyCapella {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: FullPayloadCapella { execution_payload },
                    bls_to_execution_changes,
                },
            },
            signature,
        }
    }
}

impl<E: EthSpec> SignedBeaconBlockDeneb<E, BlindedPayload<E>> {
    pub fn into_full_block(
        self,
        execution_payload: ExecutionPayloadDeneb<E>,
    ) -> SignedBeaconBlockDeneb<E, FullPayload<E>> {
        let SignedBeaconBlockDeneb {
            message:
                BeaconBlockDeneb {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body:
                        BeaconBlockBodyDeneb {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload: BlindedPayloadDeneb { .. },
                            bls_to_execution_changes,
                            blob_kzg_commitments,
                        },
                },
            signature,
        } = self;
        SignedBeaconBlockDeneb {
            message: BeaconBlockDeneb {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BeaconBlockBodyDeneb {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: FullPayloadDeneb { execution_payload },
                    bls_to_execution_changes,
                    blob_kzg_commitments,
                },
            },
            signature,
        }
    }
}

impl<E: EthSpec> SignedBeaconBlockElectra<E, BlindedPayload<E>> {
    pub fn into_full_block(
        self,
        execution_payload: ExecutionPayloadElectra<E>,
    ) -> SignedBeaconBlockElectra<E, FullPayload<E>> {
        let SignedBeaconBlockElectra {
            message:
                BeaconBlockElectra {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body:
                        BeaconBlockBodyElectra {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload: BlindedPayloadElectra { .. },
                            bls_to_execution_changes,
                            blob_kzg_commitments,
                            consolidations,
                        },
                },
            signature,
        } = self;
        SignedBeaconBlockElectra {
            message: BeaconBlockElectra {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BeaconBlockBodyElectra {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: FullPayloadElectra { execution_payload },
                    bls_to_execution_changes,
                    blob_kzg_commitments,
                    consolidations,
                },
            },
            signature,
        }
    }
}

impl<E: EthSpec> SignedBeaconBlock<E, BlindedPayload<E>> {
    pub fn try_into_full_block(
        self,
        execution_payload: Option<ExecutionPayload<E>>,
    ) -> Option<SignedBeaconBlock<E, FullPayload<E>>> {
        let full_block = match (self, execution_payload) {
            (SignedBeaconBlock::Base(block), _) => SignedBeaconBlock::Base(block.into()),
            (SignedBeaconBlock::Altair(block), _) => SignedBeaconBlock::Altair(block.into()),
            (SignedBeaconBlock::Bellatrix(block), Some(ExecutionPayload::Bellatrix(payload))) => {
                SignedBeaconBlock::Bellatrix(block.into_full_block(payload))
            }
            (SignedBeaconBlock::Capella(block), Some(ExecutionPayload::Capella(payload))) => {
                SignedBeaconBlock::Capella(block.into_full_block(payload))
            }
            (SignedBeaconBlock::Deneb(block), Some(ExecutionPayload::Deneb(payload))) => {
                SignedBeaconBlock::Deneb(block.into_full_block(payload))
            }
            (SignedBeaconBlock::Electra(block), Some(ExecutionPayload::Electra(payload))) => {
                SignedBeaconBlock::Electra(block.into_full_block(payload))
            }
            // avoid wildcard matching forks so that compiler will
            // direct us here when a new fork has been added
            (SignedBeaconBlock::Bellatrix(_), _) => return None,
            (SignedBeaconBlock::Capella(_), _) => return None,
            (SignedBeaconBlock::Deneb(_), _) => return None,
            (SignedBeaconBlock::Electra(_), _) => return None,
        };
        Some(full_block)
    }
}

// We can blind blocks with payloads by converting the payload into a header.
//
// We can optionally keep the header, or discard it.
impl<E: EthSpec> From<SignedBeaconBlock<E>>
    for (SignedBlindedBeaconBlock<E>, Option<ExecutionPayload<E>>)
{
    fn from(signed_block: SignedBeaconBlock<E>) -> Self {
        let (block, signature) = signed_block.deconstruct();
        let (blinded_block, payload) = block.into();
        (
            SignedBeaconBlock::from_block(blinded_block, signature),
            payload,
        )
    }
}

impl<E: EthSpec> From<SignedBeaconBlock<E>> for SignedBlindedBeaconBlock<E> {
    fn from(signed_block: SignedBeaconBlock<E>) -> Self {
        let (blinded_block, _) = signed_block.into();
        blinded_block
    }
}

// We can blind borrowed blocks with payloads by converting the payload into a header (without
// cloning the payload contents).
impl<E: EthSpec> SignedBeaconBlock<E> {
    pub fn clone_as_blinded(&self) -> SignedBlindedBeaconBlock<E> {
        SignedBeaconBlock::from_block(self.message().into(), self.signature().clone())
    }
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> ForkVersionDeserialize
    for SignedBeaconBlock<E, Payload>
{
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        Ok(map_fork_name!(
            fork_name,
            Self,
            serde_json::from_value(value).map_err(|e| serde::de::Error::custom(format!(
                "SignedBeaconBlock failed to deserialize: {:?}",
                e
            )))?
        ))
    }
}

/// This module can be used to encode and decode a `SignedBeaconBlock` the same way it
/// would be done if we had tagged the superstruct enum with
/// `#[ssz(enum_behaviour = "union")]`
/// This should _only_ be used *some* cases when storing these objects in the database
/// and _NEVER_ for encoding / decoding blocks sent over the network!
pub mod ssz_tagged_signed_beacon_block {
    use super::*;
    pub mod encode {
        use super::*;
        #[allow(unused_imports)]
        use ssz::*;

        pub fn is_ssz_fixed_len() -> bool {
            false
        }

        pub fn ssz_fixed_len() -> usize {
            BYTES_PER_LENGTH_OFFSET
        }

        pub fn ssz_bytes_len<E: EthSpec, Payload: AbstractExecPayload<E>>(
            block: &SignedBeaconBlock<E, Payload>,
        ) -> usize {
            block
                .ssz_bytes_len()
                .checked_add(1)
                .expect("encoded length must be less than usize::max")
        }

        pub fn ssz_append<E: EthSpec, Payload: AbstractExecPayload<E>>(
            block: &SignedBeaconBlock<E, Payload>,
            buf: &mut Vec<u8>,
        ) {
            let fork_name = block.fork_name_unchecked();
            fork_name.ssz_append(buf);
            block.ssz_append(buf);
        }

        pub fn as_ssz_bytes<E: EthSpec, Payload: AbstractExecPayload<E>>(
            block: &SignedBeaconBlock<E, Payload>,
        ) -> Vec<u8> {
            let mut buf = vec![];
            ssz_append(block, &mut buf);

            buf
        }
    }

    pub mod decode {
        use super::*;
        #[allow(unused_imports)]
        use ssz::*;

        pub fn is_ssz_fixed_len() -> bool {
            false
        }

        pub fn ssz_fixed_len() -> usize {
            BYTES_PER_LENGTH_OFFSET
        }

        pub fn from_ssz_bytes<E: EthSpec, Payload: AbstractExecPayload<E>>(
            bytes: &[u8],
        ) -> Result<SignedBeaconBlock<E, Payload>, DecodeError> {
            let fork_byte = bytes
                .first()
                .copied()
                .ok_or(DecodeError::OutOfBoundsByte { i: 0 })?;
            let body = bytes
                .get(1..)
                .ok_or(DecodeError::OutOfBoundsByte { i: 1 })?;

            match ForkName::from_ssz_bytes(&[fork_byte])? {
                ForkName::Base => Ok(SignedBeaconBlock::Base(
                    SignedBeaconBlockBase::from_ssz_bytes(body)?,
                )),
                ForkName::Altair => Ok(SignedBeaconBlock::Altair(
                    SignedBeaconBlockAltair::from_ssz_bytes(body)?,
                )),
                ForkName::Bellatrix => Ok(SignedBeaconBlock::Bellatrix(
                    SignedBeaconBlockBellatrix::from_ssz_bytes(body)?,
                )),
                ForkName::Capella => Ok(SignedBeaconBlock::Capella(
                    SignedBeaconBlockCapella::from_ssz_bytes(body)?,
                )),
                ForkName::Deneb => Ok(SignedBeaconBlock::Deneb(
                    SignedBeaconBlockDeneb::from_ssz_bytes(body)?,
                )),
                ForkName::Electra => Ok(SignedBeaconBlock::Electra(
                    SignedBeaconBlockElectra::from_ssz_bytes(body)?,
                )),
            }
        }
    }
}

pub mod ssz_tagged_signed_beacon_block_arc {
    use super::*;
    pub mod encode {
        pub use super::ssz_tagged_signed_beacon_block::encode::*;
    }

    pub mod decode {
        pub use super::ssz_tagged_signed_beacon_block::decode::{is_ssz_fixed_len, ssz_fixed_len};
        use super::*;
        #[allow(unused_imports)]
        use ssz::*;
        use std::sync::Arc;

        pub fn from_ssz_bytes<E: EthSpec, Payload: AbstractExecPayload<E>>(
            bytes: &[u8],
        ) -> Result<Arc<SignedBeaconBlock<E, Payload>>, DecodeError> {
            ssz_tagged_signed_beacon_block::decode::from_ssz_bytes(bytes).map(Arc::new)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn add_remove_payload_roundtrip() {
        type E = MainnetEthSpec;

        let spec = &E::default_spec();
        let sig = Signature::empty();
        let blocks = vec![
            SignedBeaconBlock::<E>::from_block(
                BeaconBlock::Base(BeaconBlockBase::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Altair(BeaconBlockAltair::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Bellatrix(BeaconBlockBellatrix::empty(spec)),
                sig,
            ),
        ];

        for block in blocks {
            let (blinded_block, payload): (SignedBlindedBeaconBlock<E>, _) = block.clone().into();
            assert_eq!(blinded_block.tree_hash_root(), block.tree_hash_root());

            if let Some(payload) = &payload {
                assert_eq!(
                    payload.tree_hash_root(),
                    block
                        .message()
                        .execution_payload()
                        .unwrap()
                        .tree_hash_root()
                );
            }

            let reconstructed = blinded_block.try_into_full_block(payload).unwrap();
            assert_eq!(reconstructed, block);
        }
    }

    #[test]
    fn test_ssz_tagged_signed_beacon_block() {
        type E = MainnetEthSpec;

        let spec = &E::default_spec();
        let sig = Signature::empty();
        let blocks = vec![
            SignedBeaconBlock::<E>::from_block(
                BeaconBlock::Base(BeaconBlockBase::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Altair(BeaconBlockAltair::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Bellatrix(BeaconBlockBellatrix::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Capella(BeaconBlockCapella::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Deneb(BeaconBlockDeneb::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Electra(BeaconBlockElectra::empty(spec)),
                sig,
            ),
        ];

        for block in blocks {
            let encoded = ssz_tagged_signed_beacon_block::encode::as_ssz_bytes(&block);
            let decoded = ssz_tagged_signed_beacon_block::decode::from_ssz_bytes::<E, _>(&encoded)
                .expect("should decode");
            assert_eq!(decoded, block);
        }
    }
}
