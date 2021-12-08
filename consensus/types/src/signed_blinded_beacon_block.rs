use crate::blinded_beacon_block::BlindedBeaconBlock;
use crate::*;
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::fmt;
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct SignedBlindedBeaconBlockHash(Hash256);

impl fmt::Debug for SignedBlindedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedBlindedBeaconBlockHash({:?})", self.0)
    }
}

impl fmt::Display for SignedBlindedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash256> for SignedBlindedBeaconBlockHash {
    fn from(hash: Hash256) -> SignedBlindedBeaconBlockHash {
        SignedBlindedBeaconBlockHash(hash)
    }
}

impl From<SignedBlindedBeaconBlockHash> for Hash256 {
    fn from(signed_beacon_block_hash: SignedBlindedBeaconBlockHash) -> Hash256 {
        signed_beacon_block_hash.0
    }
}

/// A `BlindedBeaconBlock` and a signature from its proposer.
#[superstruct(
    variants(Base, Altair, Merge),
    variant_attributes(
        derive(
            Debug,
            PartialEq,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash
        ),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary)),
        serde(bound = "E: EthSpec")
    )
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct SignedBlindedBeaconBlock<E: EthSpec> {
    #[superstruct(only(Base), partial_getter(rename = "message_base"))]
    pub message: BlindedBeaconBlockBase<E>,
    #[superstruct(only(Altair), partial_getter(rename = "message_altair"))]
    pub message: BlindedBeaconBlockAltair<E>,
    #[superstruct(only(Merge), partial_getter(rename = "message_merge"))]
    pub message: BlindedBeaconBlockMerge<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedBlindedBeaconBlock<E> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        self.message().fork_name(spec)
    }

    /// SSZ decode with fork variant determined by slot.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, |bytes| {
            BlindedBeaconBlock::from_ssz_bytes(bytes, spec)
        })
    }

    /// SSZ decode which attempts to decode all variants (slow).
    pub fn any_from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, BlindedBeaconBlock::any_from_ssz_bytes)
    }

    /// SSZ decode with custom decode function.
    pub fn from_ssz_bytes_with(
        bytes: &[u8],
        block_decoder: impl FnOnce(&[u8]) -> Result<BlindedBeaconBlock<E>, ssz::DecodeError>,
    ) -> Result<Self, ssz::DecodeError> {
        // We need the customer decoder for `BlindedBeaconBlock`, which doesn't compose with the other
        // SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Signature>()?;

        let mut decoder = builder.build()?;

        // Read the first item as a `BlindedBeaconBlock`.
        let message = decoder.decode_next_with(block_decoder)?;
        let signature = decoder.decode_next()?;

        Ok(Self::from_block(message, signature))
    }

    /// Create a new `SignedBlindedBeaconBlock` from a `BlindedBeaconBlock` and `Signature`.
    pub fn from_block(block: BlindedBeaconBlock<E>, signature: Signature) -> Self {
        match block {
            BlindedBeaconBlock::Base(message) => {
                SignedBlindedBeaconBlock::Base(SignedBlindedBeaconBlockBase { message, signature })
            }
            BlindedBeaconBlock::Altair(message) => {
                SignedBlindedBeaconBlock::Altair(SignedBlindedBeaconBlockAltair {
                    message,
                    signature,
                })
            }
            BlindedBeaconBlock::Merge(message) => {
                SignedBlindedBeaconBlock::Merge(SignedBlindedBeaconBlockMerge {
                    message,
                    signature,
                })
            }
        }
    }

    /// Deconstruct the `SignedBlindedBeaconBlock` into a `BlindedBeaconBlock` and `Signature`.
    ///
    /// This is necessary to get a `&BlindedBeaconBlock` from a `SignedBlindedBeaconBlock` because
    /// `SignedBlindedBeaconBlock` only contains a `BlindedBeaconBlock` _variant_.
    pub fn deconstruct(self) -> (BlindedBeaconBlock<E>, Signature) {
        match self {
            SignedBlindedBeaconBlock::Base(block) => {
                (BlindedBeaconBlock::Base(block.message), block.signature)
            }
            SignedBlindedBeaconBlock::Altair(block) => {
                (BlindedBeaconBlock::Altair(block.message), block.signature)
            }
            SignedBlindedBeaconBlock::Merge(block) => {
                (BlindedBeaconBlock::Merge(block.message), block.signature)
            }
        }
    }

    /// Accessor for the block's `message` field as a ref.
    pub fn message(&self) -> BlindedBeaconBlockRef<'_, E> {
        match self {
            SignedBlindedBeaconBlock::Base(inner) => BlindedBeaconBlockRef::Base(&inner.message),
            SignedBlindedBeaconBlock::Altair(inner) => {
                BlindedBeaconBlockRef::Altair(&inner.message)
            }
            SignedBlindedBeaconBlock::Merge(inner) => BlindedBeaconBlockRef::Merge(&inner.message),
        }
    }

    /// Accessor for the block's `message` as a mutable reference (for testing only).
    pub fn message_mut(&mut self) -> BlindedBeaconBlockRefMut<'_, E> {
        match self {
            SignedBlindedBeaconBlock::Base(inner) => {
                BlindedBeaconBlockRefMut::Base(&mut inner.message)
            }
            SignedBlindedBeaconBlock::Altair(inner) => {
                BlindedBeaconBlockRefMut::Altair(&mut inner.message)
            }
            SignedBlindedBeaconBlock::Merge(inner) => {
                BlindedBeaconBlockRefMut::Merge(&mut inner.message)
            }
        }
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
            self.slot().epoch(E::slots_per_epoch()),
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
}
