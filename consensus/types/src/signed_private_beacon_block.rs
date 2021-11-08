use crate::private_beacon_block::PrivateBeaconBlock;
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
pub struct SignedPrivateBeaconBlockHash(Hash256);

impl fmt::Debug for SignedPrivateBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedPrivateBeaconBlockHash({:?})", self.0)
    }
}

impl fmt::Display for SignedPrivateBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash256> for SignedPrivateBeaconBlockHash {
    fn from(hash: Hash256) -> SignedPrivateBeaconBlockHash {
        SignedPrivateBeaconBlockHash(hash)
    }
}

impl From<SignedPrivateBeaconBlockHash> for Hash256 {
    fn from(signed_beacon_block_hash: SignedPrivateBeaconBlockHash) -> Hash256 {
        signed_beacon_block_hash.0
    }
}

/// A `PrivateBeaconBlock` and a signature from its proposer.
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
pub struct SignedPrivateBeaconBlock<E: EthSpec> {
    #[superstruct(only(Base), partial_getter(rename = "message_base"))]
    pub message: PrivateBeaconBlockBase<E>,
    #[superstruct(only(Altair), partial_getter(rename = "message_altair"))]
    pub message: PrivateBeaconBlockAltair<E>,
    #[superstruct(only(Merge), partial_getter(rename = "message_merge"))]
    pub message: PrivateBeaconBlockMerge<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedPrivateBeaconBlock<E> {
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
            PrivateBeaconBlock::from_ssz_bytes(bytes, spec)
        })
    }

    /// SSZ decode which attempts to decode all variants (slow).
    pub fn any_from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, PrivateBeaconBlock::any_from_ssz_bytes)
    }

    /// SSZ decode with custom decode function.
    pub fn from_ssz_bytes_with(
        bytes: &[u8],
        block_decoder: impl FnOnce(&[u8]) -> Result<PrivateBeaconBlock<E>, ssz::DecodeError>,
    ) -> Result<Self, ssz::DecodeError> {
        // We need the customer decoder for `PrivateBeaconBlock`, which doesn't compose with the other
        // SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Signature>()?;

        let mut decoder = builder.build()?;

        // Read the first item as a `PrivateBeaconBlock`.
        let message = decoder.decode_next_with(block_decoder)?;
        let signature = decoder.decode_next()?;

        Ok(Self::from_block(message, signature))
    }

    /// Create a new `SignedPrivateBeaconBlock` from a `PrivateBeaconBlock` and `Signature`.
    pub fn from_block(block: PrivateBeaconBlock<E>, signature: Signature) -> Self {
        match block {
            PrivateBeaconBlock::Base(message) => {
                SignedPrivateBeaconBlock::Base(SignedPrivateBeaconBlockBase { message, signature })
            }
            PrivateBeaconBlock::Altair(message) => {
                SignedPrivateBeaconBlock::Altair(SignedPrivateBeaconBlockAltair {
                    message,
                    signature,
                })
            }
            PrivateBeaconBlock::Merge(message) => {
                SignedPrivateBeaconBlock::Merge(SignedPrivateBeaconBlockMerge {
                    message,
                    signature,
                })
            }
        }
    }

    /// Deconstruct the `SignedPrivateBeaconBlock` into a `PrivateBeaconBlock` and `Signature`.
    ///
    /// This is necessary to get a `&PrivateBeaconBlock` from a `SignedPrivateBeaconBlock` because
    /// `SignedPrivateBeaconBlock` only contains a `PrivateBeaconBlock` _variant_.
    pub fn deconstruct(self) -> (PrivateBeaconBlock<E>, Signature) {
        match self {
            SignedPrivateBeaconBlock::Base(block) => {
                (PrivateBeaconBlock::Base(block.message), block.signature)
            }
            SignedPrivateBeaconBlock::Altair(block) => {
                (PrivateBeaconBlock::Altair(block.message), block.signature)
            }
            SignedPrivateBeaconBlock::Merge(block) => {
                (PrivateBeaconBlock::Merge(block.message), block.signature)
            }
        }
    }

    /// Accessor for the block's `message` field as a ref.
    pub fn message(&self) -> PrivateBeaconBlockRef<'_, E> {
        match self {
            SignedPrivateBeaconBlock::Base(inner) => PrivateBeaconBlockRef::Base(&inner.message),
            SignedPrivateBeaconBlock::Altair(inner) => {
                PrivateBeaconBlockRef::Altair(&inner.message)
            }
            SignedPrivateBeaconBlock::Merge(inner) => PrivateBeaconBlockRef::Merge(&inner.message),
        }
    }

    /// Accessor for the block's `message` as a mutable reference (for testing only).
    pub fn message_mut(&mut self) -> PrivateBeaconBlockRefMut<'_, E> {
        match self {
            SignedPrivateBeaconBlock::Base(inner) => {
                PrivateBeaconBlockRefMut::Base(&mut inner.message)
            }
            SignedPrivateBeaconBlock::Altair(inner) => {
                PrivateBeaconBlockRefMut::Altair(&mut inner.message)
            }
            SignedPrivateBeaconBlock::Merge(inner) => {
                PrivateBeaconBlockRefMut::Merge(&mut inner.message)
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
