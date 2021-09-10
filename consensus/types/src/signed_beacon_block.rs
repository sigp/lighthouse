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
    variants(Base, Altair),
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
pub struct SignedBeaconBlock<E: EthSpec> {
    #[superstruct(only(Base), partial_getter(rename = "message_base"))]
    pub message: BeaconBlockBase<E>,
    #[superstruct(only(Altair), partial_getter(rename = "message_altair"))]
    pub message: BeaconBlockAltair<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedBeaconBlock<E> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        self.message().fork_name(spec)
    }

    /// SSZ decode with fork variant determined by slot.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, |bytes| BeaconBlock::from_ssz_bytes(bytes, spec))
    }

    /// SSZ decode which attempts to decode all variants (slow).
    pub fn any_from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, BeaconBlock::any_from_ssz_bytes)
    }

    /// SSZ decode with custom decode function.
    pub fn from_ssz_bytes_with(
        bytes: &[u8],
        block_decoder: impl FnOnce(&[u8]) -> Result<BeaconBlock<E>, ssz::DecodeError>,
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
    pub fn from_block(block: BeaconBlock<E>, signature: Signature) -> Self {
        match block {
            BeaconBlock::Base(message) => {
                SignedBeaconBlock::Base(SignedBeaconBlockBase { message, signature })
            }
            BeaconBlock::Altair(message) => {
                SignedBeaconBlock::Altair(SignedBeaconBlockAltair { message, signature })
            }
        }
    }

    /// Deconstruct the `SignedBeaconBlock` into a `BeaconBlock` and `Signature`.
    ///
    /// This is necessary to get a `&BeaconBlock` from a `SignedBeaconBlock` because
    /// `SignedBeaconBlock` only contains a `BeaconBlock` _variant_.
    pub fn deconstruct(self) -> (BeaconBlock<E>, Signature) {
        match self {
            SignedBeaconBlock::Base(block) => (BeaconBlock::Base(block.message), block.signature),
            SignedBeaconBlock::Altair(block) => {
                (BeaconBlock::Altair(block.message), block.signature)
            }
        }
    }

    /// Accessor for the block's `message` field as a ref.
    pub fn message(&self) -> BeaconBlockRef<'_, E> {
        match self {
            SignedBeaconBlock::Base(inner) => BeaconBlockRef::Base(&inner.message),
            SignedBeaconBlock::Altair(inner) => BeaconBlockRef::Altair(&inner.message),
        }
    }

    /// Accessor for the block's `message` as a mutable reference (for testing only).
    pub fn message_mut(&mut self) -> BeaconBlockRefMut<'_, E> {
        match self {
            SignedBeaconBlock::Base(inner) => BeaconBlockRefMut::Base(&mut inner.message),
            SignedBeaconBlock::Altair(inner) => BeaconBlockRefMut::Altair(&mut inner.message),
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
