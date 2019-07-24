//! Merkle partials are a format for inclusion proofs of specific leaves in a merkle tree.
//!
//! This library is written to conform with the evolving Ethereum 2.0 specification for
//! [merkle proofs](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/light_client/merkle_proofs.md#merklepartial).
//! It provides implementations for the all SSZ primitives, as well as `FixedVectors` and
//! `VariableLists`. Custom contianers can be derived using the `merkle_partial_derive` macro,
//! assuming that each of the child objects have implemented the
//! [`MerkleTreeOverlay`](trait.MerkleTreeOverlay.html) trait.

pub mod cache;
mod error;
pub mod field;
mod merkle_tree_overlay;
mod partial;
mod path;
mod ser;
pub mod tree_arithmetic;

pub use error::Error;
pub use merkle_tree_overlay::{impls, MerkleTreeOverlay};
pub use partial::Partial;
pub use path::Path;
pub use ser::SerializedPartial;

/// General index for a node in a merkle tree.
pub type NodeIndex = u64;

use tree_hash::BYTES_PER_CHUNK;
