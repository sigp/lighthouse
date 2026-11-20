//! leanXMSS over Keccak-256: two layers of XMSS of height 16 over WOTS+C keys, as
//! specified in the [leanXMSS specification]. Each leaf of the top tree signs the
//! root of one bottom tree, whose `2^16` leaves sign messages, so a key signs at
//! `2^32` leaf indices. A public key is 32 bytes, a signature 2404, and a
//! verification 186 permutations.
//!
//! `Th(P, A, M) = H(P | A | M)` truncated to 16 bytes, `H` the leanVM hash, with
//! a 16-byte address `A` (the `hash` module).
//!
//! [leanXMSS specification]: https://github.com/leanEthereum/leanVM/releases/download/doc-latest/leanXMSS.pdf

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod hash;
mod scheme;
mod tree;
mod wots;

use hash::*;
use internals::*;
use tree::*;
use wots::*;

pub use scheme::{
    LeanXmssExpandedSecretKey, LeanXmssPublicKey, LeanXmssSignature, MAX_CACHE_SIZE,
    MAX_CACHED_BOTTOM_TREES, key_gen, sign, verify,
};

/// How many bytes in a [`SecretKey`].
pub const SECRET_KEY_LEN: usize = 32;
/// The secret key
pub type SecretKey = [u8; SECRET_KEY_LEN];

/// Hashed before the seed, so no other scheme derives from the same bytes.
pub(crate) const SEED_TAG: &[u8] = b"leanXMSS";

pub(crate) type Randomizer = [u8; RANDOMIZER_LEN];

/// How many bytes in a [`Message`].
pub const MESSAGE_LEN: usize = 32;
/// The message to be signed
pub type Message = [u8; MESSAGE_LEN];

/// Our double layer XMSS contains 2^32 WOTS. LeafIndex is the type to index each WOTS.
pub type LeafIndex = u32;

/// The last digits, which the signer grinds to zero, so they have no chain.
pub(crate) const ZERO_DIGITS: usize = 6;
/// Chain steps one verification walks per layer.
pub(crate) const CHAIN_HASHES: usize = V * (CHAIN_LEN - 1) - TARGET_SUM;
/// Randomizers tried per layer signature.
pub(crate) const MAX_RANDOMIZER_TRIALS: u64 = 1 << 32;

/// log2 of maximum number of signatures you can sign.
pub const LOG_LIFETIME: usize = 2 * LAYER_HEIGHT;

/// how many bytes in a [`LeanXmssPublicKey`].
pub const PUB_KEY_SIZE: usize = N + PUBLIC_PARAM_LEN;
pub(crate) const LEAF_INDEX_SIZE: usize = size_of::<LeafIndex>();
/// One layer's signature: the randomizer, the chain values and the path.
pub(crate) const LAYER_SIG_SIZE: usize = RANDOMIZER_LEN + V * N + LAYER_HEIGHT * N;
/// The leaf index, then the bottom layer's signature, then the top one's.
pub const SIG_SIZE: usize = LEAF_INDEX_SIZE + 2 * LAYER_SIG_SIZE;

/// The scheme's parameters and building blocks, for the aggregation guest and the test vectors. Not
/// the API: that is the crate root.
pub mod internals {
    pub use crate::hash::*;
    pub use crate::scheme::{LayerSignature, layer_root};
    pub use crate::wots::*;
    use crate::{LeanXmssPublicKey, LeanXmssSignature};

    /// The randomizer a layer's message digest is computed under.
    pub const RANDOMIZER_LEN: usize = 16;

    // WOTS+C
    /// `w`: digit size in bits.
    pub const W: usize = 2;
    /// `2^w`: one more than the steps of a hash chain.
    pub const CHAIN_LEN: usize = 1 << W;
    /// The digest's digits: 128 bits of base `2^w`.
    pub const DIGITS: usize = 8 * N / W;
    /// `v`: the chains of a one-time key.
    pub const V: usize = DIGITS - crate::ZERO_DIGITS;
    /// `T`: the sum of every codeword's `v` digits. Above the mean, so verification
    /// walks fewer chain steps.
    pub const TARGET_SUM: usize = 106;

    /// Height of each layer's tree.
    pub const LAYER_HEIGHT: usize = 16;

    /// The public key's public parameter.
    pub fn pk_public_param(pk: &LeanXmssPublicKey) -> &PublicParam {
        &pk.public_param
    }

    /// The bottom layer's signature.
    pub fn sig_bottom(sig: &LeanXmssSignature) -> &LayerSignature {
        &sig.bottom
    }

    /// The top layer's signature.
    pub fn sig_top(sig: &LeanXmssSignature) -> &LayerSignature {
        &sig.top
    }
}

/// Permutations of one verification: per layer the message digest, the chains,
/// the one-time leaf and the path.
pub(crate) const VERIFY_PERMUTATIONS: usize = blocks(RANDOMIZER_LEN + MESSAGE_LEN)
    + blocks(RANDOMIZER_LEN + N)
    + 2 * (CHAIN_HASHES * blocks(2 * N) + blocks(V * N) + LAYER_HEIGHT * blocks(2 * N));

const _: () = assert!(V == 58 && TARGET_SUM < V * (CHAIN_LEN - 1));
const _: () = assert!(PUB_KEY_SIZE == 32 && LAYER_SIG_SIZE == 1200 && SIG_SIZE == 2404);
const _: () = assert!(VERIFY_PERMUTATIONS == 186);
// A leaf index is the two layers' indices side by side.
const _: () = assert!(LOG_LIFETIME == 8 * LEAF_INDEX_SIZE);
