//! The tweakable hash `Th(P, A, M) = Truncate_n(H(P | A | M))`, `H` the leanVM hash
//! ([`keccak256::hash`], Keccak-256), its address and the address types.
//!
//! The public parameter and the address are 16 bytes each, as every value hashed
//! after them is, so a prover whose cells are 16 bytes never has to cut a value in
//! two: a chain step and a Merkle node are one permutation. A chain step's address
//! leaves out the chain index, which follows the value instead (`wots::chain`), so a
//! key's chains share their step addresses.
//!
//! The two layers share one public parameter, so the address separates them: the
//! top layer sets [`TOP`] in `hi`. A bottom address's `lo` is the leaf index, or a
//! node's index `leaf_index >> level`, which also separates the bottom trees; a top
//! address's is the top tree's own.

use keccak256::Hasher;

use crate::*;

/// `n`: hash value and Merkle node length, in bytes.
pub const N: usize = 16;
pub type Digest = [u8; N];

pub const PUBLIC_PARAM_LEN: usize = 16;
pub type PublicParam = [u8; PUBLIC_PARAM_LEN];

pub(crate) const ADDRESS_LEN: usize = 16;

// Hash types (the low five bits of the address's byte 7).
pub(crate) const TWEAK_PRF: u8 = 0;
pub const TWEAK_CHAIN: u8 = 1;
pub const TWEAK_LEAF: u8 = 2;
pub const TWEAK_NODE: u8 = 3;
pub(crate) const TWEAK_PARAMETER: u8 = 5;
pub(crate) const TWEAK_RANDOMIZER: u8 = 7;
pub const TWEAK_MSG: u8 = 12;

/// The top layer's flag in `hi`.
pub const TOP: u32 = 1 << 23;

/// `hi` for `field` on layer `layer` (0 the bottom, 1 the top).
pub fn layer_hi(layer: usize, field: u32) -> u32 {
    field | (layer as u32 * TOP)
}

/// The address of a hash call: its type, a chain step, and two fields, `hi < 2^24`
/// and `lo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tweak {
    t: u8,
    step: u8,
    hi: u32,
    lo: u32,
}

pub fn tweak(t: u8, hi: u32, lo: u32) -> Tweak {
    debug_assert!(t < 32 && hi < 1 << 24);
    Tweak { t, step: 0, hi, lo }
}

impl Tweak {
    /// The same address at chain step `step < 8`.
    pub fn step(self, step: usize) -> Self {
        debug_assert!(step < 8);
        Self {
            step: step as u8,
            ..self
        }
    }
}

/// The 16 bytes that follow `P` in a hash input: `[lo:4 | hi:3 | t + 32 step:1 | zero:8]`,
/// the fields little endian.
pub fn address(tw: &Tweak) -> [u8; ADDRESS_LEN] {
    let mut out = [0u8; ADDRESS_LEN];
    out[..4].copy_from_slice(&tw.lo.to_le_bytes());
    out[4..7].copy_from_slice(&tw.hi.to_le_bytes()[..3]);
    out[7] = tw.t | tw.step << 5;
    out
}

/// Permutations the leanVM hash spends on a hash input whose payload is
/// `payload` bytes: one per 136-byte block, the last holding the padding.
pub const fn blocks(payload: usize) -> usize {
    keccak256::permutations(PUBLIC_PARAM_LEN + ADDRESS_LEN + payload)
}

/// A hasher that has absorbed `P | A`.
pub fn hasher(pp: &PublicParam, tw: &Tweak) -> Hasher {
    keccak256::prefixed_hasher(pp, &address(tw))
}

/// `Th` over a byte payload.
pub fn th(pp: &PublicParam, tw: &Tweak, payload: &[u8]) -> Digest {
    keccak256::truncate(hasher(pp, tw).update(payload).finalize())
}

/// `Th` over a concatenation of digests: a Merkle node or a leaf.
pub(crate) fn th_digests(pp: &PublicParam, tw: &Tweak, values: &[Digest]) -> Digest {
    th(pp, tw, values.as_flattened())
}

/// Two secrets for one hash: the two halves of the untruncated hash of the seed.
pub(crate) fn th_pair(pp: &PublicParam, tw: &Tweak, seed: &SchemeSeed) -> [Digest; 2] {
    let output = hasher(pp, tw).update(seed.as_bytes()).finalize();
    [
        output[..N].try_into().unwrap(),
        output[N..].try_into().unwrap(),
    ]
}

/// The seed the scheme derives every secret from, [`scheme_seed`] of a key's seed:
/// its own type, so that a key's seed cannot stand in for it.
#[derive(Clone, Copy)]
pub struct SchemeSeed(pub(crate) [u8; 32]);

impl SchemeSeed {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The seed the scheme derives from: the hash of `SEED_TAG` then the key's seed,
/// so no other scheme derives from the same bytes.
pub fn scheme_seed(seed: &SecretKey) -> SchemeSeed {
    SchemeSeed(Hasher::new().update(SEED_TAG).update(seed).finalize())
}

/// The public parameter, derived from the scheme's seed under `P = 0`.
pub fn public_param(seed: &SchemeSeed) -> PublicParam {
    th(
        &[0; PUBLIC_PARAM_LEN],
        &tweak(TWEAK_PARAMETER, 0, 0),
        seed.as_bytes(),
    )
}
