//! The leanXMSS signer and verifier from the pinned leanVM revision.

use crate::{
    Error, LeafIndex, XMSS_MESSAGE_BYTES_LEN, XMSS_PUBLIC_KEY_BYTES_LEN, XMSS_SECRET_KEY_BYTES_LEN,
    XMSS_SIGNATURE_BYTES_LEN,
};
use lean_xmss::internals::{public_param, scheme_seed};
use lean_xmss::{LeanXmssExpandedSecretKey, LeanXmssPublicKey, LeanXmssSignature};
use std::panic::{AssertUnwindSafe, catch_unwind};

const _: () = assert!(lean_xmss::PUB_KEY_SIZE == XMSS_PUBLIC_KEY_BYTES_LEN);
const _: () = assert!(lean_xmss::SIG_SIZE == XMSS_SIGNATURE_BYTES_LEN);
const _: () = assert!(lean_xmss::SECRET_KEY_LEN == XMSS_SECRET_KEY_BYTES_LEN);
const _: () = assert!(lean_xmss::MESSAGE_LEN == XMSS_MESSAGE_BYTES_LEN);
const _: () = assert!(lean_xmss::internals::LAYER_HEIGHT == crate::SUBTREE_LEAVES.ilog2() as usize);

pub(crate) const DEFAULT_BOTTOM_TREE_CACHE_SIZE: usize = lean_xmss::DEFAULT_BOTTOM_TREE_CACHE_SIZE;

pub(crate) fn public_parameter(seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN]) -> [u8; 16] {
    public_param(&scheme_seed(seed))
}

/// The top tree, plus a cache of the most recently used bottom trees.
pub(crate) struct ExpandedKey(LeanXmssExpandedSecretKey);

/// Builds the top tree: `2^16` one-time keys, on the order of a second of hashing.
pub(crate) fn key_gen(
    seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN],
) -> (ExpandedKey, [u8; XMSS_PUBLIC_KEY_BYTES_LEN]) {
    let (secret_key, public_key) = lean_xmss::key_gen(seed);
    (ExpandedKey(secret_key), public_key.to_bytes())
}

pub(crate) fn from_cache_bytes(
    seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN],
    public_key: &[u8; XMSS_PUBLIC_KEY_BYTES_LEN],
    bytes: &[u8],
) -> Option<ExpandedKey> {
    LeanXmssExpandedSecretKey::from_cache_bytes(
        seed,
        &LeanXmssPublicKey::from_bytes(public_key),
        bytes,
    )
    .map(ExpandedKey)
}

pub(crate) fn cache_to_bytes(key: &ExpandedKey) -> Result<Vec<u8>, Error> {
    catch_unwind(AssertUnwindSafe(|| key.0.cache_to_bytes())).map_err(|_| Error::SigningFailed)
}

pub(crate) fn prepare(
    key: &ExpandedKey,
    leaf_index: LeafIndex,
    cancelled: impl Fn() -> bool,
) -> Result<bool, Error> {
    if cancelled() {
        return Ok(false);
    }

    // Upstream panics rather than returning errors (a poisoned cache lock). Contain it.
    catch_unwind(AssertUnwindSafe(|| key.0.prepare(leaf_index)))
        .map_err(|_| Error::SigningFailed)?;
    Ok(!cancelled())
}

pub(crate) fn sign(
    key: &ExpandedKey,
    _public_key: &[u8; XMSS_PUBLIC_KEY_BYTES_LEN],
    message: &[u8; XMSS_MESSAGE_BYTES_LEN],
    leaf_index: LeafIndex,
) -> Result<[u8; XMSS_SIGNATURE_BYTES_LEN], Error> {
    // Upstream panics rather than returning errors (a poisoned cache lock, or no admissible
    // encoding, which has negligible probability). Contain it.
    catch_unwind(AssertUnwindSafe(|| {
        lean_xmss::sign(&key.0, message, leaf_index).to_bytes()
    }))
    .map_err(|_| Error::SigningFailed)
}

/// Whether `signature` is valid for `message` at the leaf index it embeds.
pub(crate) fn verify(
    public_key: &[u8; XMSS_PUBLIC_KEY_BYTES_LEN],
    message: &[u8; XMSS_MESSAGE_BYTES_LEN],
    signature: &[u8; XMSS_SIGNATURE_BYTES_LEN],
) -> bool {
    lean_xmss::verify(
        &LeanXmssPublicKey::from_bytes(public_key),
        message,
        &LeanXmssSignature::from_bytes(signature),
    )
}
