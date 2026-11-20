//! An insecure stand-in for leanXMSS, for tests and debug builds: anyone can "sign" for any
//! public key, but a signature is only accepted for the key, leaf index and message it was
//! made for, so logic errors (wrong key, wrong leaf, wrong message) are still caught.
//!
//! - public key: `sha256("lighthouse-fake-xmss-pk" || seed)`
//! - signature: `leaf_index (u32 LE) || sha256(public key || leaf_index (u32 LE) || message)`,
//!   zero-padded to the real signature length

use crate::{
    Error, LEAF_INDEX_BYTES_LEN, LeafIndex, XMSS_MESSAGE_BYTES_LEN, XMSS_PUBLIC_KEY_BYTES_LEN,
    XMSS_SECRET_KEY_BYTES_LEN, XMSS_SIGNATURE_BYTES_LEN,
};
use ethereum_hashing::{HASH_LEN, hash_fixed};

const PUBLIC_KEY_DOMAIN: &[u8] = b"lighthouse-fake-xmss-pk";

pub(crate) const MAX_CACHE_SIZE: usize = 0;

pub(crate) struct ExpandedKey;

pub(crate) fn key_gen(
    seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN],
) -> (ExpandedKey, [u8; XMSS_PUBLIC_KEY_BYTES_LEN]) {
    let mut preimage = PUBLIC_KEY_DOMAIN.to_vec();
    preimage.extend_from_slice(seed);
    (ExpandedKey, hash_fixed(&preimage))
}

pub(crate) fn from_cache_bytes(
    _seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN],
    _public_key: &[u8; XMSS_PUBLIC_KEY_BYTES_LEN],
    _bytes: &[u8],
) -> Option<ExpandedKey> {
    None
}

pub(crate) fn cache_snapshot(
    _key: &ExpandedKey,
    _previous: Option<u64>,
) -> Result<Option<(u64, Vec<u8>)>, Error> {
    Ok(None)
}

pub(crate) fn prepare(
    _key: &ExpandedKey,
    _leaf_index: LeafIndex,
    cancelled: impl Fn() -> bool,
) -> Result<bool, Error> {
    Ok(!cancelled())
}

fn fake_signature(
    public_key: &[u8; XMSS_PUBLIC_KEY_BYTES_LEN],
    message: &[u8; XMSS_MESSAGE_BYTES_LEN],
    leaf_index: LeafIndex,
) -> [u8; XMSS_SIGNATURE_BYTES_LEN] {
    let leaf_bytes = leaf_index.to_le_bytes();
    let mut preimage = Vec::with_capacity(
        XMSS_PUBLIC_KEY_BYTES_LEN + LEAF_INDEX_BYTES_LEN + XMSS_MESSAGE_BYTES_LEN,
    );
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(&leaf_bytes);
    preimage.extend_from_slice(message);
    let digest: [u8; HASH_LEN] = hash_fixed(&preimage);

    let mut signature = [0; XMSS_SIGNATURE_BYTES_LEN];
    let (leaf, rest) = signature.split_at_mut(LEAF_INDEX_BYTES_LEN);
    leaf.copy_from_slice(&leaf_bytes);
    if let Some(slot) = rest.get_mut(..HASH_LEN) {
        slot.copy_from_slice(&digest);
    }
    signature
}

pub(crate) fn sign(
    _key: &ExpandedKey,
    public_key: &[u8; XMSS_PUBLIC_KEY_BYTES_LEN],
    message: &[u8; XMSS_MESSAGE_BYTES_LEN],
    leaf_index: LeafIndex,
) -> Result<[u8; XMSS_SIGNATURE_BYTES_LEN], Error> {
    Ok(fake_signature(public_key, message, leaf_index))
}

/// Whether `signature` is the fake signature of `message` at the leaf index it embeds.
pub(crate) fn verify(
    public_key: &[u8; XMSS_PUBLIC_KEY_BYTES_LEN],
    message: &[u8; XMSS_MESSAGE_BYTES_LEN],
    signature: &[u8; XMSS_SIGNATURE_BYTES_LEN],
) -> bool {
    let Some(leaf_bytes) = signature.first_chunk::<LEAF_INDEX_BYTES_LEN>() else {
        return false;
    };
    let leaf_index = LeafIndex::from_le_bytes(*leaf_bytes);
    fake_signature(public_key, message, leaf_index) == *signature
}
