//! Lighthouse's wrapper around leanXMSS, the stateful hash-based signature scheme of the PQ
//! consensus-specs feature (`specs/_features/pq`).
//!
//! A key signs at `2^32` one-time leaves. Signing the same leaf twice with different messages
//! breaks the key, so nothing here tracks which leaves were used: the caller chooses the leaf
//! for every signature (the spec schedules them) and is responsible for never reusing one.
//!
//! The byte types are spec-exact: [`XmssPublicKey`] is `XMSSPubkey = Bytes32` and
//! [`XmssSignature`] is `XMSSSignature = ByteVector[2404]`, for SSZ and for tree hashing.
//!
//! Verification uses the pinned leanVM revision. Signing uses a compact cache backported
//! onto that revision. With the `fake_crypto` feature both are replaced by a cheap, insecure
//! stand-in whose signatures still bind the key, the leaf and the message.

#[cfg(feature = "fake_crypto")]
mod fake;
#[cfg(not(feature = "fake_crypto"))]
mod lean;

#[cfg(feature = "fake_crypto")]
use fake as backend;
#[cfg(not(feature = "fake_crypto"))]
use lean as backend;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use std::fmt;
use std::str::FromStr;
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};
use zeroize::Zeroizing;

/// Length of a serialized public key: the Merkle root followed by the public parameter.
pub const XMSS_PUBLIC_KEY_BYTES_LEN: usize = 32;
/// Length of a serialized signature: the leaf index followed by one signature per layer.
pub const XMSS_SIGNATURE_BYTES_LEN: usize = 2404;
/// Length of a secret key seed.
pub const XMSS_SECRET_KEY_BYTES_LEN: usize = 32;
/// Length of a signed message.
pub const XMSS_MESSAGE_BYTES_LEN: usize = 32;

/// Whether this build signs and verifies with the insecure `fake_crypto` stand-in.
pub const FAKE_CRYPTO: bool = cfg!(feature = "fake_crypto");

/// The index of a one-time leaf. The spec's `Uint64` leaf indices must fit in this.
pub type LeafIndex = u32;

/// The number of signing leaves in one bottom tree.
pub const SUBTREE_LEAVES: LeafIndex = 1 << 16;

/// Upper bound for the compact tree payload, excluding any caller-provided framing.
pub const MAX_CACHE_SIZE: usize = backend::MAX_CACHE_SIZE;

/// Length of the little-endian leaf index at the start of a signature.
const LEAF_INDEX_BYTES_LEN: usize = size_of::<LeafIndex>();

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid byte length: got {len}, expected {expected}")]
    InvalidByteLength { len: usize, expected: usize },
    #[error("invalid hex string: {0}")]
    InvalidHex(String),
    #[error("signing failed")]
    SigningFailed,
}

fn decode_hex<const N: usize>(string: &str) -> Result<[u8; N], Error> {
    let stripped = string
        .strip_prefix("0x")
        .ok_or_else(|| Error::InvalidHex("must start with 0x".to_string()))?;
    let bytes = hex::decode(stripped).map_err(|e| Error::InvalidHex(e.to_string()))?;
    fixed_bytes(&bytes)
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::InvalidByteLength {
        len: bytes.len(),
        expected: N,
    })
}

/// Implements the byte-oriented traits shared by the public key and the signature: hex
/// `Display`/`Debug`/`FromStr`, serde as a 0x-prefixed hex string, and SSZ as a fixed-length
/// byte vector. Modelled on `crypto/bls/src/macros.rs`.
macro_rules! impl_bytes_traits {
    ($type: ident, $byte_size: expr) => {
        impl $type {
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                fixed_bytes(bytes).map(Self)
            }

            pub fn as_bytes(&self) -> &[u8; $byte_size] {
                &self.0
            }

            pub fn to_bytes(&self) -> [u8; $byte_size] {
                self.0
            }

            /// The all-zero value, used as a placeholder before signing and as the SSZ default.
            pub fn empty() -> Self {
                Self([0; $byte_size])
            }
        }

        #[cfg(feature = "arbitrary")]
        impl arbitrary::Arbitrary<'_> for $type {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                let mut bytes = [0u8; $byte_size];
                u.fill_buffer(&mut bytes)?;
                Ok(Self(bytes))
            }
        }

        impl From<[u8; $byte_size]> for $type {
            fn from(bytes: [u8; $byte_size]) -> Self {
                Self(bytes)
            }
        }

        impl AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }

        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }

        impl FromStr for $type {
            type Err = Error;

            fn from_str(string: &str) -> Result<Self, Self::Err> {
                decode_hex(string).map(Self)
            }
        }

        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let string = String::deserialize(deserializer)?;
                Self::from_str(&string).map_err(serde::de::Error::custom)
            }
        }

        impl Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $byte_size
            }

            fn ssz_bytes_len(&self) -> usize {
                $byte_size
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self.0)
            }
        }

        impl Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $byte_size
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let array = bytes
                    .try_into()
                    .map_err(|_| DecodeError::InvalidByteLength {
                        len: bytes.len(),
                        expected: $byte_size,
                    })?;
                Ok(Self(array))
            }
        }

        impl TreeHash for $type {
            fn tree_hash_type() -> TreeHashType {
                TreeHashType::Vector
            }

            fn tree_hash_packed_encoding(&self) -> PackedEncoding {
                unreachable!("Vector should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Vector should never be packed.")
            }

            fn tree_hash_root(&self) -> Hash256 {
                let minimum_chunk_count = $byte_size.div_ceil(tree_hash::BYTES_PER_CHUNK);
                tree_hash::merkle_root(&self.0, minimum_chunk_count)
            }
        }
    };
}

/// A leanXMSS public key (the spec's `XMSSPubkey`).
///
/// Every 32-byte string decodes as a public key, so there is no separate "bytes" type and
/// no validation on deserialization.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XmssPublicKey([u8; XMSS_PUBLIC_KEY_BYTES_LEN]);

impl_bytes_traits!(XmssPublicKey, XMSS_PUBLIC_KEY_BYTES_LEN);

/// A leanXMSS signature (the spec's `XMSSSignature`).
///
/// Every 2404-byte string decodes as a signature; whether it verifies is another matter.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct XmssSignature([u8; XMSS_SIGNATURE_BYTES_LEN]);

impl_bytes_traits!(XmssSignature, XMSS_SIGNATURE_BYTES_LEN);

impl XmssSignature {
    /// The leaf index the signature carries (the spec's `GetLeafIndex`).
    ///
    /// This is what the signer claims, and what a verifier walks the Merkle path with. It is
    /// not checked against any schedule here: use [`verify`] with the expected leaf.
    pub fn leaf_index(&self) -> LeafIndex {
        let (leaf_bytes, _) = self.0.split_at(LEAF_INDEX_BYTES_LEN);
        let mut leaf_index = [0; LEAF_INDEX_BYTES_LEN];
        leaf_index.copy_from_slice(leaf_bytes);
        LeafIndex::from_le_bytes(leaf_index)
    }
}

/// A leanXMSS secret key, expanded from its 32-byte seed for fast signing.
///
/// Deliberately neither `Clone` nor serializable, and `Debug` shows only the public key.
/// Two live copies of a stateful key are how leaves get reused.
pub struct XmssSecretKey {
    public_key: XmssPublicKey,
    expanded: backend::ExpandedKey,
}

impl XmssSecretKey {
    /// Expands `seed` into a signing key and derives its public key.
    ///
    /// This is expensive with the real scheme (it hashes a tree of `2^16` one-time keys;
    /// expect around a second): do not call it on an async executor thread.
    /// With `fake_crypto` it is a single hash.
    pub fn from_seed(seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN]) -> Self {
        let (expanded, public_key) = backend::key_gen(seed);
        Self {
            public_key: XmssPublicKey(public_key),
            expanded,
        }
    }

    /// As [`Self::from_seed`], from a slice.
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self, Error> {
        let seed = Zeroizing::new(fixed_bytes::<XMSS_SECRET_KEY_BYTES_LEN>(seed)?);
        Ok(Self::from_seed(&seed))
    }

    /// Expands from a compact tree cache authenticated by the caller for this seed.
    ///
    /// The public key and the cached trees are checked before use. A restored cache starts
    /// at revision zero. With `fake_crypto`, there are no trees to restore.
    pub fn from_cache_bytes(
        seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN],
        public_key: XmssPublicKey,
        bytes: &[u8],
    ) -> Option<Self> {
        let expanded = backend::from_cache_bytes(seed, public_key.as_bytes(), bytes)?;
        Some(Self {
            public_key,
            expanded,
        })
    }

    /// Returns the current revision and its public tree data if the set of trees changed.
    /// Callers should authenticate these bytes before trusting them on reload.
    pub fn cache_snapshot(&self, previous: Option<u64>) -> Result<Option<(u64, Vec<u8>)>, Error> {
        backend::cache_snapshot(&self.expanded, previous)
    }

    pub fn public_key(&self) -> XmssPublicKey {
        self.public_key
    }

    /// Precomputes what signing at `leaf_index` needs, so that the signature itself is fast.
    ///
    /// The first signature in each range of `2^16` leaves builds that range's tree (as
    /// expensive as key generation); this does it ahead of time. The key caches the last few
    /// ranges it used. A no-op with `fake_crypto`.
    pub fn prepare(&self, leaf_index: LeafIndex) -> Result<(), Error> {
        self.prepare_with_cancel(leaf_index, || false).map(|_| ())
    }

    /// Prepares a tree without holding the cache lock during computation.
    /// Returns false if cancelled before the tree could be prepared.
    pub fn prepare_with_cancel(
        &self,
        leaf_index: LeafIndex,
        cancelled: impl Fn() -> bool,
    ) -> Result<bool, Error> {
        backend::prepare(&self.expanded, leaf_index, cancelled)
    }

    /// Signs `message` at `leaf_index` (the spec's `Sign`). Deterministic.
    ///
    /// The caller owns the leaf schedule: signing two different messages at one leaf reveals
    /// enough to forge. Nothing here remembers which leaves were used.
    pub fn sign(
        &self,
        message: &[u8; XMSS_MESSAGE_BYTES_LEN],
        leaf_index: LeafIndex,
    ) -> Result<XmssSignature, Error> {
        backend::sign(&self.expanded, &self.public_key.0, message, leaf_index).map(XmssSignature)
    }
}

impl fmt::Debug for XmssSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XmssSecretKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Whether `signature` is `public_key`'s signature of `message` at exactly `leaf_index` (the
/// spec's `Verify`).
///
/// The scheme itself accepts a signature at whichever leaf it carries, so the leaf is
/// compared explicitly first: a valid signature made at another leaf is rejected.
pub fn verify(
    public_key: &XmssPublicKey,
    leaf_index: LeafIndex,
    message: &[u8; XMSS_MESSAGE_BYTES_LEN],
    signature: &XmssSignature,
) -> bool {
    signature.leaf_index() == leaf_index && backend::verify(&public_key.0, message, &signature.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_hashing::hash32_concat;

    const LEAF: LeafIndex = (1 << 15) + 7;

    fn seed(byte: u8) -> [u8; XMSS_SECRET_KEY_BYTES_LEN] {
        [byte; XMSS_SECRET_KEY_BYTES_LEN]
    }

    fn message(byte: u8) -> [u8; XMSS_MESSAGE_BYTES_LEN] {
        [byte; XMSS_MESSAGE_BYTES_LEN]
    }

    /// Merkleizes `bytes` as an SSZ byte vector without using `tree_hash`: split into 32-byte
    /// chunks (the last zero-padded), pad the chunk list with zero chunks to a power of two,
    /// then hash pairwise up to the root.
    fn independent_merkle_root(bytes: &[u8]) -> [u8; 32] {
        let mut layer: Vec<[u8; 32]> = bytes
            .chunks(32)
            .map(|chunk| {
                let mut padded = [0; 32];
                padded[..chunk.len()].copy_from_slice(chunk);
                padded
            })
            .collect();
        layer.resize(layer.len().next_power_of_two(), [0; 32]);
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .map(|pair| hash32_concat(&pair[0], &pair[1]))
                .collect();
        }
        layer[0]
    }

    #[test]
    fn sizes_match_the_spec() {
        assert_eq!(<XmssPublicKey as Encode>::ssz_fixed_len(), 32);
        assert_eq!(<XmssSignature as Encode>::ssz_fixed_len(), 2404);
        assert!(<XmssPublicKey as Encode>::is_ssz_fixed_len());
        assert!(<XmssSignature as Decode>::is_ssz_fixed_len());
        // 2404 bytes are 75 full chunks and one of 4 bytes.
        assert_eq!(XMSS_SIGNATURE_BYTES_LEN.div_ceil(32), 76);
    }

    #[test]
    fn sign_and_verify() {
        let secret_key = XmssSecretKey::from_seed(&seed(1));
        let public_key = secret_key.public_key();
        let signature = secret_key.sign(&message(2), LEAF).unwrap();

        assert_eq!(signature.leaf_index(), LEAF);
        assert!(verify(&public_key, LEAF, &message(2), &signature));
        // Deterministic.
        assert_eq!(secret_key.sign(&message(2), LEAF).unwrap(), signature);
    }

    #[cfg(not(feature = "fake_crypto"))]
    #[test]
    fn compact_cache_matches_pinned_signer_and_reloads_boundary_trees() {
        use std::{cell::Cell, time::Instant};

        let seed = seed(0x34);
        let message = message(0xf2);
        let (old, old_public_key) = lean_xmss::key_gen(&seed);
        let key = XmssSecretKey::from_seed(&seed);
        assert_eq!(key.public_key().to_bytes(), old_public_key.to_bytes());

        let leaf_indices = [0, 63, 64, SUBTREE_LEAVES - 1, SUBTREE_LEAVES, u32::MAX];
        let mut signatures = Vec::new();
        let mut old_total = std::time::Duration::ZERO;
        let mut compact_total = std::time::Duration::ZERO;
        for leaf in leaf_indices {
            old.prepare(leaf);
            key.prepare(leaf).unwrap();
            let started = Instant::now();
            let expected = lean_xmss::sign(&old, &message, leaf).to_bytes();
            old_total += started.elapsed();
            let started = Instant::now();
            let signature = key.sign(&message, leaf).unwrap();
            compact_total += started.elapsed();
            assert_eq!(signature.to_bytes(), expected, "leaf {leaf}");
            assert!(verify(&key.public_key(), leaf, &message, &signature));
            signatures.push(signature);
        }

        let (revision, bytes) = key.cache_snapshot(None).unwrap().unwrap();
        assert_eq!(revision, 3);
        assert_eq!(bytes.len(), 16_384 + 3 * 17_588);
        let started = Instant::now();
        let restored = XmssSecretKey::from_cache_bytes(&seed, key.public_key(), &bytes).unwrap();
        eprintln!(
            "six warm signatures: pinned {:?}, compact {:?}; restored three subtrees in {:?}",
            old_total,
            compact_total,
            started.elapsed(),
        );
        for (leaf, expected) in leaf_indices.into_iter().zip(signatures) {
            assert_eq!(
                restored.sign(&message, leaf).unwrap(),
                expected,
                "leaf {leaf}"
            );
        }
        assert!(restored.cache_snapshot(Some(0)).unwrap().is_none());

        // The new subtree spans 65,536 leaves. Cancellation during its construction
        // cannot publish a partial tree, change the revision, or evict a usable tree.
        let probes = Cell::new(0);
        assert!(
            !restored
                .prepare_with_cancel(2 * SUBTREE_LEAVES, || {
                    probes.set(probes.get() + 1);
                    probes.get() == 4
                })
                .unwrap()
        );
        assert_eq!(probes.get(), 4);
        assert!(restored.cache_snapshot(Some(0)).unwrap().is_none());

        let reload = |data| XmssSecretKey::from_cache_bytes(&seed, key.public_key(), data);
        assert!(reload(&bytes[1..]).is_none());
        let mut tampered = bytes.clone();
        tampered[3] ^= 1;
        assert!(reload(&tampered).is_none());
        let mut tampered = bytes.clone();
        tampered[16_384 + 1204] ^= 1;
        assert!(reload(&tampered).is_none());
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes[16_384..16_384 + 17_588]);
        assert!(reload(&duplicate).is_none());
        let mut oversized = bytes.clone();
        oversized.resize(MAX_CACHE_SIZE + 17_588, 0);
        assert!(reload(&oversized).is_none());
        assert!(XmssSecretKey::from_cache_bytes(&[0x35; 32], key.public_key(), &bytes).is_none());
        assert!(XmssSecretKey::from_cache_bytes(&seed, XmssPublicKey::empty(), &bytes).is_none());
    }

    #[test]
    fn verify_binds_key_leaf_and_message() {
        let secret_key = XmssSecretKey::from_seed(&seed(1));
        let public_key = secret_key.public_key();
        let signature = secret_key.sign(&message(2), LEAF).unwrap();

        // Another message.
        assert!(!verify(&public_key, LEAF, &message(3), &signature));
        // Another key.
        let other_key = XmssSecretKey::from_seed(&seed(9)).public_key();
        assert_ne!(other_key, public_key);
        assert!(!verify(&other_key, LEAF, &message(2), &signature));
        // A valid signature, but expected at another leaf.
        assert!(!verify(&public_key, LEAF + 1, &message(2), &signature));
        // The leaf rewritten to the expected one: the signature no longer verifies.
        let mut bytes = signature.to_bytes();
        bytes[..4].copy_from_slice(&(LEAF + 1).to_le_bytes());
        let relabelled = XmssSignature::from(bytes);
        assert_eq!(relabelled.leaf_index(), LEAF + 1);
        assert!(!verify(&public_key, LEAF + 1, &message(2), &relabelled));
        // A flipped bit at the end of the signature.
        let mut bytes = signature.to_bytes();
        bytes[XMSS_SIGNATURE_BYTES_LEN - 1] ^= 1;
        assert!(!verify(
            &public_key,
            LEAF,
            &message(2),
            &XmssSignature::from(bytes)
        ));
    }

    #[test]
    fn prepare_then_sign_in_the_same_range() {
        let secret_key = XmssSecretKey::from_seed(&seed(4));
        secret_key.prepare(LEAF).unwrap();
        let signature = secret_key.sign(&message(5), LEAF + 1).unwrap();
        assert!(verify(
            &secret_key.public_key(),
            LEAF + 1,
            &message(5),
            &signature
        ));
    }

    #[test]
    fn secret_key_from_seed_bytes() {
        assert_eq!(
            XmssSecretKey::from_seed_bytes(&[0; 31]).unwrap_err(),
            Error::InvalidByteLength {
                len: 31,
                expected: 32
            }
        );
        let from_slice = XmssSecretKey::from_seed_bytes(&seed(6)).unwrap();
        // `Debug` shows the public key and nothing of the seed.
        let debug = format!("{from_slice:?}");
        assert!(debug.contains(&from_slice.public_key().to_string()));
        assert!(!debug.contains(&hex::encode(seed(6))));
    }

    #[test]
    fn ssz_round_trip() {
        let public_key = XmssPublicKey::from(seed(7));
        let bytes = public_key.as_ssz_bytes();
        assert_eq!(bytes, seed(7));
        assert_eq!(XmssPublicKey::from_ssz_bytes(&bytes).unwrap(), public_key);
        assert!(XmssPublicKey::from_ssz_bytes(&bytes[1..]).is_err());

        let raw: Vec<u8> = (0..XMSS_SIGNATURE_BYTES_LEN).map(|i| i as u8).collect();
        let signature = XmssSignature::from_bytes(&raw).unwrap();
        let bytes = signature.as_ssz_bytes();
        assert_eq!(bytes, raw);
        assert_eq!(XmssSignature::from_ssz_bytes(&bytes).unwrap(), signature);
        assert_eq!(
            XmssSignature::from_ssz_bytes(&bytes[1..]),
            Err(DecodeError::InvalidByteLength {
                len: 2403,
                expected: 2404
            })
        );
        assert_eq!(signature.leaf_index(), u32::from_le_bytes([0, 1, 2, 3]));
    }

    #[test]
    fn serde_round_trip() {
        let public_key = XmssPublicKey::from(seed(0xab));
        let json = serde_json::to_string(&public_key).unwrap();
        assert_eq!(json, format!("\"0x{}\"", "ab".repeat(32)));
        assert_eq!(
            serde_json::from_str::<XmssPublicKey>(&json).unwrap(),
            public_key
        );

        let signature = XmssSignature::from([0xcd; XMSS_SIGNATURE_BYTES_LEN]);
        let json = serde_json::to_string(&signature).unwrap();
        assert_eq!(json, format!("\"0x{}\"", "cd".repeat(2404)));
        assert_eq!(
            serde_json::from_str::<XmssSignature>(&json).unwrap(),
            signature
        );

        // No prefix, bad hex, wrong length.
        assert!(
            serde_json::from_str::<XmssPublicKey>(&format!("\"{}\"", "ab".repeat(32))).is_err()
        );
        assert!(
            serde_json::from_str::<XmssPublicKey>(&format!("\"0x{}\"", "zz".repeat(32))).is_err()
        );
        assert!(
            serde_json::from_str::<XmssPublicKey>(&format!("\"0x{}\"", "ab".repeat(31))).is_err()
        );
        assert!(
            serde_json::from_str::<XmssSignature>(&format!("\"0x{}\"", "ab".repeat(32))).is_err()
        );
    }

    #[test]
    fn public_key_tree_hash_root_is_the_key() {
        // `Bytes32` is a single chunk, so its root is the bytes themselves.
        let public_key = XmssPublicKey::from(seed(0x11));
        assert_eq!(public_key.tree_hash_root().0, seed(0x11));
        assert_eq!(
            public_key.tree_hash_root().0,
            independent_merkle_root(&seed(0x11))
        );
    }

    #[test]
    fn signature_tree_hash_root_matches_independent_merkleization() {
        let patterns: [Box<dyn Fn(usize) -> u8>; 3] = [
            Box::new(|_| 0),
            Box::new(|i| i as u8),
            Box::new(|i| (i * 31 + 7) as u8),
        ];
        for pattern in patterns {
            let raw: Vec<u8> = (0..XMSS_SIGNATURE_BYTES_LEN).map(pattern).collect();
            let signature = XmssSignature::from_bytes(&raw).unwrap();
            assert_eq!(signature.tree_hash_root().0, independent_merkle_root(&raw),);
        }
        // 76 chunks pad to 128 leaves: the root is not that of the 2404 bytes packed any
        // other way, e.g. as a list would be (with a length mix-in).
        let signature = XmssSignature::from([0xff; XMSS_SIGNATURE_BYTES_LEN]);
        let vector_root = independent_merkle_root(&[0xff; XMSS_SIGNATURE_BYTES_LEN]);
        let mut length = [0; 32];
        length[..8].copy_from_slice(&(XMSS_SIGNATURE_BYTES_LEN as u64).to_le_bytes());
        assert_eq!(signature.tree_hash_root().0, vector_root);
        assert_ne!(
            signature.tree_hash_root().0,
            hash32_concat(&vector_root, &length)
        );
    }

    #[cfg(feature = "fake_crypto")]
    #[test]
    fn fake_signature_layout() {
        let secret_key = XmssSecretKey::from_seed(&seed(1));
        let signature = secret_key.sign(&message(2), LEAF).unwrap();
        let bytes = signature.as_bytes();

        let mut preimage = secret_key.public_key().to_bytes().to_vec();
        preimage.extend_from_slice(&LEAF.to_le_bytes());
        preimage.extend_from_slice(&message(2));
        assert_eq!(bytes[..4], LEAF.to_le_bytes());
        assert_eq!(bytes[4..36], ethereum_hashing::hash_fixed(&preimage));
        assert!(bytes[36..].iter().all(|byte| *byte == 0));
    }
}
