use crate::{
    BlstError, Error, Hash256, INFINITY_SIGNATURE, ZeroizeHash,
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_aggregate_signature::TAggregateSignature,
    generic_public_key::{
        GenericPublicKey, PUBLIC_KEY_BYTES_LEN, PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN, TPublicKey,
    },
    generic_secret_key::TSecretKey,
    generic_signature::{SIGNATURE_BYTES_LEN, SIGNATURE_UNCOMPRESSED_BYTES_LEN, TSignature},
};
pub use blst::min_pk as blst_core;
use blst::{BLST_ERROR, MultiPoint, blst_scalar};
use rand::Rng;
use std::collections::HashMap;
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const RAND_BITS: usize = 64;
/// Bytes per scalar in the flat buffer that `blst`'s multi-scalar multiplication expects.
const RAND_BYTES: usize = RAND_BITS / 8;

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::BlstAggregatePublicKey as AggregatePublicKey;
    pub use super::BlstAggregateSignature as AggregateSignature;
    pub use super::SignatureSet;
    pub use super::blst_core::PublicKey;
    pub use super::blst_core::SecretKey;
    pub use super::blst_core::Signature;
    pub use super::verify_signature_sets;
}

pub type SignatureSet<'a> = crate::generic_signature_set::GenericSignatureSet<
    'a,
    blst_core::PublicKey,
    BlstAggregatePublicKey,
    blst_core::Signature,
    BlstAggregateSignature,
>;

/// Batch-verify a collection of signature sets. Returns `true` only if every set is valid; one bad
/// set fails the whole batch (callers then re-check sets one by one to find it).
///
/// Optimization: Sets that sign the same `message` are folded into a single pairing
/// instead of one each. This helps most on the attestation subnets, where many unaggregated
/// attestations vote for the same `AttestationData`.
///
/// To stay sound, each signature and its public key are scaled by a fresh, secret, non-zero random
/// scalar before being summed. This is the same operation the standard batch verification already uses across
/// messages. Without it an attacker could craft bad signatures that cancel out.
pub fn verify_signature_sets<'a>(
    signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    let sets = signature_sets.collect::<Vec<_>>();

    if sets.is_empty() {
        return false;
    }

    let rng = &mut rand::rng();

    // Reduce each set to one `(public_key, signature)` pair and bucket the pairs by message.
    let mut group_index: HashMap<Hash256, usize> = HashMap::with_capacity(sets.len());
    let mut groups: Vec<(
        Hash256,
        Vec<blst_core::PublicKey>,
        Vec<blst_core::Signature>,
    )> = Vec::with_capacity(sets.len());

    for set in &sets {
        let Some((public_key, signature)) = reduce_signature_set(set) else {
            // A malformed set (bad/empty signature, no signing keys) fails the whole batch.
            return false;
        };

        match group_index.get(&set.message) {
            Some(&i) => {
                groups[i].1.push(public_key);
                groups[i].2.push(signature);
            }
            None => {
                group_index.insert(set.message, groups.len());
                groups.push((set.message, vec![public_key], vec![signature]));
            }
        }
    }

    // Collapse each group into one `(message, public_key, signature)` entry, then hand them to
    // `blst`'s batch verifier. One entry per distinct message means one pairing per distinct message.
    let mut msgs: Vec<Hash256> = Vec::with_capacity(groups.len());
    let mut pks: Vec<blst_core::PublicKey> = Vec::with_capacity(groups.len());
    let mut sigs: Vec<blst_core::Signature> = Vec::with_capacity(groups.len());

    for (message, mut group_pks, mut group_sigs) in groups {
        msgs.push(message);

        if group_pks.len() == 1 {
            // Nothing to fold. Forward the set as-is, so batches where every message is distinct
            // (e.g. block verification) behave exactly as before.
            pks.append(&mut group_pks);
            sigs.append(&mut group_sigs);
        } else {
            // Fold the group: scale each `(public_key, signature)` by a fresh secret scalar and sum. Since
            // the message is shared, the per-signature pairings combine into one.
            let scalars = random_scalar_bytes(rng, group_pks.len());

            pks.push(
                group_pks
                    .as_slice()
                    .mult(&scalars, RAND_BITS)
                    .to_public_key(),
            );
            sigs.push(
                group_sigs
                    .as_slice()
                    .mult(&scalars, RAND_BITS)
                    .to_signature(),
            );
        }
    }

    // One random coefficient per collapsed entry for the final batch verification.
    let mut rands: Vec<blst_scalar> = Vec::with_capacity(msgs.len());
    for _ in 0..msgs.len() {
        // Only the low 64 bits (`RAND_BITS`) are used.
        let vals = [nonzero_u64(rng), 0, 0, 0];
        let mut rand_i = std::mem::MaybeUninit::<blst_scalar>::uninit();

        // TODO: remove this `unsafe` code-block once we get a safe option from `blst`.
        //
        // https://github.com/sigp/lighthouse/issues/1720
        unsafe {
            blst::blst_scalar_from_uint64(rand_i.as_mut_ptr(), vals.as_ptr());
            rands.push(rand_i.assume_init());
        }
    }

    let msgs_refs = msgs.iter().map(|msg| msg.as_slice()).collect::<Vec<_>>();
    let pks_refs = pks.iter().collect::<Vec<_>>();
    let sigs_refs = sigs.iter().collect::<Vec<_>>();

    // Public keys have already been checked for subgroup and infinity.
    // Signatures have already been checked for subgroup.
    let err = blst_core::Signature::verify_multiple_aggregate_signatures(
        &msgs_refs, DST, &pks_refs, false, &sigs_refs, false, &rands, RAND_BITS,
    );

    err == blst::BLST_ERROR::BLST_SUCCESS
}

/// Reduce a `SignatureSet` to one `(public_key, signature)` pair, with the same checks as the
/// non-folded path. Returns `None` (failing the batch) if the set is malformed: an empty or
/// non-subgroup signature, no signing keys, or public keys that won't aggregate.
fn reduce_signature_set(
    set: &SignatureSet<'_>,
) -> Option<(blst_core::PublicKey, blst_core::Signature)> {
    // Subgroup-check the signature; an empty (`None`) signature fails.
    let point = set.signature.point()?;
    if !point.0.subgroup_check() {
        return None;
    }
    let signature = point.0.to_signature();

    // No signing keys means the set is invalid.
    if set.signing_keys.is_empty() {
        return None;
    }

    // Aggregate the signing keys into one public key (keys were validated at deserialization).
    let signing_keys = set
        .signing_keys
        .iter()
        .map(|pk| pk.point())
        .collect::<Vec<_>>();
    let agg_pk = blst_core::AggregatePublicKey::aggregate(&signing_keys, false).ok()?;

    Some((agg_pk.to_public_key(), signature))
}

/// Pack `n` fresh non-zero random scalars into the flat little-endian buffer `blst`'s multi-scalar
/// multiplication expects (`RAND_BYTES` bytes each).
fn random_scalar_bytes(rng: &mut impl Rng, n: usize) -> Vec<u8> {
    let mut scalars = Vec::with_capacity(n * RAND_BYTES);
    for _ in 0..n {
        scalars.extend_from_slice(&nonzero_u64(rng).to_le_bytes());
    }
    scalars
}

/// A fresh, non-zero random `u64` coefficient. Zero must never be used: it would drop a
/// `(public_key, signature)` pair from the sum and could let an invalid signature through.
fn nonzero_u64(rng: &mut impl Rng) -> u64 {
    let mut r: u64 = 0;
    while r == 0 {
        r = rng.random();
    }
    r
}

impl TPublicKey for blst_core::PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.compress()
    }

    fn serialize_uncompressed(&self) -> [u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] {
        blst_core::PublicKey::serialize(self)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        // key_validate accepts uncompressed bytes too so enforce byte length here.
        // It also does subgroup checks, noting infinity check is done in `generic_public_key.rs`.
        if bytes.len() != PUBLIC_KEY_BYTES_LEN {
            return Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: PUBLIC_KEY_BYTES_LEN,
            });
        }
        Self::key_validate(bytes).map_err(Into::into)
    }

    fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN {
            return Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN,
            });
        }
        // Ensure we use the `blst` function rather than the one from this trait.
        let result: Result<Self, BlstError> = Self::deserialize(bytes);
        let key = result?;
        Ok(key)
    }
}

/// A wrapper that allows for `PartialEq` and `Clone` impls.
pub struct BlstAggregatePublicKey(blst_core::AggregatePublicKey);

impl Clone for BlstAggregatePublicKey {
    fn clone(&self) -> Self {
        Self(blst_core::AggregatePublicKey::from_public_key(
            &self.0.to_public_key(),
        ))
    }
}

impl PartialEq for BlstAggregatePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_public_key() == other.0.to_public_key()
    }
}

impl TAggregatePublicKey<blst_core::PublicKey> for BlstAggregatePublicKey {
    fn to_public_key(&self) -> GenericPublicKey<blst_core::PublicKey> {
        GenericPublicKey::from_point(self.0.to_public_key())
    }

    fn aggregate(pubkeys: &[GenericPublicKey<blst_core::PublicKey>]) -> Result<Self, Error> {
        let pubkey_refs = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();

        // Public keys have already been checked for subgroup and infinity
        let agg_pub = blst_core::AggregatePublicKey::aggregate(&pubkey_refs, false)?;
        Ok(BlstAggregatePublicKey(agg_pub))
    }
}

impl TSignature<blst_core::PublicKey> for blst_core::Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.to_bytes()
    }

    fn serialize_uncompressed(&self) -> [u8; SIGNATURE_UNCOMPRESSED_BYTES_LEN] {
        self.serialize()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }

    fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        Self::deserialize(bytes).map_err(Into::into)
    }

    fn verify(&self, pubkey: &blst_core::PublicKey, msg: Hash256) -> bool {
        // Public keys have already been checked for subgroup and infinity
        // Check Signature inside function for subgroup
        self.verify(true, msg.as_slice(), DST, &[], pubkey, false) == BLST_ERROR::BLST_SUCCESS
    }
}

/// A wrapper that allows for `PartialEq` and `Clone` impls.
pub struct BlstAggregateSignature(blst_core::AggregateSignature);

impl Clone for BlstAggregateSignature {
    fn clone(&self) -> Self {
        Self(blst_core::AggregateSignature::from_signature(
            &self.0.to_signature(),
        ))
    }
}

impl PartialEq for BlstAggregateSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_signature() == other.0.to_signature()
    }
}

impl TAggregateSignature<blst_core::PublicKey, BlstAggregatePublicKey, blst_core::Signature>
    for BlstAggregateSignature
{
    fn infinity() -> Self {
        blst_core::Signature::from_bytes(&INFINITY_SIGNATURE)
            .map(|sig| blst_core::AggregateSignature::from_signature(&sig))
            .map(Self)
            .expect("should decode infinity signature")
    }

    fn add_assign(&mut self, other: &blst_core::Signature) {
        // Add signature into aggregate, signature has already been subgroup checked
        let _ = self.0.add_signature(other, false);
    }

    fn add_assign_aggregate(&mut self, other: &Self) {
        self.0.add_aggregate(&other.0)
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0.to_signature().to_bytes()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        blst_core::Signature::from_bytes(bytes)
            .map_err(Into::into)
            .map(|sig| blst_core::AggregateSignature::from_signature(&sig))
            .map(Self)
    }

    fn fast_aggregate_verify(
        &self,
        msg: Hash256,
        pubkeys: &[&GenericPublicKey<blst_core::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        let signature = self.0.clone().to_signature();
        // Public keys are already valid due to PoP
        // Check Signature inside function for subgroup
        signature.fast_aggregate_verify(true, msg.as_slice(), DST, &pubkeys)
            == BLST_ERROR::BLST_SUCCESS
    }

    fn aggregate_verify(
        &self,
        msgs: &[Hash256],
        pubkeys: &[&GenericPublicKey<blst_core::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        let msgs = msgs.iter().map(|hash| hash.as_slice()).collect::<Vec<_>>();
        let signature = self.0.clone().to_signature();
        // Public keys have already been checked for subgroup and infinity
        // Check Signature inside function for subgroup
        signature.aggregate_verify(true, &msgs, DST, &pubkeys, false) == BLST_ERROR::BLST_SUCCESS
    }
}

impl TSecretKey<blst_core::Signature, blst_core::PublicKey> for blst_core::SecretKey {
    fn random() -> Self {
        let rng = &mut rand::rng();
        let ikm: [u8; 32] = rng.random();

        Self::key_gen(&ikm, &[]).unwrap()
    }

    fn public_key(&self) -> blst_core::PublicKey {
        self.sk_to_pk()
    }

    fn sign(&self, msg: Hash256) -> blst_core::Signature {
        self.sign(msg.as_slice(), DST, &[])
    }

    fn serialize(&self) -> ZeroizeHash {
        self.to_bytes().into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }
}
