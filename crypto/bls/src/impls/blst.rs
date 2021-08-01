use crate::{
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_aggregate_signature::TAggregateSignature,
    generic_public_key::{GenericPublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN},
    generic_secret_key::TSecretKey,
    generic_signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, ZeroizeHash, INFINITY_SIGNATURE,
};
pub use blst::min_pk as blst_core;
use blst::{blst_scalar, BLST_ERROR};
use rand::Rng;
use std::iter::ExactSizeIterator;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const RAND_BITS: usize = 64;

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::blst_core::PublicKey;
    pub use super::blst_core::SecretKey;
    pub use super::blst_core::Signature;
    pub use super::verify_signature_sets;
    pub use super::BlstAggregatePublicKey as AggregatePublicKey;
    pub use super::BlstAggregateSignature as AggregateSignature;
    pub use super::SignatureSet;
}

pub type SignatureSet<'a> = crate::generic_signature_set::GenericSignatureSet<
    'a,
    blst_core::PublicKey,
    BlstAggregatePublicKey,
    blst_core::Signature,
    BlstAggregateSignature,
>;

pub fn verify_signature_sets<'a>(
    signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    let sets = signature_sets.collect::<Vec<_>>();

    if sets.is_empty() {
        return false;
    }

    let rng = &mut rand::thread_rng();

    let mut rands: Vec<blst_scalar> = Vec::with_capacity(sets.len());
    let mut msgs_refs = Vec::with_capacity(sets.len());
    let mut sigs = Vec::with_capacity(sets.len());
    let mut pks = Vec::with_capacity(sets.len());

    for set in &sets {
        // Generate random scalars.
        let mut vals = [0u64; 4];
        while vals[0] == 0 {
            // Do not use zero
            vals[0] = rng.gen();
        }
        let mut rand_i = std::mem::MaybeUninit::<blst_scalar>::uninit();

        // TODO: remove this `unsafe` code-block once we get a safe option from `blst`.
        //
        // https://github.com/sigp/lighthouse/issues/1720
        unsafe {
            blst::blst_scalar_from_uint64(rand_i.as_mut_ptr(), vals.as_ptr());
            rands.push(rand_i.assume_init());
        }

        // Grab a slice of the message, to satisfy the blst API.
        msgs_refs.push(set.message.as_bytes());

        if let Some(point) = set.signature.point() {
            // Subgroup check the signature
            if !point.0.subgroup_check() {
                return false;
            }
            // Convert the aggregate signature into a signature.
            sigs.push(point.0.to_signature())
        } else {
            // Any "empty" signature should cause a signature failure.
            return false;
        }

        // Sanity check.
        if set.signing_keys.is_empty() {
            // A signature that has no signing keys is invalid.
            return false;
        }

        // Collect all the public keys into a point, to satisfy the blst API.
        //
        // Note: we could potentially have the `SignatureSet` take a pubkey point instead of a
        // `GenericPublicKey` and avoid this allocation.
        let signing_keys = set
            .signing_keys
            .iter()
            .map(|pk| pk.point())
            .collect::<Vec<_>>();

        // Aggregate all the public keys.
        // Public keys have already been checked for subgroup and infinity
        let agg_pk = match blst_core::AggregatePublicKey::aggregate(&signing_keys, false) {
            Ok(agg_pk) => agg_pk,
            Err(_) => return false,
        };
        pks.push(agg_pk.to_public_key());
    }

    let (sig_refs, pks_refs): (Vec<_>, Vec<_>) = sigs.iter().zip(pks.iter()).unzip();

    // Public keys have already been checked for subgroup and infinity
    // Signatures have already been checked for subgroup
    // Signature checks above could be done here for convienence as well
    let err = blst_core::Signature::verify_multiple_aggregate_signatures(
        &msgs_refs, DST, &pks_refs, false, &sig_refs, false, &rands, RAND_BITS,
    );

    err == blst::BLST_ERROR::BLST_SUCCESS
}

impl TPublicKey for blst_core::PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.compress()
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

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }

    fn verify(&self, pubkey: &blst_core::PublicKey, msg: Hash256) -> bool {
        // Public keys have already been checked for subgroup and infinity
        // Check Signature inside function for subgroup
        self.verify(true, msg.as_bytes(), DST, &[], pubkey, false) == BLST_ERROR::BLST_SUCCESS
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
        signature.fast_aggregate_verify(true, msg.as_bytes(), DST, &pubkeys)
            == BLST_ERROR::BLST_SUCCESS
    }

    fn aggregate_verify(
        &self,
        msgs: &[Hash256],
        pubkeys: &[&GenericPublicKey<blst_core::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        let msgs = msgs.iter().map(|hash| hash.as_bytes()).collect::<Vec<_>>();
        let signature = self.0.clone().to_signature();
        // Public keys have already been checked for subgroup and infinity
        // Check Signature inside function for subgroup
        signature.aggregate_verify(true, &msgs, DST, &pubkeys, false) == BLST_ERROR::BLST_SUCCESS
    }
}

impl TSecretKey<blst_core::Signature, blst_core::PublicKey> for blst_core::SecretKey {
    fn random() -> Self {
        let rng = &mut rand::thread_rng();
        let ikm: [u8; 32] = rng.gen();

        Self::key_gen(&ikm, &[]).unwrap()
    }

    fn public_key(&self) -> blst_core::PublicKey {
        self.sk_to_pk()
    }

    fn sign(&self, msg: Hash256) -> blst_core::Signature {
        self.sign(msg.as_bytes(), DST, &[])
    }

    fn serialize(&self) -> ZeroizeHash {
        self.to_bytes().into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }
}
