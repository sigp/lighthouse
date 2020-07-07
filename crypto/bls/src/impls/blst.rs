use crate::{
    aggregate_public_key::TAggregatePublicKey,
    aggregate_signature::TAggregateSignature,
    public_key::{PublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::TSecretKey,
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, SecretHash,
};
pub use blst::min_pk as blst_core;
use blst::{blst_scalar, BLST_ERROR};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::iter::ExactSizeIterator;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub type SignatureSet<'a> = crate::signature_set::SignatureSet<
    'a,
    blst_core::PublicKey,
    blst_core::AggregatePublicKey,
    blst_core::Signature,
    blst_core::AggregateSignature,
>;

pub fn verify_signature_sets<'a>(
    signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    let sets = signature_sets.collect::<Vec<_>>();

    let rng = &mut rand::thread_rng();

    let mut rands: Vec<blst_scalar> = Vec::with_capacity(sets.len());

    for _ in 0..sets.len() {
        let mut vals = [0u64; 4];
        vals[0] = rng.gen();
        let mut rand_i = std::mem::MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst::blst_scalar_from_uint64(rand_i.as_mut_ptr(), vals.as_ptr());
            rands.push(rand_i.assume_init());
        }
    }
    let msgs_refs: Vec<&[u8]> = sets.iter().map(|s| s.message.as_bytes()).collect();

    let sigs_result = sets
        .iter()
        .map(|s| s.signature.point().ok_or(()).map(|s| s.to_signature()))
        .collect::<Result<Vec<_>, ()>>();

    let sigs = if let Ok(sigs) = sigs_result {
        sigs
    } else {
        return false;
    };

    let pks: Vec<blst_core::PublicKey> = sets
        .iter()
        .map(|set| {
            // TODO: check for empty singing keys vec.

            let signing_keys = set
                .signing_keys
                .iter()
                .map(|pk| pk.point())
                .collect::<Vec<_>>();

            blst_core::AggregatePublicKey::aggregate(&signing_keys).to_public_key()
        })
        .collect();

    let sig_refs = sigs
        .iter()
        .map(|s| s)
        .collect::<Vec<&blst_core::Signature>>();

    let pks_refs: Vec<&blst_core::PublicKey> = pks.iter().collect();

    let err = blst_core::Signature::verify_multiple_aggregate_signatures(
        &msgs_refs, DST, &pks_refs, &sig_refs, &rands, 64,
    );

    err == blst::BLST_ERROR::BLST_SUCCESS
}

impl TPublicKey for blst_core::PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.compress()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::uncompress(&bytes).map_err(Into::into)
    }
}

impl TAggregatePublicKey for blst_core::AggregatePublicKey {
    fn zero() -> Self {
        unsafe { std::mem::MaybeUninit::<Self>::zeroed().assume_init() }
    }

    fn add_assign(&mut self, other: &Self) {
        todo!("blst_core add_assign")
    }

    fn add_assign_multiple<'a>(&'a mut self, others: impl Iterator<Item = &'a Self>) {
        todo!("blst_core add_assign_multiple")
    }

    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.to_public_key().compress()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        blst_core::PublicKey::from_bytes(&bytes)
            .map_err(Into::into)
            .map(|pk| Self::from_public_key(&pk as *const blst_core::PublicKey))
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
        self.verify(msg.as_bytes(), DST, &[], pubkey) == BLST_ERROR::BLST_SUCCESS
    }
}

impl TAggregateSignature<blst_core::PublicKey, blst_core::AggregatePublicKey, blst_core::Signature>
    for blst_core::AggregateSignature
{
    fn zero() -> Self {
        todo!("blst_core zero")
    }

    fn add_assign(&mut self, other: &blst_core::Signature) {
        self.add_signature(other)
    }

    fn add_assign_aggregate(&mut self, other: &Self) {
        self.add_aggregate(other)
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.to_signature().to_bytes()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        blst_core::Signature::from_bytes(bytes)
            .map_err(Into::into)
            .map(|sig| {
                blst_core::AggregateSignature::from_signature(&sig as *const blst_core::Signature)
            })
    }

    fn fast_aggregate_verify(
        &self,
        msg: Hash256,
        pubkeys: &[&PublicKey<blst_core::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        let signature = self.clone().to_signature();
        signature.fast_aggregate_verify(msg.as_bytes(), DST, &pubkeys) == BLST_ERROR::BLST_SUCCESS
    }

    fn aggregate_verify(
        &self,
        msgs: &[Hash256],
        pubkeys: &[&PublicKey<blst_core::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        let msgs = msgs.iter().map(|hash| hash.as_bytes()).collect::<Vec<_>>();
        let signature = self.clone().to_signature();
        signature.aggregate_verify(&msgs, DST, &pubkeys) == BLST_ERROR::BLST_SUCCESS
    }
}

impl TSecretKey<blst_core::Signature, blst_core::PublicKey> for blst_core::SecretKey {
    fn random() -> Self {
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        Self::key_gen(&ikm, &[]).unwrap()
    }

    fn public_key(&self) -> blst_core::PublicKey {
        self.sk_to_pk()
    }

    fn sign(&self, msg: Hash256) -> blst_core::Signature {
        self.sign(msg.as_bytes(), DST, &[])
    }

    fn serialize(&self) -> SecretHash {
        self.to_bytes().into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(&bytes).map_err(Into::into)
    }
}
