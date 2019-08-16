use types::{AggregatePublicKey, AggregateSignature, Hash256, PublicKey, SecretKey, Signature};

pub struct BigNum(SecretKey);

impl BigNum {
    pub fn random() -> Self {
        Self(SecretKey::random())
    }
}

pub struct BlsMultiVerify {
    agg_sig: AggregateSignature,
    agg_pub: AggregatePublicKey,
    msgs: Vec<Hash256>,
}

impl BlsMultiVerify {
    pub fn new() -> Self {
        Self {
            agg_sig: AggregateSignature::new(),
            agg_pub: AggregatePublicKey::new(),
            msgs: vec![],
        }
    }

    pub fn add_signature<'a>(
        signature: &Signature,
        message: Hash256,
        pubkeys: impl Iterator<Item = &'a PublicKey>,
    ) {
        let rand = BigNum::random();
        //
    }
}
