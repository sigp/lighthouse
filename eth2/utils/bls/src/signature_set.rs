use crate::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use milagro_bls::{G1Point, G2Point};

#[derive(Clone)]
pub struct SignatureSet<'a> {
    sig: &'a G2Point,
    keys: Vec<&'a G1Point>,
    msgs: Vec<Vec<u8>>,
    domain: u64,
}

impl<'a> SignatureSet<'a> {
    pub fn new<S, K>(sig: &'a S, keys: Vec<&'a K>, msgs: Vec<Vec<u8>>, domain: u64) -> Self
    where
        S: G2Ref,
        K: G1Ref,
    {
        Self {
            sig: sig.g2_ref(),
            keys: keys.into_iter().map(|k| k.g1_ref()).collect(),
            msgs,
            domain,
        }
    }
}

pub trait G1Ref {
    fn g1_ref(&self) -> &G1Point;
}

impl G1Ref for AggregatePublicKey {
    fn g1_ref(&self) -> &G1Point {
        &self.as_raw().point
    }
}

impl G1Ref for PublicKey {
    fn g1_ref(&self) -> &G1Point {
        &self.as_raw().point
    }
}

pub trait G2Ref {
    fn g2_ref(&self) -> &G2Point;
}

impl G2Ref for AggregateSignature {
    fn g2_ref(&self) -> &G2Point {
        &self.as_raw().point
    }
}

impl G2Ref for Signature {
    fn g2_ref(&self) -> &G2Point {
        &self.as_raw().point
    }
}
