use bls::Error;
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

use super::{AggregateSignature, Attestation, AttestationData, BitList, EthSpec, SignatureBytes};

/// An attestation type with SSZ bytes for the signature
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LazyAttestation<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub signature: SignatureBytes,
}

impl<T: EthSpec> LazyAttestation<T> {
    pub fn to_attestation(self) -> Result<Attestation<T>, Error> {
        Ok(Attestation {
            aggregation_bits: self.aggregation_bits,
            data: self.data,
            signature: AggregateSignature::from(&self.signature.decompress()?),
        })
    }
}
