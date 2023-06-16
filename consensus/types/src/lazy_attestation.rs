use bls::Error;
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

use super::{AggregateSignature, Attestation, AttestationData, BitList, EthSpec, SignatureBytes};

///Details an attestation type that is simpler for decoding
///
#[derive(
    arbitrary::Arbitrary, Debug, Clone, Serialize, Deserialize, Encode, Decode, Derivative,
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
    /// Convert the lazy attestation to an actual Attestation
    pub fn to_attestation(self) -> Result<Attestation<T>, Error> {
        let attestation = Attestation {
            aggregation_bits: self.aggregation_bits,
            data: self.data,
            signature: AggregateSignature::from(&self.signature.decompress()?),
        };

        Ok(attestation)
    }
}
