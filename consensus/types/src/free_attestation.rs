/// Note: this object does not actually exist in the spec.
///
/// We use it for managing attestations that have not been aggregated.
use super::{AttestationData, Signature};
use serde_derive::Serialize;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FreeAttestation {
    pub data: AttestationData,
    pub signature: Signature,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
}
