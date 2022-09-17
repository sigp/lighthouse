use ssz_types::VariableList;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use crate::bls_field_element::BlsFieldElement;
use crate::EthSpec;

#[derive(Default, Debug, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Blob<T: EthSpec>(pub VariableList<BlsFieldElement, T::FieldElementsPerBlob>);