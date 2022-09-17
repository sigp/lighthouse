use ssz_types::VariableList;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use crate::test_utils::RngCore;
use crate::bls_field_element::BlsFieldElement;
use crate::{EthSpec, Uint256};
use crate::test_utils::TestRandom;

#[derive(Default, Debug, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Blob<T: EthSpec>(pub VariableList<BlsFieldElement, T::FieldElementsPerBlob>);

impl <T: EthSpec> TestRandom for Blob<T> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut res = Blob(VariableList::empty());
        for i in 0..4096 {
            let slice = ethereum_types::U256([rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()]);
            let elem =BlsFieldElement(slice);
            res.0.push(elem);
        }
        res
    }
}