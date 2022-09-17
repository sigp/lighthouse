use ssz_types::VariableList;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use tree_hash::TreeHash;
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

impl<T: EthSpec> Encode for Blob<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<BlsFieldElement, T::FieldElementsPerBlob> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <VariableList<BlsFieldElement, T::FieldElementsPerBlob> as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl<T: EthSpec> Decode for Blob<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<BlsFieldElement, T::FieldElementsPerBlob> as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <VariableList<BlsFieldElement, T::FieldElementsPerBlob> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        <VariableList<BlsFieldElement, T::FieldElementsPerBlob>>::from_ssz_bytes(bytes).map(Self)
    }
}

impl<T: EthSpec> TreeHash for Blob<T> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <VariableList<BlsFieldElement, T::FieldElementsPerBlob>>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <VariableList<BlsFieldElement, T::FieldElementsPerBlob>>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}
