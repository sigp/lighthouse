use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
#[ssz(struct_behaviour = "transparent")]
#[serde(transparent)]
pub struct BanderwagonGroupElement<T: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    inner: FixedVector<u8, T::BytesPerBanderwagonElement>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
#[ssz(struct_behaviour = "transparent")]
#[serde(transparent)]
pub struct BanderwagonFieldElement<T: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    inner: FixedVector<u8, T::BytesPerBanderwagonElement>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
#[ssz(struct_behaviour = "transparent")]
#[serde(transparent)]
pub struct Stem<T: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    inner: FixedVector<u8, T::MaxStemLength>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
#[ssz(struct_behaviour = "transparent")]
#[serde(transparent)]
pub struct StateDiffValue<T: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    inner: FixedVector<u8, T::BytesPerSuffixStateDiffValue>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
pub struct SuffixStateDiff<T: EthSpec> {
    //#[serde(with = "eth2_serde_utils::quoted_u8")]
    pub suffix: u8,
    // `None` means not currently present.
    pub current_value: Optional<StateDiffValue<T>>,
    // `None` means value is not updated.
    pub new_value: Optional<StateDiffValue<T>>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
pub struct StemStateDiff<T: EthSpec> {
    pub stem: Stem<T>,
    pub suffix_diffs: VariableList<SuffixStateDiff<T>, T::MaxVerkleWidth>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
#[ssz(struct_behaviour = "transparent")]
#[serde(transparent)]
pub struct StateDiff<T: EthSpec> {
    pub inner: VariableList<StemStateDiff<T>, T::MaxStems>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
pub struct IpaProof<T: EthSpec> {
    pub cl: FixedVector<BanderwagonGroupElement<T>, T::IpaProofDepth>,
    pub cr: FixedVector<BanderwagonGroupElement<T>, T::IpaProofDepth>,
    pub final_evaluation: BanderwagonFieldElement<T>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
#[ssz(struct_behaviour = "transparent")]
#[serde(transparent)]
pub struct StemValue<T: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    inner: FixedVector<u8, T::MaxStemLength>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
pub struct VerkleProof<T: EthSpec> {
    pub other_stems: VariableList<StemValue<T>, T::MaxStems>,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub depth_extension_present: VariableList<u8, T::MaxStems>,
    pub commitments_by_path: VariableList<BanderwagonGroupElement<T>, T::MaxCommittments>,
    pub d: BanderwagonGroupElement<T>,
    pub ipa_proof: IpaProof<T>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[arbitrary(bound = "T: EthSpec")]
#[serde(bound = "T: EthSpec")]
pub struct ExecutionWitness<T: EthSpec> {
    pub state_diff: StateDiff<T>,
    pub verkle_proof: VerkleProof<T>,
    pub parent_state_root: Hash256,
}
