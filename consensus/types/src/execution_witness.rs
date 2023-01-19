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
#[serde(rename_all = "camelCase")]
pub struct SuffixStateDiff<T: EthSpec> {
    //#[serde(with = "eth2_serde_utils::quoted_u8")]
    suffix: u8,
    // `None` means not currently present.
    current_value: Option<StateDiffValue<T>>,
    // `None` means value is not updated.
    // Not present for the Kaustinen testnet.
    //new_value: Option<StateDiffValue<T>>,
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
#[serde(rename_all = "camelCase")]
pub struct StemStateDiff<T: EthSpec> {
    stem: Stem<T>,
    suffix_diffs: VariableList<SuffixStateDiff<T>, T::MaxVerkleWidth>,
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
    inner: VariableList<StemStateDiff<T>, T::MaxStems>,
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
#[serde(rename_all = "camelCase")]
pub struct IpaProof<T: EthSpec> {
    cl: FixedVector<BanderwagonGroupElement<T>, T::IpaProofDepth>,
    cr: FixedVector<BanderwagonGroupElement<T>, T::IpaProofDepth>,
    final_evaluation: BanderwagonFieldElement<T>,
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
#[serde(rename_all = "camelCase")]
pub struct VerkleProof<T: EthSpec> {
    other_stems: VariableList<StemValue<T>, T::MaxStems>,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    depth_extension_present: VariableList<u8, T::MaxStems>,
    commitments_by_path: VariableList<BanderwagonGroupElement<T>, T::MaxCommittments>,
    d: BanderwagonGroupElement<T>,
    ipa_proof: IpaProof<T>,
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
#[serde(rename_all = "camelCase")]
pub struct ExecutionWitness<T: EthSpec> {
    state_diff: StateDiff<T>,
    verkle_proof: VerkleProof<T>,
}
