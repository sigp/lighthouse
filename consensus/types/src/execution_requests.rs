use crate::test_utils::TestRandom;
use crate::{ConsolidationRequest, DepositRequest, EthSpec, WithdrawalRequest};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    Derivative,
    Default,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct ExecutionRequests<E: EthSpec> {
    pub deposits: VariableList<DepositRequest, E::MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, E::MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, E::MaxConsolidationRequestsPerPayload>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ExecutionRequests);
}
