use crate::test_utils::TestRandom;
use crate::{ConsolidationRequest, DepositRequest, EthSpec, WithdrawalRequest};
use alloy_primitives::Bytes;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type DepositRequests<E> =
    VariableList<DepositRequest, <E as EthSpec>::MaxDepositRequestsPerPayload>;
pub type WithdrawalRequests<E> =
    VariableList<WithdrawalRequest, <E as EthSpec>::MaxWithdrawalRequestsPerPayload>;
pub type ConsolidationRequests<E> =
    VariableList<ConsolidationRequest, <E as EthSpec>::MaxConsolidationRequestsPerPayload>;

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
    pub deposits: DepositRequests<E>,
    pub withdrawals: WithdrawalRequests<E>,
    pub consolidations: ConsolidationRequests<E>,
}

impl<E: EthSpec> ExecutionRequests<E> {
    /// Returns the encoding according to EIP-7685 to send
    /// to the execution layer over the engine api.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        let deposit_bytes = Bytes::from(self.deposits.as_ssz_bytes());
        let withdrawal_bytes = Bytes::from(self.withdrawals.as_ssz_bytes());
        let consolidation_bytes = Bytes::from(self.consolidations.as_ssz_bytes());
        vec![deposit_bytes, withdrawal_bytes, consolidation_bytes]
    }
}

#[cfg(test)]
mod tests {
    use crate::MainnetEthSpec;

    use super::*;

    ssz_and_tree_hash_tests!(ExecutionRequests<MainnetEthSpec>);
}
