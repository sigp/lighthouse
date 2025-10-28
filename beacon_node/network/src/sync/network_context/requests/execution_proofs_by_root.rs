use lighthouse_network::rpc::methods::ExecutionProofsByRootRequest;
use std::sync::Arc;
use types::{EthSpec, ExecutionProof, ExecutionProofId, Hash256};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Clone)]
pub struct ExecutionProofsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub already_have: Vec<ExecutionProofId>,
    pub count_needed: usize,
}

impl ExecutionProofsByRootSingleBlockRequest {
    pub fn into_request(self) -> Result<ExecutionProofsByRootRequest, String> {
        ExecutionProofsByRootRequest::new(
            self.block_root,
            self.already_have,
            self.count_needed,
        )
        .map_err(|e| e.to_string())
    }
}

pub struct ExecutionProofsByRootRequestItems<E: EthSpec> {
    request: ExecutionProofsByRootSingleBlockRequest,
    items: Vec<Arc<ExecutionProof>>,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> ExecutionProofsByRootRequestItems<E> {
    pub fn new(request: ExecutionProofsByRootSingleBlockRequest) -> Self {
        Self {
            request,
            items: vec![],
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for ExecutionProofsByRootRequestItems<E> {
    type Item = Arc<ExecutionProof>;

    /// Appends a proof to this multi-item request.
    /// Note: This is very similar to `DataColumnsByRootSingleBlockRequest`
    fn add(&mut self, proof: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = proof.block_root;
        if self.request.block_root != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        // Verify proof is not in the already_have list
        // We should not receive proofs we already have
        if self.request.already_have.contains(&proof.proof_id) {
            return Err(LookupVerifyError::UnrequestedProof(proof.proof_id));
        }

        // Check for duplicate proof IDs
        if self.items.iter().any(|p| p.proof_id == proof.proof_id) {
            return Err(LookupVerifyError::DuplicatedProofIDs(proof.proof_id));
        }

        self.items.push(proof);

        // We've received all requested proofs when we have count_needed proofs
        Ok(self.items.len() >= self.request.count_needed)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}