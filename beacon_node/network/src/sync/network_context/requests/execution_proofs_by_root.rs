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


#[cfg(test)]
mod tests {
    use super::*;
    use types::{ExecutionBlockHash, Hash256, MinimalEthSpec as E};

    fn make_proof(
        block_root: Hash256,
        subnet_id: u8,
        block_hash: ExecutionBlockHash,
    ) -> Arc<ExecutionProof> {
        Arc::new(
            ExecutionProof::new(
                ExecutionProofId::new(subnet_id).unwrap(),
                types::Slot::new(0),
                block_hash,
                block_root,
                vec![1, 2, 3],
            )
            .unwrap(),
        )
    }

    #[test]
    fn test_add_proof_success() {
        let block_root = Hash256::random();
        let request = ExecutionProofsByRootSingleBlockRequest {
            block_root,
            already_have: vec![],
            count_needed: 2,
        };

        let mut items = ExecutionProofsByRootRequestItems::<E>::new(request);
        let proof = make_proof(block_root, 0, ExecutionBlockHash::zero());

        let result = items.add(proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Not complete yet (need 2)
    }

    #[test]
    fn test_add_proof_wrong_block_root() {
        let block_root = Hash256::random();
        let wrong_root = Hash256::random();
        let request = ExecutionProofsByRootSingleBlockRequest {
            block_root,
            already_have: vec![],
            count_needed: 1,
        };

        let mut items = ExecutionProofsByRootRequestItems::<E>::new(request);
        let proof = make_proof(wrong_root, 0, ExecutionBlockHash::zero());

        let result = items.add(proof);
        assert!(matches!(
            result,
            Err(LookupVerifyError::UnrequestedBlockRoot(_))
        ));
    }

    #[test]
    fn test_add_proof_already_have() {
        let block_root = Hash256::random();
        let request = ExecutionProofsByRootSingleBlockRequest {
            block_root,
            already_have: vec![ExecutionProofId::new(0).unwrap()],
            count_needed: 2,
        };

        let mut items = ExecutionProofsByRootRequestItems::<E>::new(request);
        let proof = make_proof(block_root, 0, ExecutionBlockHash::zero()); // proof 0 in already_have

        let result = items.add(proof);
        assert!(matches!(
            result,
            Err(LookupVerifyError::UnrequestedProof(_))
        ));
    }

    #[test]
    fn test_add_duplicate_subnet() {
        let block_root = Hash256::random();
        let request = ExecutionProofsByRootSingleBlockRequest {
            block_root,
            already_have: vec![],
            count_needed: 1,
        };

        let mut items = ExecutionProofsByRootRequestItems::<E>::new(request);
        let proof1 = make_proof(block_root, 0, ExecutionBlockHash::zero());
        let proof2 = make_proof(block_root, 0, ExecutionBlockHash::zero());

        assert!(items.add(proof1).is_ok());
        let result = items.add(proof2);
        assert!(matches!(
            result,
            Err(LookupVerifyError::DuplicatedProofIDs(_))
        ));
    }

    #[test]
    fn test_complete_when_count_reached() {
        let block_root = Hash256::random();
        let request = ExecutionProofsByRootSingleBlockRequest {
            block_root,
            already_have: vec![],
            count_needed: 2,
        };

        let mut items = ExecutionProofsByRootRequestItems::<E>::new(request);
        let proof1 = make_proof(block_root, 0, ExecutionBlockHash::zero());
        let proof2 = make_proof(block_root, 1, ExecutionBlockHash::zero());

        assert!(!items.add(proof1).unwrap()); // Not complete
        assert!(items.add(proof2).unwrap()); // Complete!

        let received = items.consume();
        assert_eq!(received.len(), 2);
    }

    #[test]
    fn test_already_have_excludes_proofs() {
        let block_root = Hash256::random();
        let request = ExecutionProofsByRootSingleBlockRequest {
            block_root,
            already_have: vec![ExecutionProofId::new(0).unwrap(), ExecutionProofId::new(1).unwrap()],
            count_needed: 2,
        };

        let mut items = ExecutionProofsByRootRequestItems::<E>::new(request);

        // Should accept proofs not in already_have
        let proof2 = make_proof(block_root, 2, ExecutionBlockHash::zero());
        let proof3 = make_proof(block_root, 3, ExecutionBlockHash::zero());

        assert!(!items.add(proof2).unwrap()); // Not complete
        assert!(items.add(proof3).unwrap()); // Complete!

        let received = items.consume();
        assert_eq!(received.len(), 2);
    }
}