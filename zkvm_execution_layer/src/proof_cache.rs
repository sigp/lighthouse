use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::RwLock;
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId};

/// Thread-safe LRU cache for execution proofs
///
/// Stores proofs indexed by execution block hash.
///
/// Note: Multiple proofs from different subnets can exist for the same block hash.
pub struct ProofCache {
    cache: Arc<RwLock<LruCache<ExecutionBlockHash, Vec<ExecutionProof>>>>,
}

impl ProofCache {
    /// Create a new proof cache with the specified capacity
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).expect("Cache capacity must be > 0");
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
        }
    }

    /// Insert a proof into the cache
    ///
    /// TODO(zkproofs): Add more docs
    pub async fn insert(&self, proof: ExecutionProof) {
        let block_hash = proof.block_hash;
        let mut cache = self.cache.write().await;

        cache
            .get_or_insert_mut(block_hash, Vec::new)
            // TODO(zkproofs): can replace this with a HashSet so we don't need this
            .retain(|p| p.subnet_id != proof.subnet_id);

        cache.get_mut(&block_hash).unwrap().push(proof);
    }

    /// Get all proofs for a specific block hash
    pub async fn get(&self, block_hash: &ExecutionBlockHash) -> Option<Vec<ExecutionProof>> {
        let cache = self.cache.read().await;
        cache.peek(block_hash).cloned()
    }

    /// Get proofs for a specific block hash from specific subnets
    ///
    /// TODO(zkproofs): This is cloning proofs, so can be expensive
    pub async fn get_from_subnets(
        &self,
        block_hash: &ExecutionBlockHash,
        subnet_ids: &[ExecutionProofSubnetId],
    ) -> Vec<ExecutionProof> {
        let cache = self.cache.read().await;

        cache
            .peek(block_hash)
            .map(|proofs| {
                proofs
                    .iter()
                    .filter(|p| subnet_ids.contains(&p.subnet_id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if we have the minimum required number of proofs from _different_ subnets
    pub async fn has_required_proofs(
        &self,
        block_hash: &ExecutionBlockHash,
        min_required: usize,
    ) -> bool {
        let cache = self.cache.read().await;

        cache
            .peek(block_hash)
            .map(|proofs| proofs.len() >= min_required)
            .unwrap_or(false)
    }

    /// Get the number of unique subnets/proofs we have for a particular execution payload
    pub async fn subnet_count(&self, block_hash: &ExecutionBlockHash) -> usize {
        let cache = self.cache.read().await;

        cache
            .peek(block_hash)
            .map(|proofs| proofs.len())
            .unwrap_or(0)
    }

    /// Check if a proof exists from a specific subnet for a block
    pub async fn has_proof_from_subnet(
        &self,
        block_hash: &ExecutionBlockHash,
        subnet_id: ExecutionProofSubnetId,
    ) -> bool {
        let cache = self.cache.read().await;

        cache
            .peek(block_hash)
            .map(|proofs| proofs.iter().any(|p| p.subnet_id == subnet_id))
            .unwrap_or(false)
    }

    /// Remove all proofs for a specific block hash
    pub async fn remove(&self, block_hash: &ExecutionBlockHash) -> Option<Vec<ExecutionProof>> {
        let mut cache = self.cache.write().await;
        cache.pop(block_hash)
    }

    /// Clear all cached proofs
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get the current number of entries in the cache
    pub async fn len(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Check if the cache is empty
    pub async fn is_empty(&self) -> bool {
        let cache = self.cache.read().await;
        cache.is_empty()
    }
}

impl Clone for ProofCache {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash256;

    fn create_test_proof(
        subnet_id: ExecutionProofSubnetId,
        block_hash: ExecutionBlockHash,
    ) -> ExecutionProof {
        use types::FixedBytesExtended;
        ExecutionProof::new(subnet_id, block_hash, Hash256::zero(), vec![1, 2, 3]).unwrap()
    }

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::repeat_byte(1);
        let proof = create_test_proof(subnet_0, block_hash);

        cache.insert(proof.clone()).await;

        let retrieved = cache.get(&block_hash).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_cache_multiple_subnets() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();
        let block_hash = ExecutionBlockHash::repeat_byte(1);

        let proof_0 = create_test_proof(subnet_0, block_hash);
        let proof_1 = create_test_proof(subnet_1, block_hash);

        cache.insert(proof_0).await;
        cache.insert(proof_1).await;

        let proofs = cache.get(&block_hash).await.unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(cache.subnet_count(&block_hash).await, 2);
    }

    #[tokio::test]
    async fn test_cache_replace_same_subnet() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::repeat_byte(1);

        let mut proof_1 = create_test_proof(subnet_0, block_hash);
        proof_1.proof_data = vec![1].into(); // modify proof_data, so its a different execution proof
        let proof_2 = create_test_proof(subnet_0, block_hash);

        cache.insert(proof_1).await;
        cache.insert(proof_2.clone()).await;

        let proofs = cache.get(&block_hash).await.unwrap();
        assert_eq!(proofs.len(), 1); // Should only have one proof from subnet 0

        assert_eq!(proofs[0], proof_2); // proof_2 should replace proof_1, since they are for the same subnet and blockhash
    }

    #[tokio::test]
    async fn test_has_required_proofs() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();
        let block_hash = ExecutionBlockHash::repeat_byte(1);

        assert!(!cache.has_required_proofs(&block_hash, 2).await);

        cache.insert(create_test_proof(subnet_0, block_hash)).await;
        assert!(!cache.has_required_proofs(&block_hash, 2).await);

        cache.insert(create_test_proof(subnet_1, block_hash)).await;
        assert!(cache.has_required_proofs(&block_hash, 2).await);
    }

    #[tokio::test]
    async fn test_has_proof_from_subnet() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();
        let block_hash = ExecutionBlockHash::repeat_byte(1);

        assert!(!cache.has_proof_from_subnet(&block_hash, subnet_0).await);

        cache.insert(create_test_proof(subnet_0, block_hash)).await;

        assert!(cache.has_proof_from_subnet(&block_hash, subnet_0).await);
        assert!(!cache.has_proof_from_subnet(&block_hash, subnet_1).await);
    }

    #[tokio::test]
    async fn test_get_from_subnets() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();
        let subnet_2 = ExecutionProofSubnetId::new(2).unwrap();
        let block_hash = ExecutionBlockHash::repeat_byte(1);

        cache.insert(create_test_proof(subnet_0, block_hash)).await;
        cache.insert(create_test_proof(subnet_1, block_hash)).await;
        cache.insert(create_test_proof(subnet_2, block_hash)).await;

        let proofs = cache
            .get_from_subnets(&block_hash, &[subnet_0, subnet_2])
            .await;
        assert_eq!(proofs.len(), 2);
        assert!(proofs.iter().any(|p| p.subnet_id == subnet_0));
        assert!(proofs.iter().any(|p| p.subnet_id == subnet_2));
        assert!(!proofs.iter().any(|p| p.subnet_id == subnet_1));
    }

    #[tokio::test]
    async fn test_cache_remove() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::repeat_byte(1);

        cache.insert(create_test_proof(subnet_0, block_hash)).await;
        assert!(cache.get(&block_hash).await.is_some());

        let removed = cache.remove(&block_hash).await;
        assert!(removed.is_some());
        assert!(cache.get(&block_hash).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = ProofCache::new(10);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash_1 = ExecutionBlockHash::repeat_byte(1);
        let block_hash_2 = ExecutionBlockHash::repeat_byte(2);

        cache
            .insert(create_test_proof(subnet_0, block_hash_1))
            .await;
        cache
            .insert(create_test_proof(subnet_0, block_hash_2))
            .await;

        assert_eq!(cache.len().await, 2);

        cache.clear().await;

        assert_eq!(cache.len().await, 0);
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        let cache = ProofCache::new(2);
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash_1 = ExecutionBlockHash::repeat_byte(1);
        let block_hash_2 = ExecutionBlockHash::repeat_byte(2);
        let block_hash_3 = ExecutionBlockHash::repeat_byte(3);

        cache
            .insert(create_test_proof(subnet_0, block_hash_1))
            .await;
        cache
            .insert(create_test_proof(subnet_0, block_hash_2))
            .await;
        cache
            .insert(create_test_proof(subnet_0, block_hash_3))
            .await;

        // Cache should only hold 2 entries
        assert_eq!(cache.len().await, 2);

        // block_hash_1 should be evicted (last recently used)
        assert!(cache.get(&block_hash_1).await.is_none());
        assert!(cache.get(&block_hash_2).await.is_some());
        assert!(cache.get(&block_hash_3).await.is_some());
    }
}
