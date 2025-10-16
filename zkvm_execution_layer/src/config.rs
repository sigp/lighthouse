use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use types::ExecutionProofSubnetId;

const DEFAULT_PROOF_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

const DEFAULT_GOSSIP_GRACE_PERIOD: Duration = Duration::from_millis(4000);

/// Configuration for the zkVM Execution Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKVMExecutionLayerConfig {
    /// Which subnets/proofs that we are subscribed to and therefore need to
    /// know how to verify
    pub subscribed_subnets: HashSet<ExecutionProofSubnetId>,

    /// Minimum number of proofs required from _different_ subnets
    /// in order for the node to mark an execution payload as VALID.
    pub min_proofs_required: usize,

    /// Which subnets to generate proofs for (empty if not generating proofs)
    pub generation_subnets: HashSet<ExecutionProofSubnetId>,

    /// Proof cache size (number of execution block hashes to cache proofs for)
    pub proof_cache_size: usize,

    /// Timeout for proof requests via RPC
    ///
    /// Note: This is needed for the case that we need to request proofs via
    /// RPC because we didn't receive them via gossip within `gossip_grace_period`
    pub proof_request_timeout: Duration,

    /// Delay before falling back to RPC (gossip grace period)
    /// During this time, we wait for `min_proofs_required` proofs to arrive via gossip
    ///
    /// TODO(zkproofs): This starts counting down from when the user receives the execution payload
    pub gossip_grace_period: Duration,
}

impl Default for ZKVMExecutionLayerConfig {
    fn default() -> Self {
        Self {
            subscribed_subnets: HashSet::new(),
            min_proofs_required: 1,
            generation_subnets: HashSet::new(),
            // TODO(zkproofs): This is somewhat arbitrary. The number was computed
            // by NUMBER_OF_BLOCKS_BEFORE_FINALIZATION * NUM_PROOFS_PER_BLOCK = 64 * 8
            // We can change it to be more rigorous/scientific
            proof_cache_size: 64 * 8,
            // TODO(zkproofs): Also arbitrary
            proof_request_timeout: DEFAULT_PROOF_REQUEST_TIMEOUT,
            // TODO(zkproofs): Also arbitrary
            gossip_grace_period: DEFAULT_GOSSIP_GRACE_PERIOD,
        }
    }
}

impl ZKVMExecutionLayerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_proofs_required == 0 {
            return Err("min_proofs_required must be at least 1".to_string());
        }

        if self.proof_cache_size == 0 {
            return Err("proof_cache_size must be at least 1".to_string());
        }

        // Ensure we subscribe to enough subnets to meet min_proofs_required
        if self.subscribed_subnets.len() < self.min_proofs_required {
            return Err(format!(
                "subscribed_subnets ({}) must be >= min_proofs_required ({})",
                self.subscribed_subnets.len(),
                self.min_proofs_required
            ));
        }

        // Node can only generate proofs for subnets they are subscribed to
        for subnet in &self.generation_subnets {
            if !self.subscribed_subnets.contains(subnet) {
                return Err(format!(
                    "generation_subnets must be a subset of subscribed_subnets (subnet {} not subscribed)",
                    subnet
                ));
            }
        }

        Ok(())
    }

    /// Create a builder for the config (mostly for convenience, we can remove)
    pub fn builder() -> StatelessExecutionLayerConfigBuilder {
        StatelessExecutionLayerConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct StatelessExecutionLayerConfigBuilder {
    subscribed_subnets: HashSet<ExecutionProofSubnetId>,
    min_proofs_required: Option<usize>,
    generation_subnets: HashSet<ExecutionProofSubnetId>,
    proof_cache_size: Option<usize>,
    proof_request_timeout: Option<Duration>,
    gossip_grace_period: Option<Duration>,
}

impl StatelessExecutionLayerConfigBuilder {
    pub fn subscribed_subnets(mut self, subnets: HashSet<ExecutionProofSubnetId>) -> Self {
        self.subscribed_subnets = subnets;
        self
    }

    pub fn add_subscribed_subnet(mut self, subnet: ExecutionProofSubnetId) -> Self {
        self.subscribed_subnets.insert(subnet);
        self
    }

    pub fn min_proofs_required(mut self, min: usize) -> Self {
        self.min_proofs_required = Some(min);
        self
    }

    pub fn generation_subnets(mut self, subnets: HashSet<ExecutionProofSubnetId>) -> Self {
        self.generation_subnets = subnets;
        self
    }

    pub fn add_generation_subnet(mut self, subnet: ExecutionProofSubnetId) -> Self {
        self.generation_subnets.insert(subnet);
        self
    }

    pub fn proof_cache_size(mut self, size: usize) -> Self {
        self.proof_cache_size = Some(size);
        self
    }

    pub fn proof_request_timeout(mut self, timeout: Duration) -> Self {
        self.proof_request_timeout = Some(timeout);
        self
    }

    pub fn gossip_grace_period(mut self, period: Duration) -> Self {
        self.gossip_grace_period = Some(period);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<ZKVMExecutionLayerConfig, String> {
        let config = ZKVMExecutionLayerConfig {
            subscribed_subnets: self.subscribed_subnets,
            min_proofs_required: self.min_proofs_required.unwrap_or(1),
            generation_subnets: self.generation_subnets,
            proof_cache_size: self.proof_cache_size.unwrap_or(1024),
            proof_request_timeout: self
                .proof_request_timeout
                .unwrap_or_else(|| DEFAULT_PROOF_REQUEST_TIMEOUT),
            gossip_grace_period: self
                .gossip_grace_period
                .unwrap_or_else(|| DEFAULT_GOSSIP_GRACE_PERIOD),
        };

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = ZKVMExecutionLayerConfig::default();
        // Default config should fail validation due to no subnets subscribed to
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_valid_config() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .min_proofs_required(2)
            .build();

        assert!(config.is_ok());
    }

    #[test]
    fn test_min_proofs_too_high() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(2) // Requires 2 but only subscribed to 1 subnet
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_generation_subnet_not_subscribed() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_generation_subnet(subnet_1) // Generate for subnet 1 but not subscribed
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_valid_config_with_generation() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .add_generation_subnet(subnet_0)
            .min_proofs_required(1)
            .proof_cache_size(512)
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.subscribed_subnets.len(), 2);
        assert_eq!(config.generation_subnets.len(), 1);
        assert_eq!(config.min_proofs_required, 1);
        assert_eq!(config.proof_cache_size, 512);
    }

    #[test]
    fn test_min_proofs_required_zero() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(0) // Invalid: must be > 0
            .build();

        assert!(config.is_err());
    }
}
