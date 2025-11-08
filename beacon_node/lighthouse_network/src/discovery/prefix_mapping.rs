use alloy_primitives::U256;
use discv5::enr::NodeId;
use std::collections::HashMap;
use types::{ChainSpec, SubnetId};

/// Provides prefixed `NodeId`s with prefixes, which are computed based on the given `SubnetId`.
/// These prefixed `NodeId`s are used for prefix searching during discovery.
pub(crate) struct PrefixMapping {
    chain_spec: ChainSpec,
    /// A mapping of `SubnetId` to prefixes.
    mapping: HashMap<SubnetId, Vec<i32>>,
}

impl PrefixMapping {
    pub fn new(chain_spec: ChainSpec) -> Self {
        Self {
            mapping: SubnetId::compute_attestation_subnet_prefix_mapping(&chain_spec),
            chain_spec,
        }
    }

    /// Returns random `NodeId`s with the prefix that should be subscribed to the given `SubnetId`.
    pub fn get_prefixed_node_ids(&self, subnet_id: &SubnetId) -> Result<Vec<NodeId>, &'static str> {
        let prefix_bits = self.chain_spec.attestation_subnet_prefix_bits as u32;

        // The `mask` is used in a bitwise operation to replace a specific segment of the NodeId
        // with the subnet prefix bits.
        // This variable indicates which segment of the NodeId should be replaced with the subnet
        // prefix bits.
        let mask = U256::from(2_i32.pow(prefix_bits) - 1) << (256 - prefix_bits);

        Ok(self
            .mapping
            .get(subnet_id)
            .ok_or("No prefix mapping for subnet_id")?
            .iter()
            .map(|prefix| {
                // Generate a random NodeId and replace the first few bits with the prefix.
                let random_node_id = U256::from_be_bytes(NodeId::random().raw());
                let prefixed_node_id = U256::from(*prefix) << (256 - prefix_bits);

                // Replace the first few bits of the random NodeID with the prefix. The bits that we
                // want to replace are identified by the `mask`.
                let raw_node_id: [u8; 32] =
                    (random_node_id ^ ((random_node_id ^ prefixed_node_id) & mask)).to_be_bytes();

                NodeId::from(raw_node_id)
            })
            .collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use std::collections::HashSet;

    // Test that `get_target_node_ids` returns prefixed random `NodeId`s.
    #[test]
    fn test_get_prefixed_node_ids() {
        let spec = ChainSpec::mainnet();
        let prefix_mapping = PrefixMapping::new(spec.clone());

        for target_subnet_id in (0..spec.attestation_subnet_count).map(SubnetId::new) {
            let node_ids = prefix_mapping
                .get_prefixed_node_ids(&target_subnet_id)
                .unwrap();
            assert!(!node_ids.is_empty());

            // Test that the `NodeId`s are correctly prefixed.
            for node_id in node_ids.clone() {
                let mut computed_subnet_ids =
                    SubnetId::compute_attestation_subnets(node_id.raw(), &spec);
                assert!(computed_subnet_ids.contains(&target_subnet_id));
            }

            // Test that the `NodeId`s are randomized, excluding its subnet prefix.
            let mut check_uniqueness = HashSet::new();
            for node_id in node_ids {
                let node_id_segment = U256::from_be_bytes(node_id.raw())
                    << spec.attestation_subnet_prefix_bits as u32;
                assert_ne!(node_id_segment, U256::from(0));
                assert!(check_uniqueness.insert(node_id_segment));
            }
        }
    }

    // Test that `get_target_node_ids` returns an `Err` if the given `subnet_id` is invalid.
    #[test]
    fn test_get_prefixed_node_ids_error() {
        let spec = ChainSpec::mainnet();
        let prefix_mapping = PrefixMapping::new(spec.clone());
        let subnet_id = SubnetId::new(spec.attestation_subnet_count);
        let node_ids = prefix_mapping.get_prefixed_node_ids(&subnet_id);
        assert!(node_ids.is_err());
    }
}
