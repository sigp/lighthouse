use ethereum_types::U256;
use lighthouse_network::discv5::enr::NodeId;
use std::collections::HashMap;
use types::{ChainSpec, Epoch, EthSpec, SubnetId};

/// Provides prefixed `NodeId`s with prefixes, which are computed based on the given `SubnetId` and
/// `Epoch`. These prefixed `NodeId`s are used for prefix searching during discovery.
pub(crate) struct PrefixMapping {
    chain_spec: ChainSpec,
    /// The epoch at which the prefix mapping was computed.
    epoch: Epoch,
    /// A mapping of `SubnetId` to prefixes.
    mapping: HashMap<SubnetId, Vec<i32>>,
}

impl PrefixMapping {
    pub fn new(spec: ChainSpec) -> Self {
        Self {
            chain_spec: spec,
            epoch: Epoch::new(0),
            mapping: HashMap::new(),
        }
    }

    fn get_prefixes<TSpec: EthSpec>(
        &mut self,
        subnet_id: &SubnetId,
        current_epoch: Epoch,
    ) -> Result<Vec<i32>, &'static str> {
        if self.epoch != current_epoch {
            // compute prefix mapping
            self.mapping = SubnetId::compute_prefix_mapping_for_epoch::<TSpec>(
                current_epoch,
                &self.chain_spec,
            )?;

            self.epoch = current_epoch;
        }

        let prefixes = self
            .mapping
            .get(subnet_id)
            .ok_or("No prefix in the mapping.")?
            .clone();

        Ok(prefixes)
    }

    /// Returns random `NodeId`s with the prefix that should be subscribed to the given `SubnetId` and `Epoch`.
    pub fn get_target_nodes<TSpec: EthSpec>(
        &mut self,
        subnet_id: &SubnetId,
        current_epoch: Epoch,
    ) -> Result<Vec<NodeId>, &'static str> {
        let subnet_prefix_bits = self.chain_spec.attestation_subnet_prefix_bits as u32
            + self.chain_spec.attestation_subnet_shuffling_prefix_bits as u32;
        // The `mask` is used in a bitwise operation to replace a specific segment of the NodeId
        // with the subnet prefix bits.
        // This variable indicates which segment of the NodeId should be replaced with the subnet
        // prefix bits.
        let mask = U256::from(2_i32.pow(subnet_prefix_bits) - 1) << (256 - subnet_prefix_bits);

        Ok(self
            .get_prefixes::<TSpec>(subnet_id, current_epoch)?
            .into_iter()
            .map(|prefix| {
                // We generate a random NodeId and replace the first few bits with the prefix.
                let random_node_id = U256::from(NodeId::random().raw());
                let prefixed_node_id = U256::from(prefix) << (256 - subnet_prefix_bits);

                // Replace the first few bits of the random NodeID with the prefix. The bits that we
                // want to replace are identified by the `mask`.
                let raw_node_id: [u8; 32] =
                    (random_node_id ^ ((random_node_id ^ prefixed_node_id) & mask)).into();
                NodeId::from(raw_node_id)
            })
            .collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use itertools::Itertools;
    use std::collections::HashSet;
    use types::MainnetEthSpec;

    #[test]
    fn test_get_prefixes() {
        let mut prefix_mapping = PrefixMapping::new(ChainSpec::mainnet());
        assert_eq!(prefix_mapping.epoch, Epoch::new(0));
        assert_eq!(prefix_mapping.mapping.len(), 0);

        let current_epoch = Epoch::new(54321);
        let prefixes = prefix_mapping
            .get_prefixes::<MainnetEthSpec>(&SubnetId::new(1), current_epoch)
            .unwrap();

        assert!(!prefixes.is_empty());

        assert_eq!(prefix_mapping.epoch, current_epoch);
        assert_ne!(prefix_mapping.mapping.len(), 0);
    }

    #[test]
    fn test_get_target_nodes() {
        let spec = ChainSpec::mainnet();
        let subnet_prefix_bits = spec.attestation_subnet_prefix_bits as u32
            + spec.attestation_subnet_shuffling_prefix_bits as u32;
        let current_epoch = Epoch::new(54321);
        let target_subnet = SubnetId::new(1);
        let mut prefix_mapping = PrefixMapping::new(spec.clone());
        let target_nodes = prefix_mapping
            .get_target_nodes::<MainnetEthSpec>(&target_subnet, current_epoch)
            .unwrap();

        assert!(!target_nodes.is_empty());

        let mut ids = HashSet::new();
        for node_id in target_nodes {
            let raw_node_id = U256::from(node_id.raw());

            // Test that the target node is correctly subscribed to the target_subnet.
            let (mut subnets, _) = SubnetId::compute_subnets_for_epoch::<MainnetEthSpec>(
                raw_node_id,
                current_epoch,
                &spec,
            )
            .unwrap();
            assert!(subnets.contains(&target_subnet));

            // Test that the segment of the node ID, excluding its subnet prefix is randomized.
            let node_id_segment = raw_node_id << subnet_prefix_bits;
            assert_ne!(node_id_segment, U256::from(0));
            assert!(ids.insert(node_id_segment));
        }
    }
}
