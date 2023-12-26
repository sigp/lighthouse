use lighthouse_network::discv5::enr::NodeId;
use std::collections::HashMap;
use types::{ChainSpec, Epoch, EthSpec, SubnetId};

/// Stores mappings of `SubnetId` to `NodeId`s for prefix search.
pub(crate) struct PrefixMapping {
    chain_spec: ChainSpec,
    epoch: Epoch,
    mapping: HashMap<SubnetId, Vec<NodeId>>,
}

impl PrefixMapping {
    pub fn new(spec: ChainSpec) -> Self {
        Self {
            chain_spec: spec,
            epoch: Epoch::new(0),
            mapping: HashMap::new(),
        }
    }

    /// Returns `NodeId`s with the prefix that should be subscribed to the given `SubnetId` and `Epoch`.
    pub fn get_target_nodes<TSpec: EthSpec>(
        &mut self,
        subnet_id: &SubnetId,
        current_epoch: Epoch,
    ) -> Result<Vec<NodeId>, &'static str> {
        if self.epoch != current_epoch {
            // compute prefixes
            let computed_mapping = SubnetId::compute_prefix_mapping_for_epoch::<TSpec>(
                current_epoch,
                &self.chain_spec,
            )?;

            self.mapping = computed_mapping
                .into_iter()
                .map(|(subnet_id, ids)| {
                    // convert `U256`s to `NodeId`s
                    let node_ids = ids
                        .into_iter()
                        .map(|id| {
                            let raw_node_id: [u8; 32] = id.into();
                            NodeId::from(raw_node_id)
                        })
                        .collect::<Vec<_>>();

                    (subnet_id, node_ids)
                })
                .collect();

            self.epoch = current_epoch;
        }

        let node_ids = self
            .mapping
            .get(subnet_id)
            .ok_or("No NodeId in the prefix mapping.")?
            .clone();

        Ok(node_ids)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use types::MainnetEthSpec;

    #[test]
    fn test_get_target_nodes() {
        let mut prefix_mapping = PrefixMapping::new(ChainSpec::mainnet());
        assert_eq!(prefix_mapping.epoch, Epoch::new(0));
        assert_eq!(prefix_mapping.mapping.len(), 0);

        let current_epoch = Epoch::new(54321);
        let node_ids = prefix_mapping
            .get_target_nodes::<MainnetEthSpec>(&SubnetId::new(1), current_epoch)
            .unwrap();
        assert!(!node_ids.is_empty());

        assert_eq!(prefix_mapping.epoch, current_epoch);
        assert_ne!(prefix_mapping.mapping.len(), 0);
    }
}
