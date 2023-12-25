use lighthouse_network::discv5::enr::NodeId;
use std::collections::HashMap;
use types::{ChainSpec, Epoch, EthSpec, SubnetId};

/// Stores mappings of `SubnetId` to `NodeId`s.
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

    /// Returns `NodeId` with the prefix that should be subscribed to the given `SubnetId`.
    pub fn get<TSpec: EthSpec>(
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

            // convert `U256`s to `NodeId`s
            let mut mapping = HashMap::new();
            for (subnet_id, ids) in computed_mapping {
                mapping.insert(
                    subnet_id,
                    ids.into_iter()
                        .map(|id| {
                            let raw_node_id: [u8; 32] = id.into();
                            NodeId::from(raw_node_id)
                        })
                        .collect::<Vec<_>>(),
                );
            }

            self.mapping = mapping;
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
