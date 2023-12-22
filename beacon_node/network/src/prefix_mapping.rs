use lighthouse_network::discv5::enr::NodeId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use types::{ChainSpec, Epoch, EthSpec, SubnetId};

/// Stores mappings of `SubnetId` to `NodeId`s.
pub(crate) struct PrefixMapping {
    chain_spec: ChainSpec,
    mappings: HashMap<Epoch, HashMap<SubnetId, Vec<NodeId>>>,
}

impl PrefixMapping {
    pub fn new(spec: ChainSpec) -> Self {
        Self {
            chain_spec: spec,
            mappings: HashMap::new(),
        }
    }

    /// Returns `NodeId` with the prefix that should be subscribed to the given `SubnetId`.
    pub fn get<TSpec: EthSpec>(
        &mut self,
        subnet_id: &SubnetId,
        current_epoch: Epoch,
    ) -> Result<Vec<NodeId>, &'static str> {
        let (node_ids, vacant) = match self.mappings.entry(current_epoch) {
            Entry::Occupied(entry) => {
                let mapping = entry.get();
                let node_ids = mapping
                    .get(subnet_id)
                    .ok_or("No NodeId in the prefix mapping.")?
                    .clone();
                (node_ids, false)
            }
            Entry::Vacant(entry) => {
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
                let mapping = entry.insert(mapping);
                let node_ids = mapping
                    .get(subnet_id)
                    .ok_or("No NodeId in the prefix mapping.")?
                    .clone();
                (node_ids, true)
            }
        };

        // Remove expired mappings
        if vacant {
            self.mappings.retain(|epoch, _| epoch >= &current_epoch);
        }

        Ok(node_ids)
    }
}
