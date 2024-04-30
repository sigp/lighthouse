use super::single_block_lookup::SingleBlockLookup;
use beacon_chain::BeaconChainTypes;
use std::collections::{HashMap, HashSet};
use types::Hash256;

/// Summary of a lookup of which we may not know it's parent_root yet
pub(crate) struct Node {
    block_root: Hash256,
    parent_root: Option<Hash256>,
}

impl<T: BeaconChainTypes> From<&SingleBlockLookup<T>> for Node {
    fn from(value: &SingleBlockLookup<T>) -> Self {
        Self {
            block_root: value.block_root(),
            parent_root: value.awaiting_parent(),
        }
    }
}

/// Wrapper around a chain of block roots that have a least one element (tip)
pub(crate) struct NodeChain {
    // Parent chain blocks in descending slot order
    pub(crate) chain: Vec<Hash256>,
    pub(crate) tip: Hash256,
}

impl NodeChain {
    /// Returns the block_root of the oldest ancestor (min slot) of this chain
    pub(crate) fn ancestor(&self) -> Hash256 {
        self.chain.last().copied().unwrap_or(self.tip)
    }
    pub(crate) fn len(&self) -> usize {
        self.chain.len()
    }
}

/// Given a set of nodes that reference each other, returns a list of chains with unique tips that
/// contain at least two elements. In descending slot order (tip first).
pub(crate) fn compute_parent_chains(nodes: &[Node]) -> Vec<NodeChain> {
    let mut child_to_parent = HashMap::new();
    let mut parent_to_child = HashMap::<Hash256, Vec<Hash256>>::new();
    for node in nodes {
        child_to_parent.insert(node.block_root, node.parent_root);
        if let Some(parent_root) = node.parent_root {
            parent_to_child
                .entry(parent_root)
                .or_default()
                .push(node.block_root);
        }
    }

    let mut parent_chains = vec![];

    // Iterate blocks with no children
    for tip in nodes {
        let mut block_root = tip.block_root;
        if parent_to_child.get(&block_root).is_none() {
            let mut chain = vec![];

            // Resolve chain of blocks
            while let Some(parent_root) = child_to_parent.get(&block_root) {
                // block_root is a known block that may or may not have a parent root
                chain.push(block_root);
                if let Some(parent_root) = parent_root {
                    block_root = *parent_root;
                } else {
                    break;
                }
            }

            if chain.len() > 1 {
                parent_chains.push(NodeChain {
                    chain,
                    tip: tip.block_root,
                });
            }
        }
    }

    parent_chains
}

/// Given a list of node chains, find the oldest node of a specific chain that is not contained in
/// any other chain.
pub(crate) fn find_oldest_fork_ancestor(
    parent_chains: Vec<NodeChain>,
    chain_idx: usize,
) -> Result<Hash256, &'static str> {
    let mut other_blocks = HashSet::new();

    // Register blocks from other chains
    for (i, parent_chain) in parent_chains.iter().enumerate() {
        if i != chain_idx {
            for block in &parent_chain.chain {
                other_blocks.insert(block);
            }
        }
    }

    // Should never happen
    let parent_chain = parent_chains
        .get(chain_idx)
        .ok_or("chain_idx out of bounds")?;
    // Find the first block in the target parent chain that is not in other parent chains
    // Iterate in ascending slot order
    for block in parent_chain.chain.iter().rev() {
        if !other_blocks.contains(block) {
            return Ok(*block);
        }
    }

    // No match means that the chain is fully contained within another chain. This should never
    // happen, but if that was the case just return the tip
    Ok(parent_chain.tip)
}

#[cfg(test)]
mod tests {
    use super::{compute_parent_chains, find_oldest_fork_ancestor, Node};
    use types::Hash256;

    fn h(n: u64) -> Hash256 {
        Hash256::from_low_u64_be(n)
    }

    fn n(block: u64) -> Node {
        Node {
            block_root: h(block),
            parent_root: None,
        }
    }

    fn np(parent: u64, block: u64) -> Node {
        Node {
            block_root: h(block),
            parent_root: Some(h(parent)),
        }
    }

    fn compute_parent_chains_test(nodes: &[Node], expected_chain: Vec<Vec<Hash256>>) {
        assert_eq!(
            compute_parent_chains(nodes)
                .iter()
                .map(|c| c.chain.clone())
                .collect::<Vec<_>>(),
            expected_chain
        );
    }

    fn find_oldest_fork_ancestor_test(nodes: &[Node], expected: Hash256) {
        let chains = compute_parent_chains(nodes);
        println!(
            "chains {:?}",
            chains.iter().map(|c| &c.chain).collect::<Vec<_>>()
        );
        assert_eq!(find_oldest_fork_ancestor(chains, 0).unwrap(), expected);
    }

    #[test]
    fn compute_parent_chains_empty_case() {
        compute_parent_chains_test(&[], vec![]);
    }

    #[test]
    fn compute_parent_chains_single_branch() {
        compute_parent_chains_test(&[n(0), np(0, 1), np(1, 2)], vec![vec![h(2), h(1), h(0)]]);
    }

    #[test]
    fn compute_parent_chains_single_branch_with_solo() {
        compute_parent_chains_test(
            &[n(0), np(0, 1), np(1, 2), np(3, 4)],
            vec![vec![h(2), h(1), h(0)]],
        );
    }

    #[test]
    fn compute_parent_chains_two_forking_branches() {
        compute_parent_chains_test(
            &[n(0), np(0, 1), np(1, 2), np(1, 3)],
            vec![vec![h(2), h(1), h(0)], vec![h(3), h(1), h(0)]],
        );
    }

    #[test]
    fn compute_parent_chains_two_independent_branches() {
        compute_parent_chains_test(
            &[n(0), np(0, 1), np(1, 2), n(3), np(3, 4)],
            vec![vec![h(2), h(1), h(0)], vec![h(4), h(3)]],
        );
    }

    #[test]
    fn find_oldest_fork_ancestor_simple_case() {
        find_oldest_fork_ancestor_test(&[n(0), np(0, 1), np(1, 2), np(0, 3)], h(1))
    }
}
