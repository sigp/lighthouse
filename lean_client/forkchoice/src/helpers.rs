use lean_consensus::attestation::{Checkpoint, SignedAttestation};
use lean_consensus::lean_block::LeanBlock;
use lean_consensus::lean_state::LeanState;
use std::collections::HashMap;
use types::{EthSpec, Hash256};

pub fn get_fork_choice_head<E: EthSpec>(
    blocks: &HashMap<Hash256, LeanBlock<E>>,
    root: Hash256,
    latest_attestations: &HashMap<u64, SignedAttestation>,
    min_score: usize,
) -> Hash256 {
    let mut current_root = root;
    if root == Hash256::ZERO {
        current_root = blocks
            .iter()
            .min_by_key(|(_, block)| block.slot)
            .map(|(hash, _)| *hash)
            .unwrap_or(Hash256::ZERO);
    }

    let mut attestation_weights: HashMap<Hash256, usize> = HashMap::new();

    for attestation in latest_attestations.values() {
        let head_root = attestation.message.attestation_data.head.root;
        // Only process attestations that point to known blocks
        if blocks.contains_key(&head_root) {
            // Walk up from attestation target, incrementing ancestor weights
            let mut block_hash = head_root;
            while let Some(block) = blocks.get(&block_hash) {
                if let Some(root_block) = blocks.get(&current_root) {
                    if block.slot <= root_block.slot {
                        break;
                    }
                }

                *attestation_weights.entry(block_hash).or_insert(0) += 1;
                block_hash = block.parent_root;
            }
        }
    }

    let mut children_map: HashMap<Hash256, Vec<Hash256>> = HashMap::new();

    for (block_hash, block) in blocks.iter() {
        if block.parent_root != Hash256::ZERO {
            // Only include blocks that have enough attestations OR when min_score is 0
            let weight = *attestation_weights.get(block_hash).unwrap_or(&0);
            if min_score == 0 || weight >= min_score {
                children_map
                    .entry(block.parent_root)
                    .or_insert_with(Vec::new)
                    .push(*block_hash);
            }
        }
    }

    let mut current = current_root;
    loop {
        let children = children_map.get(&current);

        if children.is_none() || children.unwrap().is_empty() {
            return current;
        }

        current = *children
            .unwrap()
            .iter()
            .max_by_key(|&&block_hash| {
                let weight = *attestation_weights.get(&block_hash).unwrap_or(&0);
                (weight, block_hash)
            })
            .unwrap();
    }
}

pub fn get_latest_justified<E: EthSpec>(
    states: &HashMap<Hash256, LeanState<E>>,
) -> Option<Checkpoint> {
    if states.is_empty() {
        return None;
    }

    let latest_state = states
        .values()
        .max_by_key(|state| state.latest_justified.slot)?;

    Some(latest_state.latest_justified.clone())
}
