use lean_consensus::attestation::SignedAttestation;
use lean_consensus::attestation::Checkpoint;
use lean_consensus::lean_block::LeanBlock;
use lean_consensus::lean_state::LeanState;
use std::collections::HashMap;
use types::{EthSpec, Hash256};

pub struct LeanStore<E: EthSpec> {
    blocks: HashMap<Hash256, LeanBlock<E>>,
    block_states: HashMap<Hash256, LeanState<E>>,

    latest_know_attestations: HashMap<u64, SignedAttestation>,
    latest_new_attestations: HashMap<u64, SignedAttestation>,

    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,

    genesis_root: Hash256,
}
