use std::ops::BitXor;

use super::active_state::ActiveState;
use super::crystallized_state::CrystallizedState;
use super::recent_proposer_record::RecentPropserRecord;
use super::block::Block;
use super::utils::types::Sha256Digest;
use super::utils::logging::Logger;
use super::config::Config;
use super::rlp;

use super::attestors::{
    process_attestations,
    get_attesters_and_proposer
};
use super::ffg::update_ffg_and_crosslink_progress;

pub fn compute_new_active_state(
    cry_state: &CrystallizedState,
    act_state: &ActiveState,
    parent_block: &Block,
    block: &Block,
    config: &Config,
    log: &Logger)
    -> ActiveState
{
    let (attestation_indicies, proposer) = get_attesters_and_proposer(
        &cry_state,
        &act_state,
        &block.skip_count,
        &config,
        &log);
    
    info!(log, "calculated attesters and proposers";
          "attesters_count" => attestation_indicies.len(),
          "proposer_index" => proposer);

    let parent_block_rlp = rlp::encode(parent_block);
    let attesters_option = process_attestations(
        &cry_state.active_validators,
        &attestation_indicies,
        &block.attestation_bitfield,
        &parent_block_rlp.to_vec(),
        &block.attestation_aggregate_sig);

    // TODO: bls verify signature here.
    
    let (partial_crosslinks, ffg_voter_bitfield, total_new_voters) = 
        update_ffg_and_crosslink_progress(
            &cry_state,
            &act_state.partial_crosslinks,
            &act_state.ffg_voter_bitfield,
            &block.shard_aggregate_votes,
            &config);

    let attesters = match attesters_option {
        None => panic!("No attestors available"),
        Some(x) => x
    };

    let proposer = RecentPropserRecord {
        index: proposer,
        randao_commitment: Sha256Digest::zero(),
        balance_delta: (attesters.len() + total_new_voters) as i64
    };

    let height = act_state.height + 1;
    let randao = act_state.randao.bitxor(block.randao_reveal);
    let mut recent_attesters = act_state.recent_attesters.to_vec();
    recent_attesters.extend_from_slice(&attesters);
    let total_skip_count = act_state.total_skip_count + block.skip_count;
    let mut recent_proposers = act_state.recent_proposers.to_vec();
    recent_proposers.push(proposer);

    ActiveState {
        height,
        randao,
        ffg_voter_bitfield,
        recent_attesters,
        partial_crosslinks,
        total_skip_count,
        recent_proposers
    }
}
