#![cfg(all(feature = "ef_tests", feature = "spec-minimal"))]

mod pq_support;

use ef_tests::{
    ComputeColumnsForCustodyGroupHandler, FastConfirmationHandler, ForkChoiceHandler,
    GetCustodyGroupsHandler, GossipValidationHandler,
};
use types::MinimalEthSpec;

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_compute_columns_for_custody_group() {
    pq_support::run_handler(ComputeColumnsForCustodyGroupHandler::<MinimalEthSpec>::default());
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_get_custody_groups() {
    pq_support::run_handler(GetCustodyGroupsHandler::<MinimalEthSpec>::default());
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_attester_slashing() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_attester_slashing",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_beacon_aggregate_and_proof() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_beacon_aggregate_and_proof",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_beacon_attestation() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_beacon_attestation",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_beacon_block() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_beacon_block",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_data_column_sidecar() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_data_column_sidecar",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_execution_payload_bid() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_execution_payload_bid",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_execution_payload_envelope() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_execution_payload_envelope",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_partial_data_column_sidecar() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_partial_data_column_sidecar",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_payload_attestation_message() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_payload_attestation_message",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_proposer_preferences() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_proposer_preferences",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn networking_gossip_proposer_slashing() {
    pq_support::run_handler(GossipValidationHandler::<MinimalEthSpec>::new(
        "gossip_proposer_slashing",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_ex_ante() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new("ex_ante"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_filter_node_tree_variants() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new(
        "filter_node_tree_variants",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_get_head() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new("get_head"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_get_parent_payload_status() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new(
        "get_parent_payload_status",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_on_attestation() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new("on_attestation"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_on_block() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new("on_block"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_on_execution_payload_envelope() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new(
        "on_execution_payload_envelope",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_on_payload_attestation_message() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new(
        "on_payload_attestation_message",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_payload_data_availability() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new(
        "payload_data_availability",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_payload_timeliness() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new(
        "payload_timeliness",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_reorg() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new("reorg"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_should_apply_proposer_boost() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new(
        "should_apply_proposer_boost",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fork_choice_withholding() {
    pq_support::run_handler(ForkChoiceHandler::<MinimalEthSpec>::new("withholding"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_basic() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new("basic"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_current_epoch() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new(
        "current_epoch",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_empty_slots() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new(
        "empty_slots",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_ffg() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new("ffg"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_is_one_confirmed() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new(
        "is_one_confirmed",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_previous_epoch() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new(
        "previous_epoch",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_reconfirmation() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new(
        "reconfirmation",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_restart_gu() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new("restart_gu"));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_revert_finality() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new(
        "revert_finality",
    ));
}

#[test]
#[ignore = "requires the explicitly selected PQ reference artifact"]
fn fast_confirmation_variables() {
    pq_support::run_handler(FastConfirmationHandler::<MinimalEthSpec>::new("variables"));
}
