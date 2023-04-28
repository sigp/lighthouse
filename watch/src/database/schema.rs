// @generated automatically by Diesel CLI.

diesel::table! {
    active_config (id) {
        id -> Int4,
        config_name -> Text,
        slots_per_epoch -> Int4,
    }
}

diesel::table! {
    beacon_blocks (slot) {
        slot -> Int4,
        root -> Bytea,
        parent_root -> Bytea,
        attestation_count -> Int4,
        transaction_count -> Nullable<Int4>,
        withdrawal_count -> Nullable<Int4>,
    }
}

diesel::table! {
    block_packing (slot) {
        slot -> Int4,
        available -> Int4,
        included -> Int4,
        prior_skip_slots -> Int4,
    }
}

diesel::table! {
    block_rewards (slot) {
        slot -> Int4,
        total -> Int4,
        attestation_reward -> Int4,
        sync_committee_reward -> Int4,
    }
}

diesel::table! {
    blockprint (slot) {
        slot -> Int4,
        best_guess -> Text,
    }
}

diesel::table! {
    canonical_slots (slot) {
        slot -> Int4,
        root -> Bytea,
        skipped -> Bool,
        beacon_block -> Nullable<Bytea>,
    }
}

diesel::table! {
    proposer_info (slot) {
        slot -> Int4,
        proposer_index -> Int4,
        graffiti -> Text,
    }
}

diesel::table! {
    suboptimal_attestations (epoch_start_slot, index) {
        epoch_start_slot -> Int4,
        index -> Int4,
        source -> Bool,
        head -> Bool,
        target -> Bool,
    }
}

diesel::table! {
    validators (index) {
        index -> Int4,
        public_key -> Bytea,
        status -> Text,
        activation_epoch -> Nullable<Int4>,
        exit_epoch -> Nullable<Int4>,
    }
}

diesel::joinable!(block_packing -> beacon_blocks (slot));
diesel::joinable!(block_rewards -> beacon_blocks (slot));
diesel::joinable!(blockprint -> beacon_blocks (slot));
diesel::joinable!(proposer_info -> beacon_blocks (slot));
diesel::joinable!(proposer_info -> validators (proposer_index));
diesel::joinable!(suboptimal_attestations -> canonical_slots (epoch_start_slot));
diesel::joinable!(suboptimal_attestations -> validators (index));

diesel::allow_tables_to_appear_in_same_query!(
    active_config,
    beacon_blocks,
    block_packing,
    block_rewards,
    blockprint,
    canonical_slots,
    proposer_info,
    suboptimal_attestations,
    validators,
);
