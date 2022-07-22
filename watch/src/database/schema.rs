// @generated automatically by Diesel CLI.

diesel::table! {
    beacon_blocks (root) {
        root -> Bytea,
        parent_root -> Bytea,
        slot -> Int4,
    }
}

diesel::table! {
    block_packing (block_root) {
        block_root -> Bytea,
        slot -> Int4,
        available -> Int4,
        included -> Int4,
        prior_skip_slots -> Int4,
    }
}

diesel::table! {
    block_rewards (block_root) {
        block_root -> Bytea,
        slot -> Int4,
        total -> Int4,
        attestation_reward -> Int4,
        sync_committee_reward -> Int4,
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
    proposer_info (block_root) {
        block_root -> Bytea,
        slot -> Int4,
        proposer_index -> Int4,
        graffiti -> Text,
    }
}

diesel::table! {
    validators (id) {
        id -> Int4,
        validator_index -> Int4,
        public_key -> Bytea,
    }
}

diesel::joinable!(block_packing -> beacon_blocks (block_root));
diesel::joinable!(block_rewards -> beacon_blocks (block_root));
diesel::joinable!(proposer_info -> beacon_blocks (block_root));

diesel::allow_tables_to_appear_in_same_query!(
    beacon_blocks,
    block_packing,
    block_rewards,
    canonical_slots,
    proposer_info,
    validators,
);
