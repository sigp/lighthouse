CREATE TABLE block_rewards (
    block_root bytea PRIMARY KEY REFERENCES beacon_blocks(root) ON DELETE CASCADE,
    slot integer NOT NULL,
    total integer NOT NULL,
    attestation_reward integer NOT NULL,
    sync_committee_reward integer NOT NULL
)
