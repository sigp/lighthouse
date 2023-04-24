CREATE TABLE block_rewards (
    slot integer PRIMARY KEY REFERENCES beacon_blocks(slot) ON DELETE CASCADE,
    total integer NOT NULL,
    attestation_reward integer NOT NULL,
    sync_committee_reward integer NOT NULL
)
