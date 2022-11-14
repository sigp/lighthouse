CREATE TABLE beacon_blocks (
    slot integer PRIMARY KEY REFERENCES canonical_slots(slot) ON DELETE CASCADE,
    root bytea REFERENCES canonical_slots(beacon_block) NOT NULL,
    parent_root bytea NOT NULL,
    attestation_count integer NOT NULL,
    transaction_count integer
)
