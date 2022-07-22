CREATE TABLE beacon_blocks (
    root bytea PRIMARY KEY REFERENCES canonical_slots(beacon_block) ON DELETE CASCADE,
    parent_root bytea NOT NULL,
    slot integer NOT NULL
)
