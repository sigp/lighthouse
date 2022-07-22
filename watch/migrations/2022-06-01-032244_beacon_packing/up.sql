CREATE TABLE block_packing (
    block_root bytea PRIMARY KEY REFERENCES beacon_blocks(root) ON DELETE CASCADE,
    slot integer NOT NULL,
    available integer NOT NULL,
    included integer NOT NULL,
    prior_skip_slots integer NOT NULL
)
