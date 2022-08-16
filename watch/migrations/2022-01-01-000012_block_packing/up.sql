CREATE TABLE block_packing (
    slot integer PRIMARY KEY REFERENCES beacon_blocks(slot) ON DELETE CASCADE,
    available integer NOT NULL,
    included integer NOT NULL,
    prior_skip_slots integer NOT NULL
)
