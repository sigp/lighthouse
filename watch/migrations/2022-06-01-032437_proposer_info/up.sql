CREATE TABLE proposer_info (
    block_root bytea PRIMARY KEY REFERENCES beacon_blocks(root) ON DELETE CASCADE,
    slot integer NOT NULL,
    proposer_index integer NOT NULL,
    graffiti text NOT NULL
)
