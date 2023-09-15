CREATE TABLE proposer_info (
    slot integer PRIMARY KEY REFERENCES beacon_blocks(slot) ON DELETE CASCADE,
    proposer_index integer REFERENCES validators(index) ON DELETE CASCADE NOT NULL,
    graffiti text NOT NULL
)
