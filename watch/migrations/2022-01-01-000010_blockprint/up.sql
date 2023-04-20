CREATE TABLE blockprint (
    slot integer PRIMARY KEY REFERENCES beacon_blocks(slot) ON DELETE CASCADE,
    best_guess text NOT NULL
)
