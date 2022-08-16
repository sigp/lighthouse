CREATE TABLE canonical_slots (
    slot integer PRIMARY KEY,
    root bytea NOT NULL,
    skipped boolean NOT NULL,
    beacon_block bytea UNIQUE
)
