CREATE TABLE suboptimal_attestations (
    epoch_start_slot integer REFERENCES canonical_slots(slot) ON DELETE CASCADE,
    index integer NOT NULL REFERENCES validators(index) ON DELETE CASCADE,
    source boolean NOT NULL,
    head boolean NOT NULL,
    target boolean NOT NULL,
    PRIMARY KEY(epoch_start_slot, index)
)
