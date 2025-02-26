CREATE TABLE suboptimal_attestations (
    epoch_start_slot integer CHECK (epoch_start_slot % 32 = 0) REFERENCES canonical_slots(slot) ON DELETE CASCADE,
    index integer NOT NULL REFERENCES validators(index) ON DELETE CASCADE,
    source boolean NOT NULL,
    head boolean NOT NULL,
    target boolean NOT NULL,
    PRIMARY KEY(epoch_start_slot, index)
)
