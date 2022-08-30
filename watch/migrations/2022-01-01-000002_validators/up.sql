CREATE TABLE validators (
    index integer PRIMARY KEY,
    public_key bytea NOT NULL,
    status text NOT NULL,
    client text,
    activation_epoch integer,
    exit_epoch integer
)
