CREATE TABLE validators (
    index integer PRIMARY KEY,
    public_key bytea NOT NULL,
    status text NOT NULL,
    balance bigint NOT NULL,
    activation_epoch integer NOT NULL,
    exit_epoch integer
)
