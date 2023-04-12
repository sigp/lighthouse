CREATE TABLE active_config (
    id integer PRIMARY KEY CHECK (id=1),
    config_name text NOT NULL,
    slots_per_epoch integer NOT NULL
)
