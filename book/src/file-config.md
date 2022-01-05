# File Config

The `lighthouse` binary provides all necessary Ethereum 2.0 functionality. It
has two primary sub-commands:

- `$ lighthouse beacon_node`: the largest and most fundamental component which connects to
  the p2p network, processes messages and tracks the head of the beacon
  chain.
- `$ lighthouse validator_client`: a lightweight but important component which loads a validators private
  key and signs messages using a `beacon_node` as a source-of-truth.

There are also some ancillary binaries like `lcli` and `account_manager`, but
these are primarily for testing.

## Documentation

Each binary supports the `--help` flag, this is the best source of
documentation.

```bash
$ lighthouse beacon_node --help
```

```bash
$ lighthouse validator_client --help
```
- a flag will be enabled if any value is set for it in the config file.
- if a flag is set in a config file, it can not be overridden to false via command line arguments.

```yaml
port: 8000
debug-level: "debug"
http: true
http-port: 6052
eth1-endpoints: "http://localhost:8545,http://localhost:9545"
```

Note: all `TOML` values must be set as strings.

```toml
port = "8000"
debug-level = "debug"
http = "true"
http-port = "6052"
eth1-endpoints = "http://localhost:8545,http://localhost:9545"
```