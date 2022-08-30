## beacon.watch

>beacon.watch is pre-MVP and still under active development and subject to change.

> beacon.watch will be experimental at least until
[Diesel](https://github.com/diesel-rs/diesel/) stabilizes on v2.0.0.

beacon.watch is an Ethereum Beacon Chain monitoring platform whose goal is to provide fast access to
data which is:
1. Not already stored natively in the Beacon Chain
2. Too specialized for Block Explorers
3. Too sensitive for public Block Explorers


### Requirements
- `git`
- `rust` : https://rustup.rs/
- `libpg` : https://www.postgresql.org/download/
- `diesel_cli` v2.0.0 :
```
cargo install diesel_cli --git https://github.com/diesel-rs/diesel/ --branch master --no-default-features --features postgres
```
- `docker` : https://docs.docker.com/engine/install/
- `docker-compose` : https://docs.docker.com/compose/install/

### Setup
1. Setup the database:
```
cd postgres_docker_compose
docker-compose up
```

1. Ensure the tests pass:
```
cargo test --release
```

1. Drop the database (if it already exists) and run the required migrations:
```
diesel database reset --database-url postgres://postgres:postgres@localhost/dev
```

1. Ensure a synced Lighthouse beacon node with historical states is available
at `localhost:5052`.
The smaller the value of `--slots-per-restore-point` the faster beacon.watch
will be able to sync to the beacon node.

1. Run the updater daemon:
```
cargo run --release -- start-daemon
```

1. Start the HTTP API server:
```
cargo run --release -- serve
```

1. Ensure connectivity:
```
curl "http://localhost:5059/v1/canonical_slots/highest"
```

> Functionality on Windows or MacOS has not been tested.


### Configuration
beacon.watch can be configured through the use of a config file.
Available options can be seen in `config.yaml.default`.

You can specify a config file during runtime:
```
cargo run -- start-daemon --config path/to/config.yaml
```

You can specify only the parts of the config file which you need changed.
Missing values will remain as their defaults.

For example, if you wish to run with default settings but only wish to alter `log_level`
your config file would be:
```yaml
# config.yaml
log_level = "info"
```

### Available Endpoints
As beacon.watch continues to develop, more endpoints will be added.

- `/v1/canonical_slots/`
  - `/v1/canonical_slots/lowest`
  - `/v1/canonical_slots/highest`


- `/v1/beacon_blocks/`
  - `/v1/beacon_blocks/{block_id}`
  - `/v1/beacon_blocks/{block_id}/next`
  - `/v1/beacon_blocks/lowest`
  - `/v1/beacon_blocks/highest`


- `/v1/proposer_info/{block_id}`


- `/v1/block_rewards/{block_id}`


- `/v1/block_packing/{block_id}`


### Future work
- New tables
  - `skip_slots`?


- Rewrite API in [`axum`](https://github.com/tokio-rs/axum)?
- More API endpoints
  - E.g. `/v1/proposer_info?start_epoch={}&end_epoch={}`
  - Use new API design.


- Store the config in the database on first run so that we can warn against unexpected config changes.


- Concurrently backfill and forwards fill, so forwards fill is not bottlenecked by large backfills.


- Better/prettier (async?) logging.


- Connect to a range of beacon_nodes to sync different components concurrently.
Generally, processing certain api queries such as `block_packing` and `attestation_performance` take the longest to sync.


### Architecture
Connection Pooling:
- 1 Pool for Updater (read and write)
- 1 Pool for HTTP Server (should be read only, although not sure if we can enforce this)
