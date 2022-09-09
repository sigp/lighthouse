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
curl "http://localhost:5059/v1/slots/highest"
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

#### `/v1/slots/{slot}`
```bash
curl "http://localhost:5059/v1/slots/4635296"
```
```json
{
  "slot": "4635296",
  "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
  "skipped": false,
  "beacon_block": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62"
}
```

#### `/v1/slots/?start_slot={}&end_slot={}`
```bash
curl "http://localhost:5059/v1/slots?start_slot=4635296&end_slot=4635297"
```
```json
[
  {
    "slot": "4635297",
    "root": "0x04ad2e963811207e344bebeba5b1217805bcc3a9e2ed9fcf2205d491778c6182",
    "skipped": false,
    "beacon_block": "0x04ad2e963811207e344bebeba5b1217805bcc3a9e2ed9fcf2205d491778c6182"
  },
  {
    "slot": "4635296",
    "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
    "skipped": false,
    "beacon_block": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62"
  }
]
```

#### `/v1/slots/lowest`
```bash
curl "http://localhost:5059/v1/slots/lowest"
```
```json
{
  "slot": "4635296",
  "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
  "skipped": false,
  "beacon_block": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62"
}
```

#### `/v1/slots/highest`
```bash
curl "http://localhost:5059/v1/slots/highest"
```
```json
{
  "slot": "4635358",
  "root": "0xe9eff13560688f1bf15cf07b60c84963d4d04a4a885ed0eb19ceb8450011894b",
  "skipped": false,
  "beacon_block": "0xe9eff13560688f1bf15cf07b60c84963d4d04a4a885ed0eb19ceb8450011894b"
}
```

#### `v1/slots/{slot}/block`
```bash
curl "http://localhost:5059/v1/slots/4635296/block"
```
```json
{
  "slot": "4635296",
  "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
  "parent_root": "0x7c4860b420a23de9d126da71f9043b3744af98c847efd9e1440f2da8fbf7f31b"
}
```

#### `/v1/blocks/{block_id}`
```bash
curl "http://localhost:5059/v1/blocks/4635296"
# OR
curl "http://localhost:5059/v1/blocks/0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62"
```
```json
{
  "slot": "4635296",
  "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
  "parent_root": "0x7c4860b420a23de9d126da71f9043b3744af98c847efd9e1440f2da8fbf7f31b"
}
```

#### `/v1/blocks?start_slot={}&end_slot={}`
```bash
curl "http://localhost:5059/v1/blocks?start_slot=4635296&end_slot=4635297"
```
```json
[
  {
    "slot": "4635297",
    "root": "0x04ad2e963811207e344bebeba5b1217805bcc3a9e2ed9fcf2205d491778c6182",
    "parent_root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62"
  },
  {
    "slot": "4635296",
    "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
    "parent_root": "0x7c4860b420a23de9d126da71f9043b3744af98c847efd9e1440f2da8fbf7f31b"
  }
]
```

#### `/v1/blocks/{block_id}/previous`
```bash
curl "http://localhost:5059/v1/blocks/4635297/previous"
# OR
curl "http://localhost:5059/v1/blocks/0x04ad2e963811207e344bebeba5b1217805bcc3a9e2ed9fcf2205d491778c6182/previous"
```
```json
{
  "slot": "4635296",
  "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
  "parent_root": "0x7c4860b420a23de9d126da71f9043b3744af98c847efd9e1440f2da8fbf7f31b"
}
```

#### `/v1/blocks/{block_id}/next`
```bash
curl "http://localhost:5059/v1/blocks/4635296/next"
# OR
curl "http://localhost:5059/v1/blocks/0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62/next"
```
```json
{
  "slot": "4635297",
  "root": "0x04ad2e963811207e344bebeba5b1217805bcc3a9e2ed9fcf2205d491778c6182",
  "parent_root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62"
}
```

#### `/v1/blocks/lowest`
```bash
curl "http://localhost:5059/v1/blocks/lowest"
```
```json
{
  "slot": "4635296",
  "root": "0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62",
  "parent_root": "0x7c4860b420a23de9d126da71f9043b3744af98c847efd9e1440f2da8fbf7f31b"
}
```

#### `/v1/blocks/highest`
```bash
curl "http://localhost:5059/v1/blocks/highest"
```
```json
{
  "slot": "4635358",
  "root": "0xe9eff13560688f1bf15cf07b60c84963d4d04a4a885ed0eb19ceb8450011894b",
  "parent_root": "0xb66e05418bb5b1d4a965c994e1f0e5b5f0d7b780e0df12f3f6321510654fa1d2"
}
```

#### `/v1/blocks/{block_id}/proposer`
```bash
curl "http://localhost:5059/v1/blocks/4635296/proposer"
# OR
curl "http://localhost:5059/v1/blocks/0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62/proposer"

```
```json
{
  "slot": "4635296",
  "proposer_index": 223126,
  "graffiti": ""
}
```

#### `/v1/blocks/{block_id}/rewards`
```bash
curl "http://localhost:5059/v1/blocks/4635296/reward"
# OR
curl "http://localhost:5059/v1/blocks/0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62/reward"

```
```json
{
  "slot": "4635296",
  "total": 25380059,
  "attestation_reward": 24351867,
  "sync_committee_reward": 1028192
}
```

#### `/v1/blocks/{block_id}/packing`
```bash
curl "http://localhost:5059/v1/blocks/4635296/packing"
# OR
curl "http://localhost:5059/v1/blocks/0xf7063a9d6c663682e59bd0b41d29ce80c3ff0b089049ff8676d6f9ee79622c62/packing"

```
```json
{
  "slot": "4635296",
  "available": 16152,
  "included": 13101,
  "prior_skip_slots": 0
}
```

#### `/v1/validators/{validator}`
```bash
curl "http://localhost:5059/v1/validators/1"
# OR
curl "http://localhost:5059/v1/validators/0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c"
```
```json
{
  "index": 1,
  "public_key": "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c",
  "status": "active_ongoing",
  "client": null,
  "activation_epoch": 0,
  "exit_epoch": null
}
```

#### `/v1/validators/{validator}/attestation/{epoch}`
```bash
curl "http://localhost:5059/v1/validators/1/attestation/144853"
# OR
curl "http://localhost:5059/v1/validators/0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c/attestation/144853"
```
```json
{
  "index": 1,
  "epoch": "144853",
  "source": true,
  "head": true,
  "target": true
}
```


### Future work
- New tables
  - `skip_slots`?


- More API endpoints
  - E.g. `/v1/proposers?start_epoch={}&end_epoch={}`


- Concurrently backfill and forwards fill, so forwards fill is not bottlenecked by large backfills.


- Better/prettier (async?) logging.


- Connect to a range of beacon_nodes to sync different components concurrently.
Generally, processing certain api queries such as `block_packing` and `attestation_performance` take the longest to sync.


### Architecture
Connection Pooling:
- 1 Pool for Updater (read and write)
- 1 Pool for HTTP Server (should be read only, although not sure if we can enforce this)
