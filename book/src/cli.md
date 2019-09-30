# Command-Line Interface (CLI)

Lighthouse a collection of CLI applications. The two primary binaries are:

- `beacon_node`: the largest and most fundamental component which connects to
	the p2p network, processes messages and tracks the head of the beacon
	chain.
- `validator_client`: a lightweight but important component which loads a validators private
	key and signs messages using a `beacon_node` as a source-of-truth.

There are also some ancillary binaries:

- `account_manager`: generates cryptographic keys.
- `lcli`: a general-purpose utility for troubleshooting Lighthouse state
	transitions (developer tool).

## Installation

Presently, we recommend building Lighthouse using the `$ cargo build --release
--all` command and executing binaries from the
`<lighthouse-repository>/target/release` directory.

## Documentation

Each binary supports the `--help` flag, this is the best source of
documentation.


```bash
$ ./beacon_node --help
```

```bash
$ ./validator_client --help
```

```bash
$ ./account_manager --help
```

```bash
$ ./lcli --help
```

## Beacon Node

The `beacon_node` CLI has two primary tasks:

- **Resuming** an existing database with `$ ./beacon_node`.
- **Creating** a new testnet database using `$ ./beacon_node testnet`.

## Creating a new database

Use the `$./beacon_node testnet` command (see [testnets](./testnets.md) for more
information).

## Resuming from an existing database

Once a database has been created, it can be resumed by running `$ ./beacon_node`.

Presently, this command will fail if no existing database is found. You must
use the `$ ./beacon_node testnet` command to create a new database.
