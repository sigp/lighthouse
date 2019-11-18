# Command-Line Interface (CLI)

The `lighthouse` binary provides all necessary Ethereum 2.0 functionality. It
has two primary sub-commands:

- `$ lighthouse beacon_node`: the largest and most fundamental component which connects to
	the p2p network, processes messages and tracks the head of the beacon
	chain.
- `$ lighthouse validator_client`: a lightweight but important component which loads a validators private
	key and signs messages using a `beacon_node` as a source-of-truth.

There are also some ancillary binaries like `lcli` and `account_manager`, but
these are primarily for testing.

> **Note:** documentation sometimes uses `$ lighthouse bn` and `$ lighthouse
> vc` instead of the long-form `beacon_node` and `validator_client`. These
> commands are valid on the CLI too.

## Installation

Typical users may install `lighthouse` to `CARGO_HOME` with `cargo install
--path lighthouse` from the root of the repository. See ["Configuring the
`PATH` environment variable"](https://www.rust-lang.org/tools/install) for more
information.

For develeopers, we recommend building Lighthouse using the `$ cargo build --release
--bin lighthouse` command and executing binaries from the
`<lighthouse-repository>/target/release` directory. This is more ergonomic when
modifying and rebuilding regularly.

## Documentation

Each binary supports the `--help` flag, this is the best source of
documentation.


```bash
$ lighthouse beacon_node --help
```

```bash
$ lighthouse validator_client --help
```

## Beacon Node

The `$ lighthouse beacon_node` (or `$ lighthouse bn`) command has two primary
tasks:

- **Resuming** an existing database with `$ lighthouse bn`.
- **Creating** a new testnet database using `$ lighthouse bn testnet`.

## Creating a new database

Use the `$ lighthouse bn testnet` command (see [testnets](./testnets.md) for
more information).

## Resuming from an existing database

Once a database has been created, it can be resumed by running `$ lighthouse bn`.

Presently, you are not allowed to call `$ lighthouse bn` unless you have first
created a database using `$ lighthouse bn testnet`.
