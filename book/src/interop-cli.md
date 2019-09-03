# Interop CLI Overview

The Lighthouse CLI has two primary tasks:

- **Resuming** an existing database with `$ ./beacon_node`.
- **Creating** a new testnet database using `$ ./beacon_node testnet`.

_See [Scenarios](./interop-scenarios.md) for methods we're likely to use
during interop._

## Creating a new database

There are several methods for creating a new beacon node database:

- `quick`: using the `(validator_client, genesis_time)` tuple.
- `recent`: as above but `genesis_time` is set to the start of some recent time
	window.
- `file`: loads the genesis file from disk in one of multiple formats.
- `bootstrap`: a Lighthouse-specific method where we connect to a running node
	and download it's specification and genesis state via the HTTP API.

See `$ ./beacon_node testnet --help` for more detail.

## Resuming from an existing database

Once a database has been created, it can be resumed by running `$ ./beacon_node`.

Presently, this command will fail if no existing database is found. You must
use the `$ ./beacon_node testnet` command to create a new database.
