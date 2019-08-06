# Lighthouse Documentation

_Lighthouse is a work-in-progress. Instructions are provided for running the
client, however these instructions are designed for developers and researchers
working on the project. We do not (yet) provide user-facing functionality._

## Introduction

- [Overview of Ethereum 2.0](serenity.md)
- [Development Environment Setup](env.md)

For client implementers looking to inter-op, see the [Inter-Op
Docs](interop.md).

## Command-line Interface

With the [development environment](env.md) configured, run `cargo build --all
--release` (this can take several minutes on the first build). Then,
navigate to the `target/release/` directory and read the CLI documentation
using:

```
$ ./beacon_node -h
```

The main [`README.md`](../README.md#simple-local-testnet) provides instructions
for running a small, local testnet.

## REST API

The beacon node provides a RESTful HTTP API which serves information about the
Beacon Chain, the P2P network and more.

This API is documented in the [`rest_oapi.yaml`](rest_oapi.yaml) Swagger YAML
file. There's an interactive version hosted on
[SwaggerHub](https://app.swaggerhub.com/apis/spble/lighthouse_rest_api/0.1.0).

The implementation of the Swagger API in Lighthouse is incomplete, we do not
(yet) guarantee that all routes are implemented.

## Configuration Files

Lighthouse uses [TOML](https://github.com/toml-lang/toml) files for
configuration. The following binaries use the following config files (they are
generated from defaults if they don't already exist):

- [Beacon Node](/beacon_node)
	- [`~/.lighthouse/beacon_node.toml`](#beacon-nodetoml): the primary
		configuration file for a beacon node.
	- `~/.lighthouse/eth2-spec.toml`: defines chain-specific "constants" that
		define an Ethereum 2.0 network.
- [Validator Client](/validator_client)
	- `~/.lighthouse/validator_client.toml`: the primary configuration file for
		a validator client.
	- `~/.lighthouse/eth2-spec.toml`: defines chain-specific "constants" that
		define an Ethereum 2.0 network.

_Note: default directories are shown, CLI flags can be used to override these
defaults._

#### `beacon-node.toml`

A TOML configuration file that defines the behaviour of the beacon node
runtime.

- Located in the `datadir` (default `~/.lighthouse`) as `beacon-node.toml`.
- Created from defaults if not present.

See the [example](config_examples/beacon-node.toml) for more information.
