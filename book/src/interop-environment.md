# Interop Environment

All that is required for inter-op is a built and tested [development
environment](./setup.md).

## Repositories

You will only require the [sigp/lighthouse](http://github.com/sigp/lighthouse)
library.

To allow for faster build/test iterations we will use the
[`interop`](https://github.com/sigp/lighthouse/tree/interop) branch of
[sigp/lighthouse](https://github.com/sigp/lighthouse/tree/interop) for
September 2019 interop.  **Please use ensure you `git checkout interop` after
cloning the repo.**

## File System

When lighthouse boots, it will create the following
directories:

- `~/.lighthouse`: database and configuration for the beacon node.
- `~/.lighthouse-validator`: database and configuration for the validator
	client.

After building the binaries with `cargo build --release --all`, there will be a
`target/release` directory in the root of the Lighthouse repository. This is
where the `beacon_node` and `validator_client` binaries are located.

You do not need to create any of these directories manually.
