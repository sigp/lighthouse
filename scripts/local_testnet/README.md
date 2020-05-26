# Simple Local Testnet

These scripts allow for running a small local testnet with two beacon nodes and
one validator client. This setup can be useful for testing and development.

## Requirements

The scripts require `lci` and `lighthouse` to be installed on `PATH`. From the
root of this repository, run:

```bash
cargo install --path lighthouse --force --locked
cargo install --path lcli --force --locked
```

## Starting the testnet

Assuming you are happy with the configuration in `var.env`, create the testnet
directory, genesis state and validator keys with:

```bash
./setup
```

Start the first beacon node:

```bash
./beacon_node
```

In a new terminal, start the validator client which will attach to the first
beacon node:

```bash
./validator_client
```

In a new terminal, start the second beacon node which will peer with the first:

```bash
./second_beacon_node
```

## Additional Info

### Debug level

The beacon nodes and validator client have their `--debug-level` set to `info`.
Specify a different debug level like this:

```bash
./validator_client debug
./beacon_node trace
./second_beacon_node warn
```

### Starting fresh

Delete the current testnet and all related files using:

```bash
./clean
```


### Updating the genesis time of the beacon state

If it's been a while since you ran `./setup` then the genesis time of the
genesis state will be far in the future, causing lots of skip slots.

Update the genesis time to now using:

```bash
./reset_genesis_time
```

> Note: you probably want to drop the beacon node database and the validator
> client slashing database if you do this. When using small validator counts
> it's probably easy to just use `./clean && ./setup`.
