# Simple Local Testnet

These scripts allow for running a small local testnet that executes merge.

POS activation happens around block 400 and takes about 7 minutes to get to.
You'll see POS Activated panda banner in beacon node logs.

## Requirements

The scripts require `lcli` and `lighthouse` to be installed on `PATH`. From the
root of this repository, run:

```bash
make
make install-lcli
```

The scripts require geth and bootnode binaries.
`GETH_BIN_DIR` is set in `vars.env`.

## Starting the testnet

Modify `vars.env` as desired.

Start a local eth1 ganache server plus boot node along with `BN_COUNT`
number of beacon nodes and `VC_COUNT` validator clients.

The `start_local_testnet.sh` script takes three options `-v VC_COUNT`, `-d DEBUG_LEVEL` and `-h` for help.
The options may be in any order or absent in which case they take the default value specified.

-   VC_COUNT: the number of validator clients to create, default: `BN_COUNT`
-   DEBUG_LEVEL: one of { error, warn, info, debug, trace }, default: `info`

```bash
./start_local_testnet.sh
```

## Stopping the testnet

This is not necessary before `start_local_testnet.sh` as it invokes `stop_local_testnet.sh` automatically.

```bash
./stop_local_testnet.sh
```

## Additional Info

### Adjusting number and distribution of validators

The `VALIDATOR_COUNT` parameter is used to specify the number of insecure validator keystores to generate and make deposits for.
The `BN_COUNT` parameter is used to adjust the division of these generated keys among separate validator client instances.
For e.g. for `VALIDATOR_COUNT=80` and `BN_COUNT=4`, the validator keys are distributed over 4 datadirs with 20 keystores per datadir. The datadirs are located in `$DATADIR/node_{i}` which can be passed to separate validator client
instances using the `--datadir` parameter.

### Starting fresh

Delete the current testnet and all related files using. Generally not necessary as `start_local_test.sh` does this each time it starts.

```bash
./clean.sh
```

### Updating the genesis time of the beacon state

If it's been a while since you ran `./setup` then the genesis time of the
genesis state will be far in the future, causing lots of skip slots.

Update the genesis time to now using:

```bash
./reset_genesis_time.sh
```

> Note: you probably want to just rerun `./start_local_testnet.sh` to start over
> but this is another option.
