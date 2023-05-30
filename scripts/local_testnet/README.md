# Simple Local Testnet

These scripts allow for running a small local testnet with multiple beacon nodes and validator clients and a geth execution client.
This setup can be useful for testing and development.

## Requirements

The scripts require `lcli`, `lighthouse`, `geth`, `bootnode` to be installed on `PATH`.


MacOS users need to install GNU `sed` and GNU `grep`, and add them both to `PATH` as well.

From the
root of this repository, run:

```bash
make
make install-lcli
```

## Starting the testnet

Modify `vars.env` as desired.

The testnet starts with a post-merge genesis state. 
Start a consensus layer and execution layer boot node along with `BN_COUNT`
number of beacon nodes each connected to a geth execution client and `VC_COUNT` validator clients.

The `start_local_testnet.sh` script takes four options `-v VC_COUNT`, `-d DEBUG_LEVEL`, `-p` to enable builder proposals and `-h` for help. It also takes a mandatory `GENESIS_FILE` for initialising geth's state.
A sample `genesis.json` is provided in this directory.

The `ETH1_BLOCK_HASH` environment variable is set to the block_hash of the genesis execution layer block which depends on the contents of `genesis.json`. Users of these scripts need to ensure that the `ETH1_BLOCK_HASH` variable is updated if genesis file is modified.

The options may be in any order or absent in which case they take the default value specified.
- VC_COUNT: the number of validator clients to create, default: `BN_COUNT`
- DEBUG_LEVEL: one of { error, warn, info, debug, trace }, default: `info`



```bash
./start_local_testnet.sh genesis.json
```

## Stopping the testnet

This is not necessary before `start_local_testnet.sh` as it invokes `stop_local_testnet.sh` automatically.
```bash
./stop_local_testnet.sh
```

## Manual creation of local testnet

These scripts are used by ./start_local_testnet.sh and may be used to manually

Assuming you are happy with the configuration in `vars.env`,
create the testnet directory, genesis state with embedded validators and validator keys with:

```bash
./setup.sh
```

Note: The generated genesis validators are embedded into the genesis state as genesis validators and hence do not require manual deposits to activate.

Generate bootnode enr and start an EL and CL bootnode so that multiple nodes can find each other
```bash
./bootnode.sh
./el_bootnode.sh
```

Start a geth node:
```bash
./geth.sh <DATADIR> <NETWORK-PORT> <HTTP-PORT> <AUTH-HTTP-PORT> <GENESIS_FILE>
```
e.g.
```bash
./geth.sh $HOME/.lighthouse/local-testnet/geth_1 5000 6000 7000 genesis.json
```

Start a beacon node:

```bash
./beacon_node.sh <DATADIR> <NETWORK-PORT> <HTTP-PORT> <EXECUTION-ENDPOINT> <EXECUTION-JWT-PATH> <OPTIONAL-DEBUG-LEVEL>
```
e.g.
```bash
./beacon_node.sh $HOME/.lighthouse/local-testnet/node_1 9000 8000 http://localhost:6000 ~/.lighthouse/local-testnet/geth_1/geth/jwtsecret
```

In a new terminal, start the validator client which will attach to the first
beacon node:

```bash
./validator_client.sh <DATADIR> <BEACON-NODE-HTTP> <OPTIONAL-DEBUG-LEVEL>
```
e.g. to attach to the above created beacon node
```bash
./validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:8000
```

You can create additional beacon node and validator client instances with appropriate parameters.

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
