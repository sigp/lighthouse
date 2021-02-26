# Simple Local Testnet

These scripts allow for running a small local testnet with multiple beacon nodes and validator clients.
This setup can be useful for testing and development.

## Requirements

The scripts require `lcli` and `lighthouse` to be installed on `PATH`. From the
root of this repository, run:

```bash
make
make install-lcli
```

## Starting the testnet

Start a local eth1 ganache server
```bash
./ganache_test_node.sh
```

Assuming you are happy with the configuration in `var.env`, deploy the deposit contract, make deposits, 
create the testnet directory, genesis state and validator keys with:

```bash
./setup.sh
```

Generate bootnode enr and start a discv5 bootnode
```bash
./bootnode.sh
```

Start a beacon node:

```bash
./beacon_node.sh <DATADIR> <NETWORK-PORT> <HTTP-PORT> <OPTIONAL-DEBUG-LEVEL>
```
e.g.
```bash
./beacon_node.sh $HOME/.lighthouse/local-testnet/node_1 9000 8000
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

In a new terminal, start the second beacon node which will peer with the first:

```bash
./second_beacon_node.sh
```

## Additional Info

### Starting fresh

Delete the current testnet and all related files using:

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

> Note: you probably want to drop the beacon node database and the validator
> client slashing database if you do this. When using small validator counts
> it's probably easy to just use `./clean.sh && ./setup.sh`.
