# Simple Local Testnet

These scripts allow for running a small local testnet with multiple beacon nodes and validator clients and a geth execution client.
This setup can be useful for testing and development.

## Requirements

The scripts require `lcli`, `lighthouse`, `geth`, `bootnode` to be installed on `PATH` (run `echo $PATH` to view all `PATH` directories).


MacOS users need to install GNU `sed` and GNU `grep`, and add them both to `PATH` as well.

The first step is to install Rust and dependencies. Refer to the [Lighthouse Book](https://lighthouse-book.sigmaprime.io/installation-source.html#dependencies) for installation. We will also need [jq](https://jqlang.github.io/jq/), which can be installed with `sudo apt install jq`.

Then, we clone the Lighthouse repository:
```bash
cd ~
git clone https://github.com/sigp/lighthouse.git
cd lighthouse
```
We are now ready to build Lighthouse. Run the command:

```bash
make
make install-lcli
```

This will build `lighthouse` and `lcli`. For `geth` and `bootnode`, go to [geth website](https://geth.ethereum.org/downloads) and download the `Geth & Tools`. For example, to download and extract `Geth & Tools 1.13.1`:

```bash
cd ~
curl -LO https://gethstore.blob.core.windows.net/builds/geth-alltools-linux-amd64-1.13.1-3f40e65c.tar.gz
tar xvf geth-alltools-linux-amd64-1.13.1-3f40e65c.tar.gz
```

After extraction, copy `geth` and `bootnode` to the `PATH`. A typical directory is `/usr/local/bin`.

```bash
cd geth-alltools-linux-amd64-1.13.1-3f40e65c
sudo cp geth bootnode /usr/local/bin
```

After that We can remove the downloaded files:

```bash
cd ~
rm -r geth-alltools-linux-amd64-1.13.1-3f40e65c geth-alltools-linux-amd64-1.13.1-3f40e65c.tar.gz
```

We are now ready to start a local testnet.

## Starting the testnet

To start a testnet using the predetermined settings:

```bash
cd ~
cd ./lighthouse/scripts/local_testnet
./start_local_testnet.sh genesis.json
```

This will execute the script and if the testnet setup is successful, you will see "Started!" at the end. 

The testnet starts with a post-merge genesis state. 
The testnet starts a consensus layer and execution layer boot node along with `BN_COUNT`
(the number of beacon nodes) each connected to a geth execution client and `VC_COUNT` (the number of validator clients). By default, `BN_COUNT=4`, `VC_COUNT=4`. 

The `start_local_testnet.sh` script takes four options `-v VC_COUNT`, `-d DEBUG_LEVEL`, `-p` to enable builder proposals and `-h` for help. It also takes a mandatory `GENESIS_FILE` for initialising geth's state.
A sample `genesis.json` is provided in this directory.

The options may be in any order or absent in which case they take the default value specified.
- VC_COUNT: the number of validator clients to create, default: `BN_COUNT`
- DEBUG_LEVEL: one of { error, warn, info, debug, trace }, default: `info`

The `ETH1_BLOCK_HASH` environment variable is set to the block_hash of the genesis execution layer block which depends on the contents of `genesis.json`. Users of these scripts need to ensure that the `ETH1_BLOCK_HASH` variable is updated if genesis file is modified.

To view the beacon, validator client and geth logs:

```bash
tail -f ~/.lighthouse/local-testnet/testnet/beacon_node_1.log
taif -f ~/.lighthouse/local-testnet/testnet/validator_node_1.log
tail -f ~/.lighthouse/local-testnet/testnet/geth_1.log
```

where `beacon_node_1` can be changed to `beacon_node_2`, `beacon_node_3` or `beacon_node_4` to view logs for different beacon nodes. The same applies to validator clients and geth nodes. 

## Stopping the testnet

To stop the testnet, navigate to the directory `cd ~/lighthouse/scripts/local_testnet`, then run the command:

```bash
./stop_local_testnet.sh
```

Once a testnet is stopped, it cannot be continued from where it left off. When the start local testnet command is run, it will start a new local testnet.

## Manual creation of local testnet

In [Starting the testnet](./README.md#starting-the-testnet), the testnet is started automatically with predetermined parameters (database directory, ports used etc).  This section describes some modifications of the local testnet settings, e.g., changing the database directory, or changing the ports used. 


The testnet also contains parameters that are specified in `vars.env`, such as the slot time `SECONDS_PER_SLOT=3` (instead of 12 seconds on mainnet). You may change these parameters to suit your testing purposes. After that, in the `local_testnet` directory, run the following command to create genesis state with embedded validators and validator keys, and also to update the time in `genesis.json`:

```bash
./setup.sh
./setup_time.sh genesis.json
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
./geth.sh $HOME/.lighthouse/local-testnet/geth_1 7001 6001 5001 genesis.json
```

Start a beacon node:

```bash
./beacon_node.sh <DATADIR> <NETWORK-PORT> <QUIC-PORT> <HTTP-PORT> <EXECUTION-ENDPOINT> <EXECUTION-JWT-PATH> <OPTIONAL-DEBUG-LEVEL>
```
e.g.
```bash
./beacon_node.sh $HOME/.lighthouse/local-testnet/node_1 9001 9101 8001 http://localhost:5001 ~/.lighthouse/local-testnet/geth_1/geth/jwtsecret
```

In a new terminal, start the validator client which will attach to the first
beacon node:

```bash
./validator_client.sh <DATADIR> <BEACON-NODE-HTTP> <OPTIONAL-DEBUG-LEVEL>
```
e.g. to attach to the above created beacon node
```bash
./validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:8001
```

You can create additional geth, beacon node and validator client instances by changing the ports, e.g., for a second geth, beacon node and validator client:

```bash
./geth.sh $HOME/.lighthouse/local-testnet/geth_2 7002 6002 5002 genesis.json
./beacon_node.sh $HOME/.lighthouse/local-testnet/node_2 9002 9102 8002 http://localhost:5002 ~/.lighthouse/local-testnet/geth_2/geth/jwtsecret
./validator_client.sh $HOME/.lighthouse/local-testnet/node_2 http://localhost:8002
```

## Additional Info

### Adjusting number and distribution of validators
The `VALIDATOR_COUNT` parameter is used to specify the number of insecure validator keystores to generate and make deposits for.
The `BN_COUNT` parameter is used to adjust the division of these generated keys among separate validator client instances.
For e.g. for `VALIDATOR_COUNT=80` and `BN_COUNT=4`, the validator keys are distributed over 4 datadirs with 20 keystores per datadir. The datadirs are located in `$DATADIR/node_{i}` which can be passed to separate validator client
instances using the `--datadir` parameter.

### Starting fresh

You can delete the current testnet and all related files using the following command. Alternatively, if you wish to start another testnet, doing the steps [Starting the testnet](./README.md#starting-the-testnet) will automatically delete the files and start a fresh local testnet. 

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

### Testing builder flow

1. Add builder URL to `BN_ARGS` in `./vars.env`, e.g. `--builder http://localhost:8650`. Some mock builder server options: 
    - [`mock-relay`](https://github.com/realbigsean/mock-relay)
    - [`dummy-builder`](https://github.com/michaelsproul/dummy_builder)
2. The above mock builders do not support non-mainnet presets as of now, and will require setting `SECONDS_PER_SLOT` and `SECONDS_PER_ETH1_BLOCK` to `12` in `./vars.env`. 
3. Start the testnet with the following command (the `-p` flag enables the validator client `--builder-proposals` flag):
    ```bash
    ./start_local_testnet.sh -p genesis.json
    ```
4. Block production using builder flow will start at epoch 4.
