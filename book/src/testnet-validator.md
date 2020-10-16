# Become a Testnet Validator

Joining an Eth2 testnet is a great way to get familiar with staking in Phase 0.
All users should experiment with a testnet prior to staking mainnet ETH.

## Supported Testnets

Lighthouse supports four testnets:

- [Medalla](https://github.com/goerli/medalla/tree/master/medalla) (default)
- [Zinken](https://github.com/goerli/medalla/tree/master/zinken)
- [Spadina](https://github.com/goerli/medalla/tree/master/spadina) (deprecated)
- [Altona](https://github.com/goerli/medalla/tree/master/altona) (deprecated)

When using Lighthouse, the `--testnet` flag selects a testnet. E.g.,

- `lighthouse` (no flag): Medalla.
- `lighthouse --testnet medalla`: Medalla.
- `lighthouse --testnet zinken`: Zinken.

Using the correct `--testnet` flag is very important; using the wrong flag can
result in penalties, slashings or lost deposits. As a rule of thumb, always
provide a `--testnet` flag instead of relying on the default.

> Note: In these documents we use `--testnet MY_TESTNET` for demonstration. You
> must replace `MY_TESTNET` with a valid testnet name.

## Joining a Testnet

There are five primary steps to become a testnet validator:

1. Create validator keys and submit deposits.
1. Start an Eth1 client.
1. Install Lighthouse.
1. Import the validator keys into Lighthouse.
1. Start Lighthouse.
1. Leave Lighthouse running.

Each of these primary steps has several intermediate steps, so we recommend
setting aside one or two hours for this process.

### Step 1. Create validator keys

The Ethereum Foundation provides an "Eth2 launch pad" for each active testnet:

- [Medalla launchpad](https://medalla.launchpad.ethereum.org/)
- [Zinken launchpad](https://zinken.launchpad.ethereum.org/)

Please follow the steps on the appropriate launch pad site to generate
validator keys and submit deposits. Make sure you select "Lighthouse" as your
client.

Move to the next step once you have completed the steps on the launch pad,
including generating keys via the Python CLI and submitting gETH/ETH deposits.

### Step 2. Start an Eth1 client

Since Eth2 relies upon the Eth1 chain for validator on-boarding, all Eth2 validators must have a connection to an Eth1 node.

We provide instructions for using Geth (the Eth1 client that, by chance, we ended up testing with), but you could use any client that implements the JSON RPC via HTTP. A fast-synced node should be sufficient.

#### Installing Geth

If you're using a Mac, follow the instructions [listed here](https://github.com/ethereum/go-ethereum/wiki/Installation-Instructions-for-Mac) to install geth. Otherwise [see here](https://github.com/ethereum/go-ethereum/wiki/Installing-Geth).

#### Starting Geth

Once you have geth installed, use this command to start your Eth1 node:

```bash
 geth --goerli --http
```

### Step 3. Install Lighthouse

*Note: Lighthouse only supports Windows via WSL.*

Follow the [Lighthouse Installation Instructions](./installation.md) to install
Lighthouse from one of the available options.

Proceed to the next step once you've successfully installed Lighthouse and view
its `--version` info.

> Note: Some of the instructions vary when using Docker, ensure you follow the
> appropriate sections later in this guide.

### Step 4. Import validator keys to Lighthouse

When Lighthouse is installed, follow the [Importing from the Ethereum 2.0 Launch
pad](./validator-import-launchpad.md) instructions so the validator client can
perform your validator duties.

Proceed to the next step once you've successfully imported all validators.

### Step 5. Start Lighthouse

For staking, one needs to run two Lighthouse processes:

- `lighthouse bn`: the "beacon node" which connects to the P2P network and
	verifies blocks.
- `lighthouse vc`: the "validator client" which manages validators, using data
	obtained from the beacon node via a HTTP API.

Starting these processes is different for binary and docker users:

#### Binary users

Those using the pre- or custom-built binaries can start the two processes with:

```bash
lighthouse --testnet MY_TESTNET bn --staking
```

```bash
lighthouse --testnet MY_TESTNET vc
```

> Note: `~/.lighthouse/{testnet}` is the default directory which contains the keys and databases.
> To specify a custom dir, see [this](#custom-directories) section 

#### Docker users

Those using Docker images can start the processes with:

```bash
$ docker run \
	--network host \
	-v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse \
	lighthouse --testnet MY_TESTNET bn --staking --http-address 0.0.0.0
```

```bash
$ docker run \
	--network host \
	-v $HOME/.lighthouse:/root/.lighthouse \
	sigp/lighthouse \
	lighthouse --testnet MY_TESTNET vc
```

### Step 6. Leave Lighthouse running

Leave your beacon node and validator client running and you'll see logs as the
beacon node stays synced with the network while the validator client produces
blocks and attestations.

It will take 4-8+ hours for the beacon chain to process and activate your
validator, however you'll know you're active when the validator client starts
successfully publishing attestations each epoch:

```
Dec 03 08:49:40.053 INFO Successfully published attestation      slot: 98, committee_index: 0, head_block: 0xa208…7fd5,
```

Although you'll produce an attestation each epoch, it's less common to produce a
block. Watch for the block production logs too:

```
Dec 03 08:49:36.225 INFO Successfully published block            slot: 98, attestations: 2, deposits: 0, service: block
```

If you see any `ERRO` (error) logs, please reach out on
[Discord](https://discord.gg/cyAszAh) or [create an
issue](https://github.com/sigp/lighthouse/issues/new).

Happy staking!


## Custom directories

Users can override the default Lighthouse data directories (`~/.lighthouse/{testnet}`) using the `--datadir` flag. The custom data directory mirrors the structure of any testnet specific default directory (e.g. `~/.lighthouse/medalla`).

> Note: Users should specify different custom directories for different testnets. 

Below is an example flow for importing validator keys, running a beacon node and validator client using a custom data directory `/var/lib/my-custom-dir` for the medalla testnet.

```bash
lighthouse --testnet medalla --datadir /var/lib/my-custom-dir account validator import --directory <PATH-TO-LAUNCHPAD-KEYS-DIRECTORY>
lighthouse --testnet medalla --datadir /var/lib/my-custom-dir bn --staking
lighthouse --testnet medalla --datadir /var/lib/my-custom-dir vc
```
The first step creates a `validators` directory under `/var/lib/my-custom-dir` which contains the imported keys and [`validator_definitions.yml`](./validator-management.md). 
After that, we simply run the beacon chain and validator client with the custom dir path. 