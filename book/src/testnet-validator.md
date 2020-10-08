# Become a Testnet Validator

Joining an Eth2 testnet is a great way to get familiar with staking in Phase 0.
All users should experiment with a testnet prior to staking mainnet ETH.

## Supported Testnets

Lighthouse supports four testnets:

- [Medalla](https://github.com/goerli/medalla/tree/master/medalla) (default)
- [Zinken](https://github.com/goerli/medalla/tree/master/zinken)
- [Spadina](https://github.com/goerli/medalla/tree/master/spadina) (deprecated)
- [Altona](https://github.com/goerli/medalla/tree/master/spadina) (deprecated)

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

See [./installation.md]

There are three options for installing Lighthouse:

- Using the [pre-built binaries](./installation-binaries.md).
- [Building from source](./installation-source.md).
- [Using Docker images](./docker.md).


### Step 4. Import validator keys to Lighthouse

Follow the [Importing from the Ethereum 2.0 Launch
pad](./validator-import-launchpad.md) instructions.

#### Docker Users

Those using either pre-built or custom-built binaries can the above
instructions directly. Those using Docker image will need to modify the import
command to something like this:

```bash
docker -v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse lighthouse --testnet MY_TESTNET account validator import --directory validator_keys
```

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
lighthouse --testnet MY_TESTNET bn --http --eth1
```

```bash
lighthouse --testnet MY_TESTNET vc
```

#### Docker users

Those using Docker images can start the processes with:

```bash
$ docker run -p 9000:9000 -p 127.0.0.1:5052:5052 -v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse lighthouse --testnet MY_TESTNET beacon --http --http-address 0.0.0.0
```

```bash
$ docker run -v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse lighthouse --testnet MY_TESTNET vc
```

### Step 6. Leave Lighthouse running

Leave your beacon node and validator client running and you'll see logs as the
beacon node stays synced with the network while the validator client produces
blocks and attestations.

It will take 4-8+ hours for the beacon chain to process and activate your
validator, however you'll know you're active when the validator client starts
successfully publishing attestations each slot:

```
Dec 03 08:49:40.053 INFO Successfully published attestation      slot: 98, committee_index: 0, head_block: 0xa208…7fd5,
```

Although you'll produce an attestation each slot, it's less common to produce a
block. Watch for the block production logs too:

```
Dec 03 08:49:36.225 INFO Successfully published block            slot: 98, attestations: 2, deposits: 0, service: block
```

If you see any `ERRO` (error) logs, please reach out on
[Discord](https://discord.gg/cyAszAh) or [create an
issue](https://github.com/sigp/lighthouse/issues/new).

Happy staking!
