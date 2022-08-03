# Become an Ethereum Consensus Mainnet Validator

[launchpad]: https://launchpad.ethereum.org/
[lh-book]: https://lighthouse-book.sigmaprime.io/
[testnet-validator]: ./testnet-validator.md
[advanced-datadir]: ./advanced-datadir.md
[license]: https://github.com/sigp/lighthouse/blob/stable/LICENSE
[slashing]: ./slashing-protection.md
[discord]: https://discord.gg/cyAszAh

Becoming an Ethereum consensus validator is rewarding, but it's not for the faint of heart. You'll need to be
familiar with the rules of staking (e.g., rewards, penalties, etc.) and also configuring and
managing servers. You'll also need at least 32 ETH!

For those with an understanding of Ethereum consensus and server maintenance, you'll find that running Lighthouse
is easy. Install it, start it, monitor it and keep it updated. You shouldn't need to interact
with it on a day-to-day basis.

Being educated is critical to validator success. Before submitting your mainnet deposit, we
recommend:

- Thoroughly exploring the [Staking Launchpad][launchpad] website
  - Try running through the deposit process *without* actually submitting a deposit.
- Reading through this documentation, especially the [Slashing Protection][slashing] section.
- Running a [testnet validator][testnet-validator].
- Performing a web search and doing your own research.

By far, the best technical learning experience is to run a [Testnet Validator][testnet-validator].
You can get hands-on experience with all the tools and it's a great way to test your staking
hardware. We recommend *all* mainnet validators to run a testnet validator initially; 32 ETH is a
significant outlay and joining a testnet is a great way to "try before you buy".

Remember, if you get stuck you can always reach out on our [Discord][discord].

>
> **Please note**: the Lighthouse team does not take any responsibility for losses or damages
> occurred through the use of Lighthouse. We have an experienced internal security team and have
> undergone multiple third-party security-reviews, however the possibility of bugs or malicious
> interference remains a real and constant threat. Validators should be prepared to lose some rewards
> due to the actions of other actors on the consensus layer or software bugs. See the
> [software license][license] for more detail on liability.

## Using Lighthouse for Mainnet

When using Lighthouse, the `--network` flag selects a network. E.g.,

- `lighthouse` (no flag): Mainnet.
- `lighthouse --network mainnet`: Mainnet.
- `lighthouse --network prater`: Prater (testnet).

Using the correct `--network` flag is very important; using the wrong flag can
result in penalties, slashings or lost deposits. As a rule of thumb, always
provide a `--network` flag instead of relying on the default.

## Joining a Testnet

There are five primary steps to become a testnet validator:

1. Create validator keys and submit deposits.
1. Start an execution client.
1. Install Lighthouse.
1. Import the validator keys into Lighthouse.
1. Start Lighthouse.
1. Leave Lighthouse running.

Each of these primary steps has several intermediate steps, so we recommend
setting aside one or two hours for this process.

### Step 1. Create validator keys

The Ethereum Foundation provides a "Staking Launchpad" for creating validator keypairs and submitting
deposits:

- [Staking Launchpad][launchpad]

Please follow the steps on the launch pad site to generate validator keys and submit deposits. Make
sure you select "Lighthouse" as your client.

Move to the next step once you have completed the steps on the launch pad,
including generating keys via the Python CLI and submitting gETH/ETH deposits.

### Step 2. Start an execution client

Since the consensus chain relies upon the execution chain for validator on-boarding, all consensus validators must have a
connection to an execution client.

We provide instructions for using Geth, but you could use any client that implements the JSON RPC
via HTTP. A fast-synced node is sufficient.

#### Installing Geth

If you're using a Mac, follow the instructions [listed
here](https://github.com/ethereum/go-ethereum/wiki/Installation-Instructions-for-Mac) to install
geth. Otherwise [see here](https://github.com/ethereum/go-ethereum/wiki/Installing-Geth).

#### Starting Geth

Once you have geth installed, use this command to start your execution node:

```bash
 geth --http
```

### Step 3. Install Lighthouse

*Note: Lighthouse only supports Windows via WSL.*

Follow the [Lighthouse Installation Instructions](./installation.md) to install
Lighthouse from one of the available options.

Proceed to the next step once you've successfully installed Lighthouse and viewed
its `--version` info.

> Note: Some of the instructions vary when using Docker, ensure you follow the
> appropriate sections later in this guide.

### Step 4. Import validator keys to Lighthouse

When Lighthouse is installed, follow the [Importing from the Ethereum Staking Launch
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
lighthouse --network mainnet bn --staking
```

```bash
lighthouse --network mainnet vc
```

> Note: `~/.lighthouse/mainnet` is the default directory which contains the keys and databases.
> To specify a custom dir, see [Custom Directories][advanced-datadir].

#### Docker users

Those using Docker images can start the processes with:

```bash
$ docker run \
	--network host \
	-v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse \
	lighthouse --network mainnet bn --staking --http-address 0.0.0.0
```

```bash
$ docker run \
	--network host \
	-v $HOME/.lighthouse:/root/.lighthouse \
	sigp/lighthouse \
	lighthouse --network mainnet vc
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
