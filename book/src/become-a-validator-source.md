# Become a Validator: Building from Source

## 0. Install Rust
If you don't have Rust installed already, visit [rustup.rs](https://rustup.rs/) to install it.

> Notes:
>   - If you're not familiar with Rust or you'd like more detailed instructions, see our  [installation guide](./installation.md).
>   - Windows is presently only supported via [WSL](https://docs.microsoft.com/en-us/windows/wsl/about).


## 1. Download and install Lighthouse

Once you have Rust installed, you can install Lighthouse with the following commands:

1.  `git clone https://github.com/sigp/lighthouse.git`
2.  `cd lighthouse`
4.  `make`

You may need to open a new terminal window before running `make`.

You've completed this step when you can run `$ lighthouse --help` and see the
help menu.


## 2. Start an Eth1 client

Since Eth2 relies upon the Eth1 chain for validator on-boarding, all Eth2 validators must have a connection to an Eth1 node.

We provide instructions for using Geth (the Eth1 client that, by chance, we ended up testing with), but you could use any client that implements the JSON RPC via HTTP. A fast-synced node should be sufficient.

### Installing Geth
If you're using a Mac, follow the instructions [listed here](https://github.com/ethereum/go-ethereum/wiki/Installation-Instructions-for-Mac) to install geth. Otherwise [see here](https://github.com/ethereum/go-ethereum/wiki/Installing-Geth).

### Starting Geth

Once you have geth installed, use this command to start your Eth1 node:

```bash
 geth --goerli --http
```

## 3. Start your beacon node

The beacon node is the core component of Eth2, it connects to other peers over
the internet and maintains a view of the chain.

Start your beacon node with:

```bash
 lighthouse --testnet medalla beacon --staking
```

> The `--testnet` parameter is optional. Omitting it will default to the
> current public testnet. Set the value to the testnet you wish to run on.
> Current values are either `altona` or `medalla`. This is true for all the
> following commands in this document.

You can also pass an external http endpoint (e.g. Infura) for the Eth1 node using the `--eth1-endpoint` flag:

```bash
 lighthouse --testnet medalla beacon --staking --eth1-endpoint <ETH1-SERVER>
```

Your beacon node has started syncing when you see the following (truncated)
log:

```
Dec 09 12:57:18.026 INFO Syncing
est_time: 2 hrs ...
```

The `distance` value reports the time since eth2 genesis, whilst the `est_time`
reports an estimate of how long it will take your node to become synced.

You'll know it's finished syncing once you see the following (truncated) log:

```
Dec 09 12:27:06.010 INFO Synced
slot: 16835, ...
```


## 4. Generate your validator key

First, [create a wallet](./wallet-create.md) that can be used to generate
validator keys. Then, from that wallet [create a
validator](./validator-create.md). A two-step example follows:

### 4.1 Create a Wallet

Create a wallet with:

```bash
lighthouse --testnet medalla account wallet create
```

You will be prompted for a wallet name and a password. The output will look like this:

```
Your wallet's 12-word BIP-39 mnemonic is:

	thank beach essence clerk gun library key grape hotel wise dutch segment

This mnemonic can be used to fully restore your wallet, should
you lose the JSON file or your password.

It is very important that you DO NOT SHARE this mnemonic as it will
reveal the private keys of all validators and keys generated with
this wallet. That would be catastrophic.

It is also important to store a backup of this mnemonic so you can
recover your private keys in the case of data loss. Writing it on
a piece of paper and storing it in a safe place would be prudent.

Your wallet's UUID is:

	e762671a-2a33-4922-901b-62a43dbd5227

You do not need to backup your UUID or keep it secret.
```

**Don't forget to make a backup** of the 12-word BIP-39 mnemonic. It can be
used to restore your validator if there is a data loss.

### 4.2 Create a Validator from the Wallet

Create a validator from the wallet with:

```bash
lighthouse --testnet medalla account validator create --count 1
```

Enter your wallet's name and password when prompted. The output will look like this:

```bash
1/1	0x80f3dce8d6745a725d8442c9bc3ca0852e772394b898c95c134b94979ebb0af6f898d5c5f65b71be6889185c486918a7
```

Take note of the _validator public key_ (the `0x` and 64 characters following
it). It's the validator's primary identifier, and will be used to find your
validator in block explorers. (The `1/1` at the start is saying it's one-of-one
keys generated).

Once you've observed the validator public key, you've successfully generated a
new sub-directory for your validator in the `.lighthouse/validators` directory.
The sub-directory is identified by your validator's public key . And is used to
store your validator's deposit data, along with its voting keys and other
information.


## 5. Start your validator client

> Note: If you are participating in the genesis of a network (the network has
> not launched yet) you should skip this step and re-run this step two days before
> the launch of the network. The beacon node does not expose its HTTP API until
> the genesis of the network is known (approx 2 days before the network
> launches).

Since the validator client stores private keys and signs messages generated by the beacon node, for security reasons it runs separately from it.

You'll need both your beacon node _and_ validator client running if you want to
stake.

Start the validator client with:

```bash
 lighthouse --testnet medalla validator --auto-register
```

The `--auto-register` flag registers your signing key with the slashing protection database, which
keeps track of all the messages your validator signs. This flag should be used sparingly,
as reusing the same key on multiple nodes can lead to your validator getting slashed. On subsequent
runs you should leave off the `--auto-register` flag.

You know that your validator client is running and has found your validator keys from [step 3](become-a-validator-source.html#3-start-your-beacon-node) when you see the following logs:

```
Dec 09 13:08:59.171 INFO Loaded validator keypair store          voting_validators: 1
Dec 09 13:09:09.000 INFO Awaiting activation                     slot: 17787, ...
```


To find an estimate for how long your beacon node will take to finish syncing, lookout for the following logs:

```bash
beacon_node_1       | Mar 16 11:33:53.979 INFO Syncing
est_time: 47 mins, speed: 16.67 slots/sec, distance: 47296 slots (7 days 14 hrs), peers: 3, service: slot_notifier
```

You'll find the estimated time under `est_time`. In the example log above, that's `47 mins`.

If your beacon node hasn't finished syncing yet, you'll see some `ERRO`
messages indicating that your node hasn't synced yet:

```bash
validator_client_1  | Mar 16 11:34:36.086 ERRO Beacon node is not synced               current_epoch: 6999, node_head_epoch: 5531, service: duties
```

It's safest to wait for your node to sync before moving on to the next step, otherwise your validator may activate before you're able to produce blocks and attestations (and you may be penalized as a result).

However, since it generally takes somewhere between [4 and 8 hours](./faq.md) after depositing for a validator to become active, if your `est_time` is less than 4 hours, you _should_ be fine to just move on to the next step. After all, this is a testnet and you're only risking Goerli ETH!

## Installation complete!

In the [next step](become-a-validator.html#2-submit-your-deposit-to-goerli) you'll need to upload your validator's deposit data. This data is stored in a file called `eth1_deposit_data.rlp`.

You'll find it in `/home/.lighthouse/validators` -- in the sub-directory that corresponds to your validator's public key.

> For example, if your username is `karlm`, and your validator's public key (aka `voting_pubkey`) is `0x8592c7..`, then you'll find your `eth1_deposit_data.rlp` file in the following directory:
>
>`/home/karlm/.lighthouse/validators/0x8592c7../`

Once you've located your `eth1_deposit_data.rlp` file, you're ready to move on to [Become a Validator: Step 2](become-a-validator.html#2-submit-your-deposit-to-goerli).
