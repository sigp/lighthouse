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

Being educated is critical to a validator's success. Before submitting your mainnet deposit, we recommend:

- Thoroughly exploring the [Staking Launchpad][launchpad] website, try running through the deposit process using a testnet launchpad such as the [Goerli staking launchpad](https://goerli.launchpad.ethereum.org/en/).
- Running a [testnet validator][testnet-validator].
- Reading through this documentation, especially the [Slashing Protection][slashing] section.
- Performing a web search and doing your own research.


>
> **Please note**: the Lighthouse team does not take any responsibility for losses or damages
> occurred through the use of Lighthouse. We have an experienced internal security team and have
> undergone multiple third-party security-reviews, however the possibility of bugs or malicious
> interference remains a real and constant threat. Validators should be prepared to lose some rewards
> due to the actions of other actors on the consensus layer or software bugs. See the
> [software license][license] for more detail on liability.


## Become a validator

There are five primary steps to become a validator:

1. [Create validator keys](#step-1-create-validator-keys)
1. [Start an execution client and Lighthouse beacon node](#step-2-start-an-execution-client-and-lighthouse-beacon-node)
1. [Import validator keys into Lighthouse](#step-3-import-validator-keys-to-lighthouse)
1. [Start Lighthouse validator client](#step-4-start-lighthouse-validator-client)
1. [Submit deposit](#step-5-submit-deposit-32eth-per-validator)

> **Important note**: The guide below contains both mainnet and testnet instructions. We highly recommend *all* users to **run a testnet validator** prior to staking mainnet ETH.  By far, the best technical learning experience is to run a testnet validator. You can get hands-on experience with all the tools and it's a great way to test your staking
hardware. 32 ETH is a significant outlay and joining a testnet is a great way to "try before you buy". 

<!--To join a testnet, for example the Goerli testnet, select `Goerli` when you are prompted to select the network in the `staking-deposit-cli` in Step 1, replace `--network mainnet` with `--network goerli` in Steps 2-4, and visit [Goerli staking launchpad](https://goerli.launchpad.ethereum.org/en/) to deposit testnet ETH in Step 5.-->


> **Never use real ETH to join a testnet!** Testnet such as the Goerli testnet uses Goerli ETH which is worthless. This allows experimentation without real-world costs.

### Step 1. Create validator keys

The Ethereum Foundation provides the [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli/releases) for creating validator keys. Download and run the `staking-deposit-cli` with the command:
```bash
./deposit new-mnemonic
```
and follow the instructions to generate the keys. When prompted for a network, select `mainnet` if you want to run a mainnet validator, or select `goerli` if you want to run a Goerli testnet validator. A new mnemonic will be generated in the process.

> **Important note:** A mnemonic (or seed phrase) is a 24-word string randomly generated in the process. It is highly recommended to write down the mnemonic and keep it safe offline. It is important to ensure that the mnemonic is never stored in any digital form (computers, mobile phones, etc) connected to the internet. Please also make one or more backups of the mnemonic to ensure your ETH is not lost in the case of data loss. It is very important to keep your mnemonic private as it represents the ultimate control of your ETH.

Upon completing this step, the files `deposit_data-*.json` and `keystore-m_*.json` will be created. The keys that are generated from staking-deposit-cli can be easily loaded into a Lighthouse validator client (`lighthouse vc`) in [Step 3](#step-3-import-validator-keys-to-lighthouse). In fact, both of these programs are designed to work with each other.


> Lighthouse also supports creating validator keys, see [Key management](./key-management.md) for more info.

### Step 2. Start an execution client and Lighthouse beacon node

Start an execution client and Lighthouse beacon node according to the [Run a Node](./run_a_node.md) guide. Make sure that both execution client and consensus client are synced.

### Step 3. Import validator keys to Lighthouse

In [Step 1](#step-1-create-validator-keys), the staking-deposit-cli will generate the validator keys into a `validator_keys` directory. Let's assume that 
this directory is `$HOME/staking-deposit-cli/validator_keys`. Using the default `validators` directory in Lighthouse (`~/.lighthouse/mainnet/validators`), run the following command to import validator keys:

Mainnet:
```bash
lighthouse --network mainnet account validator import --directory $HOME/staking-deposit-cli/validator_keys
```

Goerli testnet:
```bash
lighthouse --network goerli account validator import --directory $HOME/staking-deposit-cli/validator_keys
```

> Note: The user must specify the consensus client network that they are importing the keys by using the `--network` flag.

> Note: If the validator_keys directory is in a different location, modify the path accordingly.

> Note: `~/.lighthouse/mainnet` is the default directory which contains the keys and database. To specify a custom directory, see [Custom Directories][advanced-datadir].

> Docker users should use the command from the [Docker](#docker-users) documentation.


The user will be prompted for a password for each keystore discovered:

```
Keystore found at "/home/{username}/staking-deposit-cli/validator_keys/keystore-m_12381_3600_0_0_0-1595406747.json":

 - Public key: 0xa5e8702533f6d66422e042a0bf3471ab9b302ce115633fa6fdc5643f804b6b4f1c33baf95f125ec21969a3b1e0dd9e56
 - UUID: 8ea4cf99-8719-43c5-9eda-e97b8a4e074f

If you enter the password it will be stored as plain text in validator_definitions.yml so that it is not required each time the validator client starts.

Enter the keystore password, or press enter to omit it:
```

The user can choose whether or not they'd like to store the validator password
in the [`validator_definitions.yml`](./validator-management.md) file. If the
password is *not* stored here, the validator client (`lighthouse vc`)
application will ask for the password each time it starts. This might be nice
for some users from a security perspective (i.e., if it is a shared computer),
however it means that if the validator client restarts, the user will be subject
to offline penalties until they can enter the password. If the user trusts the
computer that is running the validator client and they are seeking maximum
validator rewards, we recommend entering a password at this point.

Once the process is done the user will see:

```
Successfully imported keystore.
Successfully updated validator_definitions.yml.

Successfully imported 1 validators (0 skipped).

WARNING: DO NOT USE THE ORIGINAL KEYSTORES TO VALIDATE WITH ANOTHER CLIENT, OR YOU WILL GET SLASHED.
```

Once you see the above message, you have successfully imported the validator keys. You can now proceed to the next step to start the validator client.


### Step 4. Start Lighthouse validator client

After the keys are imported, the user can start performing their validator duties
by starting the Lighthouse validator client `lighthouse vc`: 

Mainnet:

```bash
lighthouse vc --network mainnet --suggested-fee-recipient YourFeeRecipientAddress
```

Goerli testnet:
```bash
lighthouse vc --network goerli --suggested-fee-recipient YourFeeRecipientAddress
```

The `validator client` manages validators using data obtained from the beacon node via a HTTP API. You are highly recommended to enter a fee-recipient by changing `YourFeeRecipientAddress` to an Ethereum address under your control. 

When `lighthouse vc` starts, check that the validator public key appears
as a `voting_pubkey` as shown below:

```
INFO Enabled validator       voting_pubkey: 0xa5e8702533f6d66422e042a0bf3471ab9b302ce115633fa6fdc5643f804b6b4f1c33baf95f125ec21969a3b1e0dd9e56
```

Once this log appears (and there are no errors) the `lighthouse vc` application
will ensure that the validator starts performing its duties and being rewarded
by the protocol.

### Step 5: Submit deposit (32ETH per validator)

After you have successfully run and synced the execution client, beacon node and validator client, you can now proceed to submit the deposit. Go to the mainnet [Staking launchpad](https://launchpad.ethereum.org/en/) (or [Goerli staking launchpad](https://goerli.launchpad.ethereum.org/en/) for testnet validator) and carefully go through the steps to becoming a validator. Once you are ready, you can submit the deposit by sending 32ETH per validator to the deposit contract. Upload the `deposit_data-*.json` file generated in [Step 1](#step-1-create-validator-keys) to the Staking launchpad.

> **Important note:** Double check that the deposit contract for mainnet is `0x00000000219ab540356cBB839Cbe05303d7705Fa` before you confirm the transaction. 

Once the deposit transaction is confirmed, it will take a minimum of ~16 hours to a few days/weeks for the beacon chain to process and activate your validator, depending on the queue. Refer to our [FAQ - Why does it take so long for a validator to be activated](./faq.md#why-does-it-take-so-long-for-a-validator-to-be-activated) for more info. 

Once your validator is activated, the validator client will start to publish attestations each epoch:

```
Dec 03 08:49:40.053 INFO Successfully published attestation      slot: 98, committee_index: 0, head_block: 0xa208…7fd5,
```

If you propose a block, the log will look like:

```
Dec 03 08:49:36.225 INFO Successfully published block            slot: 98, attestations: 2, deposits: 0, service: block
```

Congratulations! Your validator is now performing its duties and you will receive rewards for securing the Ethereum network. 

### What is next?
After the validator is running and performing its duties, it is important to keep the validator online to continue accumulating rewards. However, there could be problems with the computer, the internet or other factors that cause the validator to be offline. For this, it is best to subscribe to notifications, e.g., via [beaconcha.in](https://beaconcha.in/) which will send notifications about missed attestations and/or proposals. You will be notified about the validator's offline status and will be able to react promptly. 

The next important thing is to stay up to date with updates to Lighthouse and the execution client. Updates are released from time to time, typically once or twice a month. For Lighthouse updates, you can subscribe to notifications on [Github](https://github.com/sigp/lighthouse) by clicking on `Watch`. If you only want to receive notification on new releases, select `Custom`, then `Releases`. You could also join [Lighthouse Discord](https://discord.gg/cyAszAh) where we will make an announcement when there is a new release.

You may also want to try out [Siren](./lighthouse-ui.md), a UI developed by Lighthouse to monitor validator performance.

Once you are familiar with running a validator and server maintenance, you'll find that running Lighthouse is easy. Install it, start it, monitor it and keep it updated. You shouldn't need to interact with it on a day-to-day basis. Happy staking!

## Docker users

### Import validator keys

The `import` command is a little more complex for Docker users, but the example
in this document can be substituted with:

```bash
docker run -it \
	-v $HOME/.lighthouse:/root/.lighthouse \
	-v $(pwd)/validator_keys:/root/validator_keys \
	sigp/lighthouse \
	lighthouse --network mainnet account validator import --directory /root/validator_keys
```

Here we use two `-v` volumes to attach:

- `~/.lighthouse` on the host to `/root/.lighthouse` in the Docker container.
- The `validator_keys` directory in the present working directory of the host
	to the `/root/validator_keys` directory of the Docker container.

### Start Lighthouse beacon node and validator client
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


If you get stuck you can always reach out on our [Discord][discord] or [create an
issue](https://github.com/sigp/lighthouse/issues/new).


