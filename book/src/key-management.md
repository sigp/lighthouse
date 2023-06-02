# Key Management

[launchpad]: https://launchpad.ethereum.org/

>
> **Note: While Lighthouse is able to generate the validator keys and the deposit data file to submit to the deposit contract, we strongly recommend using the [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) to create validators keys and the deposit data file. This is because the [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) has the option to assign a withdrawal address during the key generation process, while Lighthouse wallet will always generate keys with withdrawal credentials of type 0x00. This means that users who created keys using Lighthouse will have to update their withdrawal credentials in the future to enable withdrawals. In addition, Lighthouse generates the deposit data file in the form of `*.rlp`, which cannot be uploaded to the [Staking launchpad][launchpad] that accepts only `*.json` file. This means that users have to directly interact with the deposit contract to be able to submit the deposit if they were to generate the files using Lighthouse.**

Lighthouse uses a _hierarchical_ key management system for producing validator
keys. It is hierarchical because each validator key can be _derived_ from a
master key, making the validators keys _children_ of the master key. This
scheme means that a single 24-word mnemonic can be used to back up all of your
validator keys without providing any observable link between them (i.e., it is
privacy-retaining). Hierarchical key derivation schemes are common-place in
cryptocurrencies, they are already used by most hardware and software wallets
to secure BTC, ETH and many other coins.

## Key Concepts

We defined some terms in the context of validator key management:

- **Mnemonic**: a string of 24 words that is designed to be easy to write down
	and remember. E.g., _"radar fly lottery mirror fat icon bachelor sadness
	type exhaust mule six beef arrest you spirit clog mango snap fox citizen
	already bird erase"_.
	- Defined in BIP-39
- **Wallet**: a wallet is a JSON file which stores an
	encrypted version of a mnemonic.
	- Defined in EIP-2386
- **Keystore**: typically created by wallet, it contains a single encrypted BLS
	keypair.
	- Defined in EIP-2335.
- **Voting Keypair**: a BLS public and private keypair which is used for
	signing blocks, attestations and other messages on regular intervals in the beacon chain.
- **Withdrawal Keypair**: a BLS public and private keypair which will be
	required _after_ Phase 0 to manage ETH once a validator has exited.

## Create a validator
There are 2 steps involved to create a validator key using Lighthouse:
 1. [Create a wallet](#step-1-create-a-wallet-and-record-the-mnemonic)
 1. [Create a validator](#step-2-create-a-validator)

The following example demonstrates how to create a single validator key.

### Step 1: Create a wallet and record the mnemonic
A wallet allows for generating practically unlimited validators from an
easy-to-remember 24-word string (a mnemonic). As long as that mnemonic is
backed up, all validator keys can be trivially re-generated.

Whilst the wallet stores the mnemonic, it does not store it in plain-text: the
mnemonic is encrypted with a password. It is the responsibility of the user to
define a strong password. The password is only required for interacting with
the wallet, it is not required for recovering keys from a mnemonic.

To create a wallet, use the `lighthouse account wallet` command. For example, if we wish to create a new wallet for the Goerli testnet named `wally` and saves it in `~/.lighthouse/goerli/wallets` with a randomly generated password saved
to `./wallet.pass`:

```bash
lighthouse --network goerli account wallet create --name wally --password-file wally.pass
```
Using the above command, a wallet will be created in `~/.lighthouse/goerli/wallets` with the name
`wally`. It is encrypted using the password defined in the
`wally.pass` file. 

During the wallet creation process, a 24-word mnemonic will be displayed. Record the mnemonic because it allows you to recreate the files in the case of data loss.
> Notes:
> - When navigating to the directory `~/.lighthouse/goerli/wallets`, one will not see the wallet name `wally`, but a hexadecimal folder containing the wallet file. However, when interacting with `lighthouse` in the CLI, the name `wally` will be used.
> - The password is not `wally.pass`, it is the _content_ of the
>   `wally.pass` file.
> - If `wally.pass` already exists, the wallet password will be set to the content
>   of that file.

### Step 2: Create a validator
Validators are fundamentally represented by a BLS keypair. In Lighthouse, we use a wallet to generate these keypairs. Once a wallet exists, the `lighthouse account validator create` command can be used to generate the BLS keypair and all necessary information to submit a validator deposit. With the `wally` wallet created in [Step 1](#step-1-create-a-wallet-and-record-the-mnemonic), we can create a validator with the command:

```bash
lighthouse --network goerli account validator create --wallet-name wally --wallet-password wally.pass --count 1
```
This command will:

- Derive a single new BLS keypair from wallet `wally` in `~/.lighthouse/goerli/wallets`, updating it so that it generates a new key next time.
- Create a new directory `~/.lighthouse/goerli/validators` containing:
    - An encrypted keystore file `voting-keystore.json` containing the validator's voting keypair.
	- An `eth1_deposit_data.rlp` assuming the default deposit amount (`32 ETH`) which can be submitted to the deposit
		contract for the Goerli testnet. Other networks can be set via the
		`--network` parameter.
- Create a new directory `~/.lighthouse/goerli/secrets` which stores a password to the validator's voting keypair.


If you want to create another validator in the future, repeat [Step 2](#step-2-create-a-validator). The wallet keeps track of how many validators it has generated and ensures that a new validator is generated each time. The important thing is to keep the 24-word mnemonic safe so that it can be used to generate new validator keys if needed.

## Detail

### Directory Structure

There are three important directories in Lighthouse validator key management:

- `wallets/`: contains encrypted wallets which are used for hierarchical
	key derivation.
	- Defaults to `~/.lighthouse/{network}/wallets`
- `validators/`: contains a directory for each validator containing
	encrypted keystores and other validator-specific data.
	- Defaults to `~/.lighthouse/{network}/validators`
- `secrets/`: since the validator signing keys are "hot", the validator process
	needs access to the passwords to decrypt the keystores in the validators
	directory. These passwords are stored here.
	- Defaults to `~/.lighthouse/{network}/secrets` 
	
where `{network}` is the name of the network passed in the `--network` parameter.

When the validator client boots, it searches the `validators/` for directories
containing voting keystores. When it discovers a keystore, it searches the
`secrets/` directory for a file with the same name as the 0x-prefixed validator public key. If it finds this file, it attempts
to decrypt the keystore using the contents of this file as the password. If it
fails, it logs an error and moves onto the next keystore.

The `validators/` and `secrets/` directories are kept separate to allow for
ease-of-backup; you can safely backup `validators/` without worrying about
leaking private key data.
