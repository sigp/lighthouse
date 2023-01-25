# Key Management

[launchpad]: https://launchpad.ethereum.org/

>
> **Note: we recommend using the [Staking launchpad][launchpad] to create validators.**

Lighthouse uses a _hierarchical_ key management system for producing validator
keys. It is hierarchical because each validator key can be _derived_ from a
master key, making the validators keys _children_ of the master key. This
scheme means that a single 24-word mnemonic can be used to backup all of your
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
	signing blocks, attestations and other messages on regular intervals,
	whilst staking in Phase 0.
- **Withdrawal Keypair**: a BLS public and private keypair which will be
	required _after_ Phase 0 to manage ETH once a validator has exited.

## Overview

The key management system in Lighthouse involves moving down the above list of
items, starting at one easy-to-backup mnemonic and ending with multiple
keypairs. Creating a single validator looks like this:

1. Create a **wallet** and record the **mnemonic**:
    - `lighthouse --network prater account wallet create --name wally --password-file wally.pass`
1. Create the voting and withdrawal **keystores** for one validator:
	- `lighthouse --network prater account validator create --wallet-name wally --wallet-password wally.pass --count 1`


In step (1), we created a wallet in `~/.lighthouse/{network}/wallets` with the name
`wally`. We encrypted this using a pre-defined password in the
`wally.pass` file. Then, in step (2), we created one new validator in the
`~/.lighthouse/{network}/validators` directory using `wally` (unlocking it with
`wally.pass`) and storing the passwords to the validators voting key in
`~/.lighthouse/{network}/secrets`.

Thanks to the hierarchical key derivation scheme, we can delete all of the
aforementioned directories and then regenerate them as long as we remembered
the 24-word mnemonic (we don't recommend doing this, though).

Creating another validator is easy, it's just a matter of repeating step (2).
The wallet keeps track of how many validators it has generated and ensures that
a new validator is generated each time.

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
	dir. These passwords are stored here.
	- Defaults to `~/.lighthouse/{network}/secrets` where `network` is the name of the network passed in the `--network` parameter (default is `mainnet`).

When the validator client boots, it searches the `validators/` for directories
containing voting keystores. When it discovers a keystore, it searches the
`secrets/` dir for a file with the same name as the 0x-prefixed hex
representation of the keystore public key. If it finds this file, it attempts
to decrypt the keystore using the contents of this file as the password. If it
fails, it logs an error and moves onto the next keystore.

The `validators/` and `secrets/` directories are kept separate to allow for
ease-of-backup; you can safely backup `validators/` without worrying about
leaking private key data.

### Withdrawal Keypairs

In Ethereum consensus Phase 0, withdrawal keypairs do not serve any immediate purpose.
However, they become very important _after_ Phase 0: they will provide the
ultimate control of the ETH of withdrawn validators.

This presents an interesting key management scenario: withdrawal keys are very
important, but not right now. Considering this, Lighthouse has adopted a
strategy where **we do not save withdrawal keypairs to disk by default** (it is
opt-in). Instead, we assert that since the withdrawal keys can be regenerated
from a mnemonic, having them lying around on the file-system only presents risk
and complexity.

At the time of writing, we do not expose the commands to regenerate keys from
mnemonics. However, key regeneration is tested on the public Lighthouse
repository and will be exposed prior to mainnet launch.

So, in summary, withdrawal keypairs can be trivially regenerated from the
mnemonic via EIP-2333 so they are not saved to disk like the voting keypairs.
