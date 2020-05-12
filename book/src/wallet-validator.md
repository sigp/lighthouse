# Create a validator

Validators are fundamentally represented by a BLS keypair. In Lighthouse, we
use a [wallet](./wallet-create) to generate these keypairs. Once a wallet
exists, the `lighthouse account wallet validator` command is used to generate
the BLS keypair and all necessary information to submit a validator deposit and
have that validator operate in the `lighthouse validator_client`.

## Usage

To create a validator from a [wallet](./wallet-create), use the `lighthouse
account wallet validator command`:

```bash
lighthouse account wallet validator --help

Creates new validators from an existing wallet located in --base-dir.

USAGE:
    lighthouse account_manager wallet validator [OPTIONS] --name <WALLET_NAME> --wallet-passphrase <WALLET_PASSWORD_PATH>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --at-most <AT_MOST_VALIDATORS>
            Observe the number of validators in --validator-dir, only creating enough to
                                    ensure reach the given count. Never deletes an existing validator.
        --count <VALIDATOR_COUNT>
            The number of validators to create, regardless of how many already exist

    -d, --datadir <DIR>
            Data directory for lighthouse keys and databases.

        --deposit-gwei <DEPOSIT_GWEI>
            The GWEI value of the deposit amount. Defaults to the minimum amount
                                        required for an active validator (MAX_EFFECTIVE_BALANCE)
        --name <WALLET_NAME>                                              Use the wallet identified by this name
        --secrets-dir <SECRETS_DIR>
            The path where the validator keystore passwords will be stored. Defaults to ~/.lighthouse/secrets

    -s, --spec <TITLE>
            Specifies the default eth2 spec type. [default: mainnet]  [possible values: mainnet, minimal, interop]

        --store-withdrawal-keystore <SHOULD_STORE_WITHDRAWAL_KEYSTORE>
            If present, the withdrawal keystore will be stored alongside the voting keypair. It is generally recommended
            to not store the withdrawal key and instead generated them from the wallet seed when required, after phase
            0.
    -t, --testnet-dir <DIR>
            Path to directory containing eth2_testnet specs. Defaults to a hard-coded Lighthouse testnet. Only effective
            if there is no existing database.
        --validator-dir <VALIDATOR_DIRECTORY>
            The path where the validator directories will be created. Defaults to ~/.lighthouse/validators

        --wallet-passphrase <WALLET_PASSWORD_PATH>
            A path to a file containing the password which will unlock the wallet.
```

## Example

The example assumes that the `wally` wallet was generated from the
[wallet](./wallet-create) example.

```bash
lighthouse account wallet validator --name wally --wallet-password wally.pass
```

This command will:

- Derive a new BLS keypair from `wally`, updating it so that it generates a
    new key next time.
- Create a new directory in `~/.lighthouse/validators` containing:
    - An encrypted keystore containing the validators voting keypair.
	- An `eth1_deposit_data.rlp` assuming the default deposit amount (`32 ETH`
		for most testnets and mainnet) which can be submitted to the deposit
		contract.
- Store a password to the validators voting keypair in `~/.lighthouse/secrets`.
