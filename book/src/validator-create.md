# Create a validator

Validators are fundamentally represented by a BLS keypair. In Lighthouse, we
use a [wallet](./wallet-create.md) to generate these keypairs. Once a wallet
exists, the `lighthouse account validator create` command is used to generate
the BLS keypair and all necessary information to submit a validator deposit and
have that validator operate in the `lighthouse validator_client`.

## Usage

To create a validator from a [wallet](./wallet-create.md), use the `lighthouse
account validator create` command:

```bash
lighthouse account validator create --help

Creates new validators from an existing EIP-2386 wallet using the EIP-2333 HD key derivation scheme.

USAGE:
    lighthouse account_manager validator create [FLAGS] [OPTIONS] --wallet-name <WALLET_NAME> --wallet-password <WALLET_PASSWORD_PATH>

FLAGS:
    -h, --help                         Prints help information
        --store-withdrawal-keystore    If present, the withdrawal keystore will be stored alongside the voting keypair.
                                       It is generally recommended to *not* store the withdrawal key and instead
                                       generate them from the wallet seed when required.
    -V, --version                      Prints version information

OPTIONS:
        --at-most <AT_MOST_VALIDATORS>
            Observe the number of validators in --validator-dir, only creating enough to reach the given count. Never
            deletes an existing validator.
        --count <VALIDATOR_COUNT>
            The number of validators to create, regardless of how many already exist

    -d, --datadir <DIR>                               Data directory for lighthouse keys and databases.
        --debug-level <LEVEL>
            The verbosity level for emitting logs. [default: info]  [possible values: info, debug, trace, warn, error,
            crit]
        --deposit-gwei <DEPOSIT_GWEI>
            The GWEI value of the deposit amount. Defaults to the minimum amount required for an active validator
            (MAX_EFFECTIVE_BALANCE)
        --secrets-dir <SECRETS_DIR>
            The path where the validator keystore passwords will be stored. Defaults to ~/.lighthouse/{testnet}/secrets

        --testnet <testnet>
            Name of network lighthouse will connect to [possible values: medalla, altona]

    -t, --testnet-dir <DIR>
            Path to directory containing eth2_testnet specs. Defaults to a hard-coded Lighthouse testnet. Only effective
            if there is no existing database.
        --validator-dir <VALIDATOR_DIRECTORY>
            The path where the validator directories will be created. Defaults to ~/.lighthouse/{testnet}/validators

        --wallet-name <WALLET_NAME>                   Use the wallet identified by this name
        --wallet-password <WALLET_PASSWORD_PATH>
            A path to a file containing the password which will unlock the wallet.
```

## Example

The example assumes that the `wally` wallet was generated from the
[wallet](./wallet-create.md) example.

```bash
lighthouse --testnet medalla account validator create --name wally --wallet-password wally.pass --count 1
```

This command will:

- Derive a single new BLS keypair from wallet `wally` in `~/.lighthouse/{testnet}/wallets`, updating it so that it generates a
    new key next time.
- Create a new directory in `~/.lighthouse/{testnet}/validators` containing:
    - An encrypted keystore containing the validators voting keypair.
	- An `eth1_deposit_data.rlp` assuming the default deposit amount (`32 ETH`
		for most testnets and mainnet) which can be submitted to the deposit
		contract for the medalla testnet. Other testnets can be set via the
		`--testnet` CLI param.
- Store a password to the validators voting keypair in `~/.lighthouse/{testnet}/secrets`.

where `testnet` is the name of the testnet passed in the `--testnet` parameter (default is `medalla`).
