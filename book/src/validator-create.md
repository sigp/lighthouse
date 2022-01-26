# Create a validator

[launchpad]: https://launchpad.ethereum.org/

>
> **Note: we recommend using the [Eth2 launchpad][launchpad] to create validators.**

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
    lighthouse account_manager validator create [FLAGS] [OPTIONS]

FLAGS:
    -h, --help                         Prints help information
        --stdin-inputs                 If present, read all user inputs from stdin instead of tty.
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

    -d, --datadir <DIR>
            Used to specify a custom root data directory for lighthouse keys and databases. Defaults to
            $HOME/.lighthouse/{network} where network is the value of the `network` flag Note: Users should specify
            separate custom datadirs for different networks.
        --debug-level <LEVEL>
            The verbosity level for emitting logs. [default: info]  [possible values: info, debug, trace, warn, error,
            crit]
        --deposit-gwei <DEPOSIT_GWEI>
            The GWEI value of the deposit amount. Defaults to the minimum amount required for an active validator
            (MAX_EFFECTIVE_BALANCE)
        --network <network>
            Name of the Eth2 chain Lighthouse will sync and follow. [default: mainnet]  [possible values: medalla,
            altona, spadina, pyrmont, mainnet, toledo]
        --secrets-dir <SECRETS_DIR>
            The path where the validator keystore passwords will be stored. Defaults to ~/.lighthouse/{network}/secrets

    -s, --spec <DEPRECATED>
            This flag is deprecated, it will be disallowed in a future release. This value is now derived from the
            --network or --testnet-dir flags.
    -t, --testnet-dir <DIR>
            Path to directory containing eth2_testnet specs. Defaults to a hard-coded Lighthouse testnet. Only effective
            if there is no existing database.
        --wallet-name <WALLET_NAME>                 Use the wallet identified by this name
        --wallet-password <WALLET_PASSWORD_PATH>
            A path to a file containing the password which will unlock the wallet.

        --wallets-dir <wallets-dir>
            A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets
```

## Example

The example assumes that the `wally` wallet was generated from the
[wallet](./wallet-create.md) example.

```bash
lighthouse --network pyrmont account validator create --wallet-name wally --wallet-password wally.pass --count 1
```

This command will:

- Derive a single new BLS keypair from wallet `wally` in `~/.lighthouse/{network}/wallets`, updating it so that it generates a
    new key next time.
- Create a new directory in `~/.lighthouse/{network}/validators` containing:
    - An encrypted keystore containing the validators voting keypair.
	- An `eth1_deposit_data.rlp` assuming the default deposit amount (`32 ETH`
		for most testnets and mainnet) which can be submitted to the deposit
		contract for the Pyrmont testnet. Other testnets can be set via the
		`--network` CLI param.
- Store a password to the validators voting keypair in `~/.lighthouse/{network}/secrets`.
