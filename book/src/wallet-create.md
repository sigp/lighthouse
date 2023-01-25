# Create a wallet

[launchpad]: https://launchpad.ethereum.org/

>
> **Note: we recommend using the [Staking launchpad][launchpad] to create validators.**

A wallet allows for generating practically unlimited validators from an
easy-to-remember 24-word string (a mnemonic). As long as that mnemonic is
backed up, all validator keys can be trivially re-generated.

The 24-word string is randomly generated during wallet creation and printed out
to the terminal. It's important to **make one or more backups of the mnemonic**
to ensure your ETH is not lost in the case of data loss. It is very important to
**keep your mnemonic private** as it represents the ultimate control of your
ETH.

Whilst the wallet stores the mnemonic, it does not store it in plain-text: the
mnemonic is encrypted with a password. It is the responsibility of the user to
define a strong password. The password is only required for interacting with
the wallet, it is not required for recovering keys from a mnemonic.

## Usage

To create a wallet, use the `lighthouse account wallet` command:

```bash
lighthouse account wallet create --help

Creates a new HD (hierarchical-deterministic) EIP-2386 wallet.

USAGE:
    lighthouse account_manager wallet create [OPTIONS] --name <WALLET_NAME> --password-file <WALLET_PASSWORD_PATH>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --datadir <DIR>                             Data directory for lighthouse keys and databases.
        --mnemonic-output-path <MNEMONIC_PATH>
            If present, the mnemonic will be saved to this file. DO NOT SHARE THE MNEMONIC.

        --name <WALLET_NAME>
            The wallet will be created with this name. It is not allowed to create two wallets with the same name for
            the same --base-dir.
        --password-file <WALLET_PASSWORD_PATH>
            A path to a file containing the password which will unlock the wallet. If the file does not exist, a random
            password will be generated and saved at that path. To avoid confusion, if the file does not already exist it
            must include a '.pass' suffix.
    -t, --testnet-dir <DIR>
            Path to directory containing eth2_testnet specs. Defaults to a hard-coded Lighthouse testnet. Only effective
            if there is no existing database.
        --type <WALLET_TYPE>
            The type of wallet to create. Only HD (hierarchical-deterministic) wallets are supported presently..
            [default: hd]  [possible values: hd]
```


## Example

Creates a new wallet named `wally` and saves it in `~/.lighthouse/prater/wallets` with a randomly generated password saved
to `./wallet.pass`:

```bash
lighthouse --network prater account wallet create --name wally --password-file wally.pass
```

> Notes:
>
> - The password is not `wally.pass`, it is the _contents_ of the
>   `wally.pass` file.
> - If `wally.pass` already exists the wallet password will be set to contents
>   of that file.
