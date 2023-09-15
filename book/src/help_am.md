#Account Manager

```
Utilities for generating and managing Ethereum 2.0 accounts.

USAGE:
    lighthouse.exe account_manager [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
        --disable-log-timestamp          If present, do not include timestamps in logging output.
        --disable-malloc-tuning          If present, do not configure the system allocator. Providing this flag will
                                         generally increase memory usage, it should only be provided when debugging
                                         specific memory allocation issues.
    -h, --help                           Prints help information
        --log-color                      Force outputting colors when emitting logs to the terminal.
        --logfile-compress               If present, compress old log files. This can help reduce the space needed to
                                         store old logs.
        --logfile-no-restricted-perms    If present, log files will be generated as world-readable meaning they can be
                                         read by any user on the machine. Note that logs can often contain sensitive
                                         information about your validator and so this flag should be used with caution.
                                         For Windows users, the log file permissions will be inherited from the parent
                                         folder.
    -V, --version                        Prints version information

OPTIONS:
    -d, --datadir <DIR>
            Used to specify a custom root data directory for lighthouse keys and databases. Defaults to
            $HOME/.lighthouse/{network} where network is the value of the `network` flag Note: Users should specify
            separate custom datadirs for different networks.
        --debug-level <LEVEL>
            Specifies the verbosity level used when emitting logs to the terminal. [default: info]  [possible values:
            info, debug, trace, warn, error, crit]
        --log-format <FORMAT>
            Specifies the log format used when emitting logs to the terminal. [possible values: JSON]

        --logfile <FILE>
            File path where the log file will be stored. Once it grows to the value specified in `--logfile-max-size` a
            new log file is generated where future logs are stored. Once the number of log files exceeds the value
            specified in `--logfile-max-number` the oldest log file will be overwritten.
        --logfile-debug-level <LEVEL>
            The verbosity level used when emitting logs to the log file. [default: debug]  [possible values: info,
            debug, trace, warn, error, crit]
        --logfile-format <FORMAT>
            Specifies the log format used when emitting logs to the logfile. [possible values: DEFAULT, JSON]

        --logfile-max-number <COUNT>
            The maximum number of log files that will be stored. If set to 0, background file logging is disabled.
            [default: 5]
        --logfile-max-size <SIZE>
            The maximum size (in MB) each log file can grow to before rotating. If set to 0, background file logging is
            disabled. [default: 200]
        --network <network>
            Name of the Eth2 chain Lighthouse will sync and follow. [possible values: mainnet, prater, goerli, gnosis,
            sepolia]
        --safe-slots-to-import-optimistically <INTEGER>
            Used to coordinate manual overrides of the SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY parameter. This flag should
            only be used if the user has a clear understanding that the broad Ethereum community has elected to override
            this parameter in the event of an attack at the PoS transition block. Incorrect use of this flag can cause
            your node to possibly accept an invalid chain or sync more slowly. Be extremely careful with this flag.
    -s, --spec <DEPRECATED>
            This flag is deprecated, it will be disallowed in a future release. This value is now derived from the
            --network or --testnet-dir flags.
        --terminal-block-hash-epoch-override <EPOCH>
            Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH parameter. This flag should
            only be used if the user has a clear understanding that the broad Ethereum community has elected to override
            the terminal PoW block. Incorrect use of this flag will cause your node to experience a consensus failure.
            Be extremely careful with this flag.
        --terminal-block-hash-override <TERMINAL_BLOCK_HASH>
            Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH parameter. This flag should only be used if
            the user has a clear understanding that the broad Ethereum community has elected to override the terminal
            PoW block. Incorrect use of this flag will cause your node to experience a consensus failure. Be extremely
            careful with this flag.
        --terminal-total-difficulty-override <INTEGER>
            Used to coordinate manual overrides to the TERMINAL_TOTAL_DIFFICULTY parameter. Accepts a 256-bit decimal
            integer (not a hex value). This flag should only be used if the user has a clear understanding that the
            broad Ethereum community has elected to override the terminal difficulty. Incorrect use of this flag will
            cause your node to experience a consensus failure. Be extremely careful with this flag.
    -t, --testnet-dir <DIR>
            Path to directory containing eth2_testnet specs. Defaults to a hard-coded Lighthouse testnet. Only effective
            if there is no existing database.

SUBCOMMANDS:
    help         Prints this message or the help of the given subcommand(s)
    validator    Provides commands for managing Eth2 validators.
    wallet       Manage wallets, from which validator keys can be derived.
```