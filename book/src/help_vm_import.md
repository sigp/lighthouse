# Validator Manager Import

```
Uploads validators to a validator client using the HTTP API. The validators are
defined in a JSON file which can be generated using the "create-validators"
command.

Usage: lighthouse validator_manager import [OPTIONS]

Options:
      --builder-boost-factor <UINT64>
          When provided, the imported validator will use this percentage
          multiplier to apply to the builder's payload value when choosing
          between a builder payload header and payload from the local execution
          node.
      --builder-proposals <builder-proposals>
          When provided, the imported validator will attempt to create blocks
          via builder rather than the local EL. [possible values: true, false]
  -d, --datadir <DIR>
          Used to specify a custom root data directory for lighthouse keys and
          databases. Defaults to $HOME/.lighthouse/{network} where network is
          the value of the `network` flag Note: Users should specify separate
          custom datadirs for different networks.
      --debug-level <LEVEL>
          Specifies the verbosity level used when emitting logs to the terminal.
          [default: info] [possible values: info, debug, trace, warn, error,
          crit]
      --gas-limit <UINT64>
          When provided, the imported validator will use this gas limit. It is
          recommended to leave this as the default value by not specifying this
          flag.
      --genesis-state-url <URL>
          A URL of a beacon-API compatible server from which to download the
          genesis state. Checkpoint sync server URLs can generally be used with
          this flag. If not supplied, a default URL or the --checkpoint-sync-url
          may be used. If the genesis state is already included in this binary
          then this value will be ignored.
      --genesis-state-url-timeout <SECONDS>
          The timeout in seconds for the request to --genesis-state-url.
          [default: 180]
      --keystore-file <PATH_TO_KEYSTORE_FILE>
          The path to a keystore JSON file to be imported to the validator
          client. This file is usually created using staking-deposit-cli or
          ethstaker-deposit-cli
      --log-format <FORMAT>
          Specifies the log format used when emitting logs to the terminal.
          [possible values: JSON]
      --logfile <FILE>
          File path where the log file will be stored. Once it grows to the
          value specified in `--logfile-max-size` a new log file is generated
          where future logs are stored. Once the number of log files exceeds the
          value specified in `--logfile-max-number` the oldest log file will be
          overwritten.
      --logfile-debug-level <LEVEL>
          The verbosity level used when emitting logs to the log file. [default:
          debug] [possible values: info, debug, trace, warn, error, crit]
      --logfile-format <FORMAT>
          Specifies the log format used when emitting logs to the logfile.
          [possible values: DEFAULT, JSON]
      --logfile-max-number <COUNT>
          The maximum number of log files that will be stored. If set to 0,
          background file logging is disabled. [default: 10]
      --logfile-max-size <SIZE>
          The maximum size (in MB) each log file can grow to before rotating. If
          set to 0, background file logging is disabled. [default: 200]
      --network <network>
          Name of the Eth2 chain Lighthouse will sync and follow. [possible
          values: mainnet, gnosis, chiado, sepolia, holesky]
      --password <STRING>
          Password of the keystore file.
      --prefer-builder-proposals <prefer-builder-proposals>
          When provided, the imported validator will always prefer blocks
          constructed by builders, regardless of payload value. [possible
          values: true, false]
      --suggested-fee-recipient <ETH1_ADDRESS>
          When provided, the imported validator will use the suggested fee
          recipient. Omit this flag to use the default value from the VC.
  -t, --testnet-dir <DIR>
          Path to directory containing eth2_testnet specs. Defaults to a
          hard-coded Lighthouse testnet. Only effective if there is no existing
          database.
      --validators-file <PATH_TO_JSON_FILE>
          The path to a JSON file containing a list of validators to be imported
          to the validator client. This file is usually named "validators.json".
      --vc-token <PATH>
          The file containing a token required by the validator client.
      --vc-url <HTTP_ADDRESS>
          A HTTP(S) address of a validator client using the keymanager-API.
          [default: http://localhost:5062]

Flags:
      --disable-log-timestamp
          If present, do not include timestamps in logging output.
      --disable-malloc-tuning
          If present, do not configure the system allocator. Providing this flag
          will generally increase memory usage, it should only be provided when
          debugging specific memory allocation issues.
  -h, --help
          Prints help information
      --ignore-duplicates
          If present, ignore any validators which already exist on the VC.
          Without this flag, the process will terminate without making any
          changes. This flag should be used with caution, whilst it does not
          directly cause slashable conditions, it might be an indicator that
          something is amiss. Users should also be careful to avoid submitting
          duplicate deposits for validators that already exist on the VC.
      --log-color
          Force outputting colors when emitting logs to the terminal.
      --logfile-compress
          If present, compress old log files. This can help reduce the space
          needed to store old logs.
      --logfile-no-restricted-perms
          If present, log files will be generated as world-readable meaning they
          can be read by any user on the machine. Note that logs can often
          contain sensitive information about your validator and so this flag
          should be used with caution. For Windows users, the log file
          permissions will be inherited from the parent folder.
      --stdin-inputs
          If present, read all user inputs from stdin instead of tty.
```

<style> .content main {max-width:88%;} </style>
