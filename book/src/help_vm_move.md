# Validator Manager Move

```
Uploads validators to a validator client using the HTTP API. The validators are
defined in a JSON file which can be generated using the "create-validators"
command. This command only supports validators signing via a keystore on the
local file system (i.e., not Web3Signer validators).

Usage: lighthouse validator_manager move [OPTIONS] --src-vc-token <PATH> --src-vc-url <HTTP_ADDRESS> --dest-vc-token <PATH> --dest-vc-url <HTTP_ADDRESS>

Options:
      --builder-boost-factor <UINT64>
          Defines the boost factor, a percentage multiplier to apply to the
          builder's payload value when choosing between a builder payload header
          and payload from the local execution node.
      --builder-proposals <builder-proposals>
          When provided, all created validators will attempt to create blocks
          via builder rather than the local EL. [possible values: true, false]
      --count <VALIDATOR_COUNT>
          The number of validators to move.
  -d, --datadir <DIR>
          Used to specify a custom root data directory for lighthouse keys and
          databases. Defaults to $HOME/.lighthouse/{network} where network is
          the value of the `network` flag Note: Users should specify separate
          custom datadirs for different networks.
      --debug-level <LEVEL>
          Specifies the verbosity level used when emitting logs to the terminal.
          [default: info] [possible values: info, debug, trace, warn, error,
          crit]
      --dest-vc-token <PATH>
          The file containing a token required by the destination validator
          client.
      --dest-vc-url <HTTP_ADDRESS>
          A HTTP(S) address of a validator client using the keymanager-API. This
          validator client is the "destination" and will have new validators
          added as they are removed from the "source" validator client.
      --gas-limit <UINT64>
          All created validators will use this gas limit. It is recommended to
          leave this as the default value by not specifying this flag.
      --genesis-state-url <URL>
          A URL of a beacon-API compatible server from which to download the
          genesis state. Checkpoint sync server URLs can generally be used with
          this flag. If not supplied, a default URL or the --checkpoint-sync-url
          may be used. If the genesis state is already included in this binary
          then this value will be ignored.
      --genesis-state-url-timeout <SECONDS>
          The timeout in seconds for the request to --genesis-state-url.
          [default: 180]
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
      --prefer-builder-proposals <prefer-builder-proposals>
          If this flag is set, Lighthouse will always prefer blocks constructed
          by builders, regardless of payload value. [possible values: true,
          false]
      --safe-slots-to-import-optimistically <INTEGER>
          Used to coordinate manual overrides of the
          SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY parameter. This flag should only
          be used if the user has a clear understanding that the broad Ethereum
          community has elected to override this parameter in the event of an
          attack at the PoS transition block. Incorrect use of this flag can
          cause your node to possibly accept an invalid chain or sync more
          slowly. Be extremely careful with this flag.
      --src-vc-token <PATH>
          The file containing a token required by the source validator client.
      --src-vc-url <HTTP_ADDRESS>
          A HTTP(S) address of a validator client using the keymanager-API. This
          validator client is the "source" and contains the validators that are
          to be moved.
      --stdin-inputs
          If present, read all user inputs from stdin instead of tty.
      --suggested-fee-recipient <ETH1_ADDRESS>
          All created validators will use this value for the suggested fee
          recipient. Omit this flag to use the default value from the VC.
  -t, --testnet-dir <DIR>
          Path to directory containing eth2_testnet specs. Defaults to a
          hard-coded Lighthouse testnet. Only effective if there is no existing
          database.
      --terminal-block-hash-epoch-override <EPOCH>
          Used to coordinate manual overrides to the
          TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH parameter. This flag should only
          be used if the user has a clear understanding that the broad Ethereum
          community has elected to override the terminal PoW block. Incorrect
          use of this flag will cause your node to experience a consensus
          failure. Be extremely careful with this flag.
      --terminal-block-hash-override <TERMINAL_BLOCK_HASH>
          Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH
          parameter. This flag should only be used if the user has a clear
          understanding that the broad Ethereum community has elected to
          override the terminal PoW block. Incorrect use of this flag will cause
          your node to experience a consensus failure. Be extremely careful with
          this flag.
      --terminal-total-difficulty-override <INTEGER>
          Used to coordinate manual overrides to the TERMINAL_TOTAL_DIFFICULTY
          parameter. Accepts a 256-bit decimal integer (not a hex value). This
          flag should only be used if the user has a clear understanding that
          the broad Ethereum community has elected to override the terminal
          difficulty. Incorrect use of this flag will cause your node to
          experience a consensus failure. Be extremely careful with this flag.
      --validators <STRING>
          The validators to be moved. Either a list of 0x-prefixed validator
          pubkeys or the keyword "all".

Flags:
      --disable-log-timestamp
          If present, do not include timestamps in logging output.
      --disable-malloc-tuning
          If present, do not configure the system allocator. Providing this flag
          will generally increase memory usage, it should only be provided when
          debugging specific memory allocation issues.
  -h, --help
          Prints help information
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
```

<style> .content main {max-width:88%;} </style>
