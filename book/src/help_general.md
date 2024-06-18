# Lighthouse General Commands

```
Ethereum 2.0 client by Sigma Prime. Provides a full-featured beacon node, a
validator client and utilities for managing validator accounts.

Usage: lighthouse [OPTIONS] [COMMAND]

Commands:
  account_manager
          Utilities for generating and managing Ethereum 2.0 accounts. [aliases:
          a, am, account]
  beacon_node
          The primary component which connects to the Ethereum 2.0 P2P network
          and downloads, verifies and stores blocks. Provides a HTTP API for
          querying the beacon chain and publishing messages to the network.
          [aliases: b, bn, beacon]
  boot_node
          Start a special Lighthouse process that only serves as a discv5
          boot-node. This process will *not* import blocks or perform most
          typical beacon node functions. Instead, it will simply run the discv5
          service and assist nodes on the network to discover each other. This
          is the recommended way to provide a network boot-node since it has a
          reduced attack surface compared to a full beacon node.
  database_manager
          Manage a beacon node database [aliases: db]
  validator_client
          When connected to a beacon node, performs the duties of a staked
          validator (e.g., proposing blocks and attestations). [aliases: v, vc,
          validator]
  validator_manager
          Utilities for managing a Lighthouse validator client via the HTTP API.
          [aliases: vm, validator-manager]
  help
          Print this message or the help of the given subcommand(s)

Options:
  -d, --datadir <DIR>
          Used to specify a custom root data directory for lighthouse keys and
          databases. Defaults to $HOME/.lighthouse/{network} where network is
          the value of the `network` flag Note: Users should specify separate
          custom datadirs for different networks.
      --debug-level <LEVEL>
          Specifies the verbosity level used when emitting logs to the terminal.
          [default: info] [possible values: info, debug, trace, warn, error,
          crit]
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
          background file logging is disabled. [default: 5]
      --logfile-max-size <SIZE>
          The maximum size (in MB) each log file can grow to before rotating. If
          set to 0, background file logging is disabled. [default: 200]
      --network <network>
          Name of the Eth2 chain Lighthouse will sync and follow. [possible
          values: mainnet, gnosis, chiado, sepolia, holesky]
      --safe-slots-to-import-optimistically <INTEGER>
          Used to coordinate manual overrides of the
          SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY parameter. This flag should only
          be used if the user has a clear understanding that the broad Ethereum
          community has elected to override this parameter in the event of an
          attack at the PoS transition block. Incorrect use of this flag can
          cause your node to possibly accept an invalid chain or sync more
          slowly. Be extremely careful with this flag.
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
  -V, --version
          Print version

Flags:
      --disable-log-timestamp
          If present, do not include timestamps in logging output.
      --disable-malloc-tuning
          If present, do not configure the system allocator. Providing this flag
          will generally increase memory usage, it should only be provided when
          debugging specific memory allocation issues.
  -h, --help
          Prints help information
  -l
          DEPRECATED Enables environment logging giving access to sub-protocol
          logs such as discv5 and libp2p
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
