# Lighthouse CLI Reference

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
          Manage a beacon node database. [aliases: db]
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
          [default: info] [possible values: info, debug, trace, warn, error]
      --genesis-state-url <URL>
          A URL of a beacon-API compatible server from which to download the
          genesis state. Checkpoint sync server URLs can generally be used with
          this flag. If not supplied, a default URL or the --checkpoint-sync-url
          may be used. If the genesis state is already included in this binary
          then this value will be ignored.
      --genesis-state-url-timeout <SECONDS>
          The timeout in seconds for the request to --genesis-state-url.
          [default: 300]
      --log-format <FORMAT>
          Specifies the log format used when emitting logs to the terminal.
          [possible values: JSON]
      --logfile-debug-level <LEVEL>
          The verbosity level used when emitting logs to the log file. [default:
          debug] [possible values: info, debug, trace, warn, error]
      --logfile-dir <DIR>
          Directory path where the log file will be stored
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
          values: mainnet, gnosis, chiado, sepolia, holesky, hoodi]
  -t, --testnet-dir <DIR>
          Path to directory containing eth2_testnet specs. Defaults to a
          hard-coded Lighthouse testnet. Only effective if there is no existing
          database.
      --telemetry-collector-url <URL>
          URL of the OpenTelemetry collector to export tracing spans (e.g.,
          http://localhost:4317). If not set, tracing export is disabled.
      --telemetry-service-name <NAME>
          Override the OpenTelemetry service name. Defaults to 'lighthouse-bn'
          for beacon node, 'lighthouse-vc' for validator client, or 'lighthouse'
          for other subcommands.
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
      --log-color [<log-color>]
          Enables/Disables colors for logs in terminal. Set it to false to
          disable colors. [default: true] [possible values: true, false]
      --log-extra-info
          If present, show module,file,line in logs
      --logfile-color
          Enables colors in logfile.
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
