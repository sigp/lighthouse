# Validator Client

```
When connected to a beacon node, performs the duties of a staked validator
(e.g., proposing blocks and attestations).

Usage: lighthouse validator_client [OPTIONS]

Options:
      --beacon-nodes <NETWORK_ADDRESSES>
          Comma-separated addresses to one or more beacon node HTTP APIs.
          Default is http://localhost:5052.
      --beacon-nodes-tls-certs <CERTIFICATE-FILES>
          Comma-separated paths to custom TLS certificates to use when
          connecting to a beacon node (and/or proposer node). These certificates
          must be in PEM format and are used in addition to the OS trust store.
          Commas must only be used as a delimiter, and must not be part of the
          certificate path.
      --broadcast <API_TOPICS>
          Comma-separated list of beacon API topics to broadcast to all beacon
          nodes. Possible values are: none, attestations, blocks, subscriptions,
          sync-committee. Default (when flag is omitted) is to broadcast
          subscriptions only.
      --builder-boost-factor <UINT64>
          Defines the boost factor, a percentage multiplier to apply to the
          builder's payload value when choosing between a builder payload header
          and payload from the local execution node.
      --builder-registration-timestamp-override <builder-registration-timestamp-override>
          This flag takes a unix timestamp value that will be used to override
          the timestamp used in the builder api registration
  -d, --datadir <DIR>
          Used to specify a custom root data directory for lighthouse keys and
          databases. Defaults to $HOME/.lighthouse/{network} where network is
          the value of the `network` flag Note: Users should specify separate
          custom datadirs for different networks.
      --debug-level <LEVEL>
          Specifies the verbosity level used when emitting logs to the terminal.
          [default: info] [possible values: info, debug, trace, warn, error,
          crit]
      --gas-limit <INTEGER>
          The gas limit to be used in all builder proposals for all validators
          managed by this validator client. Note this will not necessarily be
          used if the gas limit set here moves too far from the previous block's
          gas limit. [default: 30,000,000]
      --genesis-state-url <URL>
          A URL of a beacon-API compatible server from which to download the
          genesis state. Checkpoint sync server URLs can generally be used with
          this flag. If not supplied, a default URL or the --checkpoint-sync-url
          may be used. If the genesis state is already included in this binary
          then this value will be ignored.
      --genesis-state-url-timeout <SECONDS>
          The timeout in seconds for the request to --genesis-state-url.
          [default: 180]
      --graffiti <GRAFFITI>
          Specify your custom graffiti to be included in blocks.
      --graffiti-file <GRAFFITI-FILE>
          Specify a graffiti file to load validator graffitis from.
      --http-address <ADDRESS>
          Set the address for the HTTP address. The HTTP server is not encrypted
          and therefore it is unsafe to publish on a public network. When this
          flag is used, it additionally requires the explicit use of the
          `--unencrypted-http-transport` flag to ensure the user is aware of the
          risks involved. For access via the Internet, users should apply
          transport-layer security like a HTTPS reverse-proxy or SSH tunnelling.
      --http-allow-origin <ORIGIN>
          Set the value of the Access-Control-Allow-Origin response HTTP header.
          Use * to allow any origin (not recommended in production). If no value
          is supplied, the CORS allowed origin is set to the listen address of
          this server (e.g., http://localhost:5062).
      --http-port <PORT>
          Set the listen TCP port for the RESTful HTTP API server.
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
      --metrics-address <ADDRESS>
          Set the listen address for the Prometheus metrics HTTP server.
      --metrics-allow-origin <ORIGIN>
          Set the value of the Access-Control-Allow-Origin response HTTP header.
          Use * to allow any origin (not recommended in production). If no value
          is supplied, the CORS allowed origin is set to the listen address of
          this server (e.g., http://localhost:5064).
      --metrics-port <PORT>
          Set the listen TCP port for the Prometheus metrics HTTP server.
      --monitoring-endpoint <ADDRESS>
          Enables the monitoring service for sending system metrics to a remote
          endpoint. This can be used to monitor your setup on certain services
          (e.g. beaconcha.in). This flag sets the endpoint where the beacon node
          metrics will be sent. Note: This will send information to a remote
          sever which may identify and associate your validators, IP address and
          other personal information. Always use a HTTPS connection and never
          provide an untrusted URL.
      --monitoring-endpoint-period <SECONDS>
          Defines how many seconds to wait between each message sent to the
          monitoring-endpoint. Default: 60s
      --network <network>
          Name of the Eth2 chain Lighthouse will sync and follow. [possible
          values: mainnet, gnosis, chiado, sepolia, holesky]
      --proposer-nodes <NETWORK_ADDRESSES>
          Comma-separated addresses to one or more beacon node HTTP APIs. These
          specify nodes that are used to send beacon block proposals. A failure
          will revert back to the standard beacon nodes specified in
          --beacon-nodes.
      --safe-slots-to-import-optimistically <INTEGER>
          Used to coordinate manual overrides of the
          SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY parameter. This flag should only
          be used if the user has a clear understanding that the broad Ethereum
          community has elected to override this parameter in the event of an
          attack at the PoS transition block. Incorrect use of this flag can
          cause your node to possibly accept an invalid chain or sync more
          slowly. Be extremely careful with this flag.
      --secrets-dir <SECRETS_DIRECTORY>
          The directory which contains the password to unlock the validator
          voting keypairs. Each password should be contained in a file where the
          name is the 0x-prefixed hex representation of the validators voting
          public key. Defaults to ~/.lighthouse/{network}/secrets.
      --suggested-fee-recipient <FEE-RECIPIENT>
          Once the merge has happened, this address will receive transaction
          fees from blocks proposed by this validator client. If a fee recipient
          is configured in the validator definitions it takes priority over this
          value.
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
      --validator-registration-batch-size <INTEGER>
          Defines the number of validators per validator/register_validator
          request sent to the BN. This value can be reduced to avoid timeouts
          from builders. [default: 500]
      --validators-dir <VALIDATORS_DIR>
          The directory which contains the validator keystores, deposit data for
          each validator along with the common slashing protection database and
          the validator_definitions.yml
      --web3-signer-keep-alive-timeout <MILLIS>
          Keep-alive timeout for each web3signer connection. Set to 'null' to
          never timeout [default: 20000]
      --web3-signer-max-idle-connections <COUNT>
          Maximum number of idle connections to maintain per web3signer host.
          Default is unlimited.

Flags:
      --builder-proposals
          If this flag is set, Lighthouse will query the Beacon Node for only
          block headers during proposals and will sign over headers. Useful for
          outsourcing execution payload construction during proposals.
      --disable-auto-discover
          If present, do not attempt to discover new validators in the
          validators-dir. Validators will need to be manually added to the
          validator_definitions.yml file.
      --disable-latency-measurement-service
          Disables the service that periodically attempts to measure latency to
          BNs.
      --disable-log-timestamp
          If present, do not include timestamps in logging output.
      --disable-malloc-tuning
          If present, do not configure the system allocator. Providing this flag
          will generally increase memory usage, it should only be provided when
          debugging specific memory allocation issues.
      --disable-run-on-all
          DEPRECATED. Use --broadcast. By default, Lighthouse publishes
          attestation, sync committee subscriptions and proposer preparation
          messages to all beacon nodes provided in the `--beacon-nodes flag`.
          This option changes that behaviour such that these api calls only go
          out to the first available and synced beacon node
      --disable-slashing-protection-web3signer
          Disable Lighthouse's slashing protection for all web3signer keys. This
          can reduce the I/O burden on the VC but is only safe if slashing
          protection is enabled on the remote signer and is implemented
          correctly. DO NOT ENABLE THIS FLAG UNLESS YOU ARE CERTAIN THAT
          SLASHING PROTECTION IS ENABLED ON THE REMOTE SIGNER. YOU WILL GET
          SLASHED IF YOU USE THIS FLAG WITHOUT ENABLING WEB3SIGNER'S SLASHING
          PROTECTION.
      --distributed
          Enables functionality required for running the validator in a
          distributed validator cluster.
      --enable-doppelganger-protection
          If this flag is set, Lighthouse will delay startup for three epochs
          and monitor for messages on the network by any of the validators
          managed by this client. This will result in three (possibly four)
          epochs worth of missed attestations. If an attestation is detected
          during this period, it means it is very likely that you are running a
          second validator client with the same keys. This validator client will
          immediately shutdown if this is detected in order to avoid potentially
          committing a slashable offense. Use this flag in order to ENABLE this
          functionality, without this flag Lighthouse will begin attesting
          immediately.
      --enable-high-validator-count-metrics
          Enable per validator metrics for > 64 validators. Note: This flag is
          automatically enabled for <= 64 validators. Enabling this metric for
          higher validator counts will lead to higher volume of prometheus
          metrics being collected.
  -h, --help
          Prints help information
      --http
          Enable the RESTful HTTP API server. Disabled by default.
      --http-allow-keystore-export
          If present, allow access to the DELETE /lighthouse/keystores HTTP API
          method, which allows exporting keystores and passwords to HTTP API
          consumers who have access to the API token. This method is useful for
          exporting validators, however it should be used with caution since it
          exposes private key data to authorized users.
      --http-store-passwords-in-secrets-dir
          If present, any validators created via the HTTP will have keystore
          passwords stored in the secrets-dir rather than the validator
          definitions file.
      --init-slashing-protection
          If present, do not require the slashing protection database to exist
          before running. You SHOULD NOT use this flag unless you're certain
          that a new slashing protection database is required. Usually, your
          database will have been initialized when you imported your validator
          keys. If you misplace your database and then run with this flag you
          risk being slashed.
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
      --metrics
          Enable the Prometheus metrics HTTP server. Disabled by default.
      --prefer-builder-proposals
          If this flag is set, Lighthouse will always prefer blocks constructed
          by builders, regardless of payload value.
      --produce-block-v3
          Enable block production via the block v3 endpoint for this validator
          client. This should only be enabled when paired with a beacon node
          that has this endpoint implemented. This flag will be enabled by
          default in future.
      --unencrypted-http-transport
          This is a safety flag to ensure that the user is aware that the http
          transport is unencrypted and using a custom HTTP address is unsafe.
      --use-long-timeouts
          If present, the validator client will use longer timeouts for requests
          made to the beacon node. This flag is generally not recommended,
          longer timeouts can cause missed duties when fallbacks are used.
```

<style> .content main {max-width:88%;} </style>
