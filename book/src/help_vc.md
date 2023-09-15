#Validator Client

```
When connected to a beacon node, performs the duties of a staked validator (e.g., proposing blocks and attestations).

USAGE:
    lighthouse.exe validator_client [FLAGS] [OPTIONS]

FLAGS:
        --allow-unsynced                         DEPRECATED: this flag does nothing
        --builder-proposals
            If this flag is set, Lighthouse will query the Beacon Node for only block headers during proposals and will
            sign over headers. Useful for outsourcing execution payload construction during proposals.
        --delete-lockfiles
            DEPRECATED. This flag does nothing and will be removed in a future release.

        --disable-auto-discover
            If present, do not attempt to discover new validators in the validators-dir. Validators will need to be
            manually added to the validator_definitions.yml file.
        --disable-log-timestamp                  If present, do not include timestamps in logging output.
        --disable-malloc-tuning
            If present, do not configure the system allocator. Providing this flag will generally increase memory usage,
            it should only be provided when debugging specific memory allocation issues.
        --disable-run-on-all
            By default, Lighthouse publishes attestation, sync committee subscriptions and proposer preparation messages
            to all beacon nodes provided in the `--beacon-nodes flag`. This option changes that behaviour such that
            these api calls only go out to the first available and synced beacon node
        --enable-doppelganger-protection
            If this flag is set, Lighthouse will delay startup for three epochs and monitor for messages on the network
            by any of the validators managed by this client. This will result in three (possibly four) epochs worth of
            missed attestations. If an attestation is detected during this period, it means it is very likely that you
            are running a second validator client with the same keys. This validator client will immediately shutdown if
            this is detected in order to avoid potentially committing a slashable offense. Use this flag in order to
            ENABLE this functionality, without this flag Lighthouse will begin attesting immediately.
        --enable-high-validator-count-metrics
            Enable per validator metrics for > 64 validators. Note: This flag is automatically enabled for <= 64
            validators. Enabling this metric for higher validator counts will lead to higher volume of prometheus
            metrics being collected.
    -h, --help                                   Prints help information
        --http                                   Enable the RESTful HTTP API server. Disabled by default.
        --init-slashing-protection
            If present, do not require the slashing protection database to exist before running. You SHOULD NOT use this
            flag unless you're certain that a new slashing protection database is required. Usually, your database will
            have been initialized when you imported your validator keys. If you misplace your database and then run with
            this flag you risk being slashed.
        --log-color                              Force outputting colors when emitting logs to the terminal.
        --logfile-compress
            If present, compress old log files. This can help reduce the space needed to store old logs.

        --logfile-no-restricted-perms
            If present, log files will be generated as world-readable meaning they can be read by any user on the
            machine. Note that logs can often contain sensitive information about your validator and so this flag should
            be used with caution. For Windows users, the log file permissions will be inherited from the parent folder.
        --metrics                                Enable the Prometheus metrics HTTP server. Disabled by default.
        --strict-fee-recipient
            [DEPRECATED] If this flag is set, Lighthouse will refuse to sign any block whose `fee_recipient` does not
            match the `suggested_fee_recipient` sent by this validator. This applies to both the normal block proposal
            flow, as well as block proposals through the builder API. Proposals through the builder API are more likely
            to have a discrepancy in `fee_recipient` so you should be aware of how your connected relay sends proposer
            payments before using this flag. If this flag is used, a fee recipient mismatch in the builder API flow will
            result in a fallback to the local execution engine for payload construction, where a strict fee recipient
            check will still be applied.
        --unencrypted-http-transport
            This is a safety flag to ensure that the user is aware that the http transport is unencrypted and using a
            custom HTTP address is unsafe.
        --use-long-timeouts
            If present, the validator client will use longer timeouts for requests made to the beacon node. This flag is
            generally not recommended, longer timeouts can cause missed duties when fallbacks are used.
    -V, --version                                Prints version information

OPTIONS:
        --beacon-node <NETWORK_ADDRESS>
            Deprecated. Use --beacon-nodes.

        --beacon-nodes <NETWORK_ADDRESSES>
            Comma-separated addresses to one or more beacon node HTTP APIs. Default is http://localhost:5052.

        --beacon-nodes-tls-certs <CERTIFICATE-FILES>
            Comma-separated paths to custom TLS certificates to use when connecting to a beacon node (and/or proposer
            node). These certificates must be in PEM format and are used in addition to the OS trust store. Commas must
            only be used as a delimiter, and must not be part of the certificate path.
        --builder-registration-timestamp-override <builder-registration-timestamp-override>
            This flag takes a unix timestamp value that will be used to override the timestamp used in the builder api
            registration
    -d, --datadir <DIR>
            Used to specify a custom root data directory for lighthouse keys and databases. Defaults to
            $HOME/.lighthouse/{network} where network is the value of the `network` flag Note: Users should specify
            separate custom datadirs for different networks.
        --debug-level <LEVEL>
            Specifies the verbosity level used when emitting logs to the terminal. [default: info]  [possible values:
            info, debug, trace, warn, error, crit]
        --gas-limit <INTEGER>
            The gas limit to be used in all builder proposals for all validators managed by this validator client. Note
            this will not necessarily be used if the gas limit set here moves too far from the previous block's gas
            limit. [default: 30,000,000]
        --graffiti <GRAFFITI>
            Specify your custom graffiti to be included in blocks.

        --graffiti-file <GRAFFITI-FILE>
            Specify a graffiti file to load validator graffitis from.

        --http-address <ADDRESS>
            Set the address for the HTTP address. The HTTP server is not encrypted and therefore it is unsafe to publish
            on a public network. When this flag is used, it additionally requires the explicit use of the
            `--unencrypted-http-transport` flag to ensure the user is aware of the risks involved. For access via the
            Internet, users should apply transport-layer security like a HTTPS reverse-proxy or SSH tunnelling.
        --http-allow-origin <ORIGIN>
            Set the value of the Access-Control-Allow-Origin response HTTP header. Use * to allow any origin (not
            recommended in production). If no value is supplied, the CORS allowed origin is set to the listen address of
            this server (e.g., http://localhost:5062).
        --http-port <PORT>
            Set the listen TCP port for the RESTful HTTP API server. [default: 5062]

        --latency-measurement-service <BOOLEAN>
            Set to 'true' to enable a service that periodically attempts to measure latency to BNs. Set to 'false' to
            disable. [default: true]
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
        --metrics-address <ADDRESS>
            Set the listen address for the Prometheus metrics HTTP server. [default: 127.0.0.1]

        --metrics-allow-origin <ORIGIN>
            Set the value of the Access-Control-Allow-Origin response HTTP header. Use * to allow any origin (not
            recommended in production). If no value is supplied, the CORS allowed origin is set to the listen address of
            this server (e.g., http://localhost:5064).
        --metrics-port <PORT>
            Set the listen TCP port for the Prometheus metrics HTTP server. [default: 5064]

        --monitoring-endpoint <ADDRESS>
            Enables the monitoring service for sending system metrics to a remote endpoint. This can be used to monitor
            your setup on certain services (e.g. beaconcha.in). This flag sets the endpoint where the beacon node
            metrics will be sent. Note: This will send information to a remote sever which may identify and associate
            your validators, IP address and other personal information. Always use a HTTPS connection and never provide
            an untrusted URL.
        --monitoring-endpoint-period <SECONDS>
            Defines how many seconds to wait between each message sent to the monitoring-endpoint. Default: 60s

        --network <network>
            Name of the Eth2 chain Lighthouse will sync and follow. [possible values: mainnet, prater, goerli, gnosis,
            sepolia]
        --proposer-nodes <NETWORK_ADDRESSES>
            Comma-separated addresses to one or more beacon node HTTP APIs. These specify nodes that are used to send
            beacon block proposals. A failure will revert back to the standard beacon nodes specified in --beacon-nodes.
        --safe-slots-to-import-optimistically <INTEGER>
            Used to coordinate manual overrides of the SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY parameter. This flag should
            only be used if the user has a clear understanding that the broad Ethereum community has elected to override
            this parameter in the event of an attack at the PoS transition block. Incorrect use of this flag can cause
            your node to possibly accept an invalid chain or sync more slowly. Be extremely careful with this flag.
        --secrets-dir <SECRETS_DIRECTORY>
            The directory which contains the password to unlock the validator voting keypairs. Each password should be
            contained in a file where the name is the 0x-prefixed hex representation of the validators voting public
            key. Defaults to ~/.lighthouse/{network}/secrets.
        --server <NETWORK_ADDRESS>
            Deprecated. Use --beacon-nodes.

    -s, --spec <DEPRECATED>
            This flag is deprecated, it will be disallowed in a future release. This value is now derived from the
            --network or --testnet-dir flags.
        --suggested-fee-recipient <FEE-RECIPIENT>
            Once the merge has happened, this address will receive transaction fees from blocks proposed by this
            validator client. If a fee recipient is configured in the validator definitions it takes priority over this
            value.
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
        --validator-registration-batch-size <INTEGER>
            Defines the number of validators per validator/register_validator request sent to the BN. This value can be
            reduced to avoid timeouts from builders. [default: 500]
        --validators-dir <VALIDATORS_DIR>
            The directory which contains the validator keystores, deposit data for each validator along with the common
            slashing protection database and the validator_definitions.yml
```