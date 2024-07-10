# Beacon Node

```
The primary component which connects to the Ethereum 2.0 P2P network and
downloads, verifies and stores blocks. Provides a HTTP API for querying the
beacon chain and publishing messages to the network.

Usage: lighthouse beacon_node [OPTIONS]

Options:
      --auto-compact-db <auto-compact-db>
          Enable or disable automatic compaction of the database on
          finalization. [default: true]
      --blob-prune-margin-epochs <EPOCHS>
          The margin for blob pruning in epochs. The oldest blobs are pruned up
          until data_availability_boundary - blob_prune_margin_epochs. [default:
          0]
      --blobs-dir <DIR>
          Data directory for the blobs database.
      --block-cache-size <SIZE>
          Specifies how many blocks the database should cache in memory
          [default: 5]
      --boot-nodes <ENR/MULTIADDR LIST>
          One or more comma-delimited base64-encoded ENR's to bootstrap the p2p
          network. Multiaddr is also supported.
      --builder <builder>
          The URL of a service compatible with the MEV-boost API.
      --builder-fallback-epochs-since-finalization <builder-fallback-epochs-since-finalization>
          If this node is proposing a block and the chain has not finalized
          within this number of epochs, it will NOT query any connected
          builders, and will use the local execution engine for payload
          construction. Setting this value to anything less than 2 will cause
          the node to NEVER query connected builders. Setting it to 2 will cause
          this condition to be hit if there are skips slots at the start of an
          epoch, right before this node is set to propose. [default: 3]
      --builder-fallback-skips <builder-fallback-skips>
          If this node is proposing a block and has seen this number of skip
          slots on the canonical chain in a row, it will NOT query any connected
          builders, and will use the local execution engine for payload
          construction. [default: 3]
      --builder-fallback-skips-per-epoch <builder-fallback-skips-per-epoch>
          If this node is proposing a block and has seen this number of skip
          slots on the canonical chain in the past `SLOTS_PER_EPOCH`, it will
          NOT query any connected builders, and will use the local execution
          engine for payload construction. [default: 8]
      --builder-header-timeout <MILLISECONDS>
          Defines a timeout value (in milliseconds) to use when fetching a block
          header from the builder API. [default: 1000]
      --builder-profit-threshold <WEI_VALUE>
          This flag is deprecated and has no effect.
      --builder-user-agent <STRING>
          The HTTP user agent to send alongside requests to the builder URL. The
          default is Lighthouse's version string.
      --checkpoint-blobs <BLOBS_SSZ>
          Set the checkpoint blobs to start syncing from. Must be aligned and
          match --checkpoint-block. Using --checkpoint-sync-url instead is
          recommended.
      --checkpoint-block <BLOCK_SSZ>
          Set a checkpoint block to start syncing from. Must be aligned and
          match --checkpoint-state. Using --checkpoint-sync-url instead is
          recommended.
      --checkpoint-state <STATE_SSZ>
          Set a checkpoint state to start syncing from. Must be aligned and
          match --checkpoint-block. Using --checkpoint-sync-url instead is
          recommended.
      --checkpoint-sync-url <BEACON_NODE>
          Set the remote beacon node HTTP endpoint to use for checkpoint sync.
      --checkpoint-sync-url-timeout <SECONDS>
          Set the timeout for checkpoint sync calls to remote beacon node HTTP
          endpoint. [default: 180]
  -d, --datadir <DIR>
          Used to specify a custom root data directory for lighthouse keys and
          databases. Defaults to $HOME/.lighthouse/{network} where network is
          the value of the `network` flag Note: Users should specify separate
          custom datadirs for different networks.
      --debug-level <LEVEL>
          Specifies the verbosity level used when emitting logs to the terminal.
          [default: info] [possible values: info, debug, trace, warn, error,
          crit]
      --discovery-port <PORT>
          The UDP port that discovery will listen on. Defaults to `port`
      --discovery-port6 <PORT>
          The UDP port that discovery will listen on over IPv6 if listening over
          both IPv4 and IPv6. Defaults to `port6`
      --enr-address <ADDRESS>...
          The IP address/ DNS address to broadcast to other peers on how to
          reach this node. If a DNS address is provided, the enr-address is set
          to the IP address it resolves to and does not auto-update based on
          PONG responses in discovery. Set this only if you are sure other nodes
          can connect to your local node on this address. This will update the
          `ip4` or `ip6` ENR fields accordingly. To update both, set this flag
          twice with the different values.
      --enr-quic-port <PORT>
          The quic UDP4 port that will be set on the local ENR. Set this only if
          you are sure other nodes can connect to your local node on this port
          over IPv4.
      --enr-quic6-port <PORT>
          The quic UDP6 port that will be set on the local ENR. Set this only if
          you are sure other nodes can connect to your local node on this port
          over IPv6.
      --enr-tcp-port <PORT>
          The TCP4 port of the local ENR. Set this only if you are sure other
          nodes can connect to your local node on this port over IPv4. The
          --port flag is used if this is not set.
      --enr-tcp6-port <PORT>
          The TCP6 port of the local ENR. Set this only if you are sure other
          nodes can connect to your local node on this port over IPv6. The
          --port6 flag is used if this is not set.
      --enr-udp-port <PORT>
          The UDP4 port of the local ENR. Set this only if you are sure other
          nodes can connect to your local node on this port over IPv4.
      --enr-udp6-port <PORT>
          The UDP6 port of the local ENR. Set this only if you are sure other
          nodes can connect to your local node on this port over IPv6.
      --epochs-per-blob-prune <EPOCHS>
          The epoch interval with which to prune blobs from Lighthouse's
          database when they are older than the data availability boundary
          relative to the current epoch. [default: 1]
      --epochs-per-migration <N>
          The number of epochs to wait between running the migration of data
          from the hot DB to the cold DB. Less frequent runs can be useful for
          minimizing disk writes [default: 1]
      --eth1-blocks-per-log-query <BLOCKS>
          Specifies the number of blocks that a deposit log query should span.
          This will reduce the size of responses from the Eth1 endpoint.
          [default: 1000]
      --eth1-cache-follow-distance <BLOCKS>
          Specifies the distance between the Eth1 chain head and the last block
          which should be imported into the cache. Setting this value lower can
          help compensate for irregular Proof-of-Work block times, but setting
          it too low can make the node vulnerable to re-orgs.
      --execution-endpoint <EXECUTION-ENDPOINT>
          Server endpoint for an execution layer JWT-authenticated HTTP JSON-RPC
          connection. Uses the same endpoint to populate the deposit cache.
      --execution-jwt <EXECUTION-JWT>
          File path which contains the hex-encoded JWT secret for the execution
          endpoint provided in the --execution-endpoint flag.
      --execution-jwt-id <EXECUTION-JWT-ID>
          Used by the beacon node to communicate a unique identifier to
          execution nodes during JWT authentication. It corresponds to the 'id'
          field in the JWT claims object.Set to empty by default
      --execution-jwt-secret-key <EXECUTION-JWT-SECRET-KEY>
          Hex-encoded JWT secret for the execution endpoint provided in the
          --execution-endpoint flag.
      --execution-jwt-version <EXECUTION-JWT-VERSION>
          Used by the beacon node to communicate a client version to execution
          nodes during JWT authentication. It corresponds to the 'clv' field in
          the JWT claims object.Set to empty by default
      --execution-timeout-multiplier <NUM>
          Unsigned integer to multiply the default execution timeouts by.
          [default: 1]
      --fork-choice-before-proposal-timeout <fork-choice-before-proposal-timeout>
          Set the maximum number of milliseconds to wait for fork choice before
          proposing a block. You can prevent waiting at all by setting the
          timeout to 0, however you risk proposing atop the wrong parent block.
          [default: 250]
      --freezer-dir <DIR>
          Data directory for the freezer database.
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
          Specify your custom graffiti to be included in blocks. Defaults to the
          current version and commit, truncated to fit in 32 bytes.
      --historic-state-cache-size <SIZE>
          Specifies how many states from the freezer database should cache in
          memory [default: 1]
      --http-address <ADDRESS>
          Set the listen address for the RESTful HTTP API server.
      --http-allow-origin <ORIGIN>
          Set the value of the Access-Control-Allow-Origin response HTTP header.
          Use * to allow any origin (not recommended in production). If no value
          is supplied, the CORS allowed origin is set to the listen address of
          this server (e.g., http://localhost:5052).
      --http-duplicate-block-status <STATUS_CODE>
          Status code to send when a block that is already known is POSTed to
          the HTTP API.
      --http-enable-beacon-processor <BOOLEAN>
          The beacon processor is a scheduler which provides quality-of-service
          and DoS protection. When set to "true", HTTP API requests will be
          queued and scheduled alongside other tasks. When set to "false", HTTP
          API responses will be executed immediately.
      --http-port <PORT>
          Set the listen TCP port for the RESTful HTTP API server.
      --http-sse-capacity-multiplier <N>
          Multiplier to apply to the length of HTTP server-sent-event (SSE)
          channels. Increasing this value can prevent messages from being
          dropped.
      --http-tls-cert <http-tls-cert>
          The path of the certificate to be used when serving the HTTP API
          server over TLS.
      --http-tls-key <http-tls-key>
          The path of the private key to be used when serving the HTTP API
          server over TLS. Must not be password-protected.
      --inbound-rate-limiter-protocols <inbound-rate-limiter-protocols>
          Configures the inbound rate limiter (requests received by this
          node).Rate limit quotas per protocol can be set in the form of
          <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple
          protocols, separate them by ';'. This is enabled by default, using
          default quotas. To disable rate limiting use the
          disable-inbound-rate-limiter flag instead.
      --invalid-gossip-verified-blocks-path <PATH>
          If a block succeeds gossip validation whilst failing full validation,
          store the block SSZ as a file at this path. This feature is only
          recommended for developers. This directory is not pruned, users should
          be careful to avoid filling up their disks.
      --libp2p-addresses <MULTIADDR>
          One or more comma-delimited multiaddrs to manually connect to a libp2p
          peer without an ENR.
      --listen-address [<ADDRESS>...]
          The address lighthouse will listen for UDP and TCP connections. To
          listen over IpV4 and IpV6 set this flag twice with the different
          values.
          Examples:
          - --listen-address '0.0.0.0' will listen over IPv4.
          - --listen-address '::' will listen over IPv6.
          - --listen-address '0.0.0.0' --listen-address '::' will listen over
          both IPv4 and IPv6. The order of the given addresses is not relevant.
          However, multiple IPv4, or multiple IPv6 addresses will not be
          accepted. [default: 0.0.0.0]
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
      --max-skip-slots <NUM_SLOTS>
          Refuse to skip more than this many slots when processing an
          attestation. This prevents nodes on minority forks from wasting our
          time and disk space, but could also cause unnecessary consensus
          failures, so is disabled by default.
      --metrics-address <ADDRESS>
          Set the listen address for the Prometheus metrics HTTP server.
      --metrics-allow-origin <ORIGIN>
          Set the value of the Access-Control-Allow-Origin response HTTP header.
          Use * to allow any origin (not recommended in production). If no value
          is supplied, the CORS allowed origin is set to the listen address of
          this server (e.g., http://localhost:5054).
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
      --network-dir <DIR>
          Data directory for network keys. Defaults to network/ inside the
          beacon node dir.
      --port <PORT>
          The TCP/UDP ports to listen on. There are two UDP ports. The discovery
          UDP port will be set to this value and the Quic UDP port will be set
          to this value + 1. The discovery port can be modified by the
          --discovery-port flag and the quic port can be modified by the
          --quic-port flag. If listening over both IPv4 and IPv6 the --port flag
          will apply to the IPv4 address and --port6 to the IPv6 address.
          [default: 9000]
      --port6 <PORT>
          The TCP/UDP ports to listen on over IPv6 when listening over both IPv4
          and IPv6. Defaults to 9090 when required. The Quic UDP port will be
          set to this value + 1. [default: 9090]
      --prepare-payload-lookahead <MILLISECONDS>
          The time before the start of a proposal slot at which payload
          attributes should be sent. Low values are useful for execution nodes
          which don't improve their payload after the first call, and high
          values are useful for ensuring the EL is given ample notice. Default:
          1/3 of a slot.
      --progressive-balances <MODE>
          Deprecated. This optimisation is now the default and cannot be
          disabled.
      --proposer-reorg-cutoff <MILLISECONDS>
          Maximum delay after the start of the slot at which to propose a
          reorging block. Lower values can prevent failed reorgs by ensuring the
          block has ample time to propagate and be processed by the network. The
          default is 1/12th of a slot (1 second on mainnet)
      --proposer-reorg-disallowed-offsets <N1,N2,...>
          Comma-separated list of integer offsets which can be used to avoid
          proposing reorging blocks at certain slots. An offset of N means that
          reorging proposals will not be attempted at any slot such that `slot %
          SLOTS_PER_EPOCH == N`. By default only re-orgs at offset 0 will be
          avoided. Any offsets supplied with this flag will impose additional
          restrictions.
      --proposer-reorg-epochs-since-finalization <EPOCHS>
          Maximum number of epochs since finalization at which proposer reorgs
          are allowed. Default: 2
      --proposer-reorg-parent-threshold <PERCENT>
          Percentage of parent vote weight above which to attempt a proposer
          reorg. Default: 160%
      --proposer-reorg-threshold <PERCENT>
          Percentage of head vote weight below which to attempt a proposer
          reorg. Default: 20%
      --prune-blobs <BOOLEAN>
          Prune blobs from Lighthouse's database when they are older than the
          data data availability boundary relative to the current epoch.
          [default: true]
      --prune-payloads <prune-payloads>
          Prune execution payloads from Lighthouse's database. This saves space
          but imposes load on the execution client, as payloads need to be
          reconstructed and sent to syncing peers. [default: true]
      --quic-port <PORT>
          The UDP port that quic will listen on. Defaults to `port` + 1
      --quic-port6 <PORT>
          The UDP port that quic will listen on over IPv6 if listening over both
          IPv4 and IPv6. Defaults to `port6` + 1
      --safe-slots-to-import-optimistically <INTEGER>
          Used to coordinate manual overrides of the
          SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY parameter. This flag should only
          be used if the user has a clear understanding that the broad Ethereum
          community has elected to override this parameter in the event of an
          attack at the PoS transition block. Incorrect use of this flag can
          cause your node to possibly accept an invalid chain or sync more
          slowly. Be extremely careful with this flag.
      --self-limiter-protocols <self-limiter-protocols>
          Enables the outbound rate limiter (requests made by this node).Rate
          limit quotas per protocol can be set in the form of
          <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple
          protocols, separate them by ';'. If the self rate limiter is enabled
          and a protocol is not present in the configuration, the quotas used
          for the inbound rate limiter will be used.
      --shuffling-cache-size <shuffling-cache-size>
          Some HTTP API requests can be optimised by caching the shufflings at
          each epoch. This flag allows the user to set the shuffling cache size
          in epochs. Shufflings are dependent on validator count and setting
          this value to a large number can consume a large amount of memory.
      --slasher-att-cache-size <COUNT>
          Set the maximum number of attestation roots for the slasher to cache
      --slasher-backend <DATABASE>
          Set the database backend to be used by the slasher. [possible values:
          lmdb, disabled]
      --slasher-broadcast [<slasher-broadcast>]
          Broadcast slashings found by the slasher to the rest of the network
          [Enabled by default]. [default: true]
      --slasher-chunk-size <EPOCHS>
          Number of epochs per validator per chunk stored on disk.
      --slasher-dir <PATH>
          Set the slasher's database directory.
      --slasher-history-length <EPOCHS>
          Configure how many epochs of history the slasher keeps. Immutable
          after initialization.
      --slasher-max-db-size <GIGABYTES>
          Maximum size of the MDBX database used by the slasher.
      --slasher-slot-offset <SECONDS>
          Set the delay from the start of the slot at which the slasher should
          ingest attestations. Only effective if the slasher-update-period is a
          multiple of the slot duration.
      --slasher-update-period <SECONDS>
          Configure how often the slasher runs batch processing.
      --slasher-validator-chunk-size <NUM_VALIDATORS>
          Number of validators per chunk stored on disk.
      --slots-per-restore-point <SLOT_COUNT>
          Specifies how often a freezer DB restore point should be stored.
          Cannot be changed after initialization. [default: 8192 (mainnet) or 64
          (minimal)]
      --state-cache-size <STATE_CACHE_SIZE>
          Specifies the size of the state cache [default: 128]
      --suggested-fee-recipient <SUGGESTED-FEE-RECIPIENT>
          Emergency fallback fee recipient for use in case the validator client
          does not have one configured. You should set this flag on the
          validator client instead of (or in addition to) setting it here.
  -t, --testnet-dir <DIR>
          Path to directory containing eth2_testnet specs. Defaults to a
          hard-coded Lighthouse testnet. Only effective if there is no existing
          database.
      --target-peers <target-peers>
          The target number of peers.
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
      --trusted-peers <TRUSTED_PEERS>
          One or more comma-delimited trusted peer ids which always have the
          highest score according to the peer scoring system.
      --trusted-setup-file-override <FILE>
          Path to a json file containing the trusted setup params. NOTE: This
          will override the trusted setup that is generated from the mainnet kzg
          ceremony. Use with caution
      --validator-monitor-file <PATH>
          As per --validator-monitor-pubkeys, but the comma-separated list is
          contained within a file at the given path.
      --validator-monitor-individual-tracking-threshold <INTEGER>
          Once the validator monitor reaches this number of local validators it
          will stop collecting per-validator Prometheus metrics and issuing
          per-validator logs. Instead, it will provide aggregate metrics and
          logs. This avoids infeasibly high cardinality in the Prometheus
          database and high log volume when using many validators. Defaults to
          64.
      --validator-monitor-pubkeys <PUBKEYS>
          A comma-separated list of 0x-prefixed validator public keys. These
          validators will receive special monitoring and additional logging.
      --wss-checkpoint <WSS_CHECKPOINT>
          Specify a weak subjectivity checkpoint in `block_root:epoch` format to
          verify the node's sync against. The block root should be 0x-prefixed.
          Note that this flag is for verification only, to perform a checkpoint
          sync from a recent state use --checkpoint-sync-url.
  -V, --version
          Print version

Flags:
      --allow-insecure-genesis-sync
          Enable syncing from genesis, which is generally insecure and
          incompatible with data availability checks. Checkpoint syncing is the
          preferred method for syncing a node. Only use this flag when testing.
          DO NOT use on mainnet!
      --always-prefer-builder-payload
          This flag is deprecated and has no effect.
      --always-prepare-payload
          Send payload attributes with every fork choice update. This is
          intended for use by block builders, relays and developers. You should
          set a fee recipient on this BN and also consider adjusting the
          --prepare-payload-lookahead flag.
      --builder-fallback-disable-checks
          This flag disables all checks related to chain health. This means the
          builder API will always be used for payload construction, regardless
          of recent chain conditions.
      --compact-db
          If present, apply compaction to the database on start-up. Use with
          caution. It is generally not recommended unless auto-compaction is
          disabled.
      --disable-backfill-rate-limiting
          Disable the backfill sync rate-limiting. This allow users to just sync
          the entire chain as fast as possible, however it can result in
          resource contention which degrades staking performance. Stakers should
          generally choose to avoid this flag since backfill sync is not
          required for staking.
      --disable-deposit-contract-sync
          Explicitly disables syncing of deposit logs from the execution node.
          This overrides any previous option that depends on it. Useful if you
          intend to run a non-validating beacon node.
      --disable-duplicate-warn-logs
          This flag is deprecated and has no effect.
      --disable-enr-auto-update
          Discovery automatically updates the nodes local ENR with an external
          IP address and port as seen by other peers on the network. This
          disables this feature, fixing the ENR's IP/PORT to those specified on
          boot.
      --disable-inbound-rate-limiter
          Disables the inbound rate limiter (requests received by this node).
      --disable-lock-timeouts
          Disable the timeouts applied to some internal locks by default. This
          can lead to less spurious failures on slow hardware but is considered
          experimental as it may obscure performance issues.
      --disable-log-timestamp
          If present, do not include timestamps in logging output.
      --disable-malloc-tuning
          If present, do not configure the system allocator. Providing this flag
          will generally increase memory usage, it should only be provided when
          debugging specific memory allocation issues.
      --disable-optimistic-finalized-sync
          Force Lighthouse to verify every execution block hash with the
          execution client during finalized sync. By default block hashes will
          be checked in Lighthouse and only passed to the EL if initial
          verification fails.
      --disable-packet-filter
          Disables the discovery packet filter. Useful for testing in smaller
          networks
      --disable-proposer-reorgs
          Do not attempt to reorg late blocks from other validators when
          proposing.
      --disable-quic
          Disables the quic transport. The node will rely solely on the TCP
          transport for libp2p connections.
      --disable-upnp
          Disables UPnP support. Setting this will prevent Lighthouse from
          attempting to automatically establish external port mappings.
      --dummy-eth1
          If present, uses an eth1 backend that generates static dummy
          data.Identical to the method used at the 2019 Canada interop.
  -e, --enr-match
          Sets the local ENR IP address and port to match those set for
          lighthouse. Specifically, the IP address will be the value of
          --listen-address and the UDP port will be --discovery-port.
      --enable-private-discovery
          Lighthouse by default does not discover private IP addresses. Set this
          flag to enable connection attempts to local addresses.
      --eth1
          If present the node will connect to an eth1 node. This is required for
          block production, you must use this flag if you wish to serve a
          validator.
      --eth1-purge-cache
          Purges the eth1 block and deposit caches
      --genesis-backfill
          Attempts to download blocks all the way back to genesis when
          checkpoint syncing.
      --gui
          Enable the graphical user interface and all its requirements. This
          enables --http and --validator-monitor-auto and enables SSE logging.
  -h, --help
          Prints help information
      --http
          Enable the RESTful HTTP API server. Disabled by default.
      --http-enable-tls
          Serves the RESTful HTTP API server over TLS. This feature is currently
          experimental.
      --import-all-attestations
          Import and aggregate all attestations, regardless of validator
          subscriptions. This will only import attestations from
          already-subscribed subnets, use with --subscribe-all-subnets to ensure
          all attestations are received for import.
      --light-client-server
          Act as a full node supporting light clients on the p2p network
          [experimental]
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
      --private
          Prevents sending various client identification information.
      --proposer-only
          Sets this beacon node at be a block proposer only node. This will run
          the beacon node in a minimal configuration that is sufficient for
          block publishing only. This flag should be used for a beacon node
          being referenced by validator client using the --proposer-node flag.
          This configuration is for enabling more secure setups.
      --purge-db
          If present, the chain database will be deleted. Use with caution.
      --reconstruct-historic-states
          After a checkpoint sync, reconstruct historic states in the database.
          This requires syncing all the way back to genesis.
      --reset-payload-statuses
          When present, Lighthouse will forget the payload statuses of any
          already-imported blocks. This can assist in the recovery from a
          consensus failure caused by the execution layer.
      --self-limiter
          Enables the outbound rate limiter (requests made by this node). Use
          the self-limiter-protocol flag to set per protocol configurations. If
          the self rate limiter is enabled and a protocol is not present in the
          configuration, the quotas used for the inbound rate limiter will be
          used.
      --shutdown-after-sync
          Shutdown beacon node as soon as sync is completed. Backfill sync will
          not be performed before shutdown.
      --slasher
          Run a slasher alongside the beacon node. It is currently only
          recommended for expert users because of the immaturity of the slasher
          UX and the extra resources required.
      --staking
          Standard option for a staking beacon node. This will enable the HTTP
          server on localhost:5052 and import deposit logs from the execution
          node. This is equivalent to `--http` on merge-ready networks, or
          `--http --eth1` pre-merge
      --subscribe-all-subnets
          Subscribe to all subnets regardless of validator count. This will also
          advertise the beacon node as being long-lived subscribed to all
          subnets.
      --validator-monitor-auto
          Enables the automatic detection and monitoring of validators connected
          to the HTTP API and using the subnet subscription endpoint. This
          generally has the effect of providing additional logging and metrics
          for locally controlled validators.
  -z, --zero-ports
          Sets all listening TCP/UDP ports to 0, allowing the OS to choose some
          arbitrary free ports.
```

<style> .content main {max-width:88%;} </style>
